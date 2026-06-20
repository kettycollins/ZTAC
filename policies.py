"""
Zero Trust Policy Decision Point (PDP) v9.0 — Risk-Based Access Control.

Архітектура (три послідовні шари):

  ШАР 0 — Жорсткий периметр гостя: поза school network гість не заходить
          у систему взагалі, до будь-яких обчислень довіри.

  ШАР 1 — IDENTITY GATE: чи ця роль взагалі має право торкатися ресурсу
          (рольові межі — teacher ніколи не бачить student_hub, і навпаки).

  ШАР 2 — CONTEXT: динамічний 100-бальний Trust Score контексту запиту.

  ШАР 3 — RESOURCE SENSITIVITY: рівень чутливості ресурсу визначає,
          який саме Trust Score потрібен для FULL / READ_ONLY / LIMITED / DENY.

Trust Score (макс. 100):
  Device:  managed = 50  /  unmanaged (BYOD) = 30
  Network: school  = 50  /  home = 30  /  public = 10
  VPN:     +10, лише якщо network != school
           (підтягує мережу до стелі School, але не перевищує її:
            30+10=40 < 50, 10+10=20 < 50 — clamp не потрібен математично)
  MFA:     +10, лише якщо device != managed
           (підтягує пристрій до стелі Managed, але не перевищує її:
            30+10=40 < 50 — clamp не потрібен математично)

Resource Sensitivity:
  critical → admin_users (створення/видалення/паролі користувачів)
  high     → admin_panel (SIEM-дашборд, логи безпеки)
  medium   → staff_panel, academic_ledger, student_hub
  low      → submissions, e_library, public_res (DMZ — нечутливі дані)
"""

# ---------------------------------------------------------------------------
# КОНФІГУРАЦІЯ: рівень чутливості кожного ресурсу
# ---------------------------------------------------------------------------
RESOURCE_SENSITIVITY = {
    "admin_users":     "critical",
    "admin_panel":     "high",
    "staff_panel":     "medium",
    "academic_ledger": "medium",
    "student_hub":     "medium",
    "submissions":     "low",
    "e_library":       "low",
    "public_res":      "low",
}

ALL_RESOURCES = list(RESOURCE_SENSITIVITY.keys())

# ---------------------------------------------------------------------------
# КОНФІГУРАЦІЯ: які ресурси кожна роль взагалі може торкатися (IDENTITY GATE)
# ---------------------------------------------------------------------------
ROLE_ELIGIBLE_RESOURCES = {
    "admin": {
        "admin_users", "admin_panel",
        "staff_panel", "academic_ledger", "student_hub",  # аудит, не власні
        "submissions", "e_library", "public_res",
    },
    "teacher": {
        "staff_panel", "academic_ledger",
        "submissions", "e_library", "public_res",
    },
    "student": {
        "student_hub",
        "submissions", "e_library", "public_res",
    },
    "guest": {
        "public_res", "e_library",
    },
}

# Ресурси, які роль бачить ЛИШЕ в режимі аудиту (READ_ONLY-стеля,
# незалежно від того, що дав би загальний sensitivity-розрахунок).
# Приклад: admin може лише ПЕРЕГЛЯДАТИ кабінет вчителя/учня, ніколи не редагувати.
ROLE_AUDIT_ONLY_RESOURCES = {
    "admin": {"staff_panel", "academic_ledger", "student_hub"},
}

# Ресурси, де "повний" функціональний доступ ролі має змістовнішу власну назву
# замість голого FULL (зберігаємо семантику з попередньої версії політик).
ROLE_FULL_ACCESS_LABEL_OVERRIDE = {
    ("teacher", "submissions"): "REVIEW_ONLY",
    ("student", "submissions"): "SUBMIT_ONLY",
}


def _calculate_trust_score(device, network, vpn, mfa_verified):
    """Обчислює 100-бальний Trust Score на основі контексту запиту."""
    device_score = 50 if device == "managed" else 30
    network_score = 50 if network == "school" else (30 if network == "home" else 10)

    vpn_bonus = 10 if (vpn == "yes" and network != "school") else 0
    mfa_bonus = 10 if (mfa_verified and device != "managed") else 0

    return device_score + network_score + vpn_bonus + mfa_bonus


def _trust_level_label(trust_score):
    """
    Узагальнена 3-рівнева мітка для банера вердикту (denied.html).
    Пороги узгоджені з 6-смуговою таблицею нижче: 90+ охоплює найвищі дві
    смуги, 60-89 — середні дві, нижче 60 — найслабші дві.
    """
    if trust_score >= 90:
        return "Trusted"
    elif trust_score >= 60:
        return "Medium Risk"
    else:
        return "High Risk"


def _access_level_for_tier(tier, trust_score):
    """
    Універсальний рушій: для рівня чутливості ресурсу (critical/high/medium/low)
    і поточного Trust Score визначає БАЗОВИЙ рівень доступу
    (до застосування рольових накладок типу audit-only чи REVIEW_ONLY).

    Low-tier ресурси (DMZ) лишаються FULL за будь-якого Trust Score —
    вони за визначенням нечутливі, тож не мають сенсу обмежуватись
    навіть при мінімальній довірі (інакше Trust Score 40 матиме БІЛЬШЕ
    доступу, ніж Trust Score 45 — нелогічний "провал" у таблиці).
    """
    if tier == "low":
        return "FULL"

    if trust_score == 100:
        return "FULL"

    if trust_score >= 90:
        return "FULL" if tier in ("high", "medium") else "LIMITED"  # critical

    if trust_score >= 70:
        return "FULL" if tier == "medium" else "LIMITED"  # critical, high

    if trust_score >= 60:
        return "FULL" if tier == "medium" else "DENY"  # critical, high

    if trust_score >= 41:
        return "LIMITED" if tier == "medium" else "DENY"  # critical, high

    # trust_score <= 40
    return "DENY"  # critical, high, medium (low вже оброблено вище)


def evaluate_access(role, device, network, vpn="no", mfa_verified=False):
    """
    Zero Trust Policy Decision Point v9.0 — Risk-Based Access Control.
    Повертає (status, trust_score, trust_level, reason_key, permissions).
    """
    if not role:
        role = "guest"

    # -----------------------------------------------------------------
    # ШАР 0: Жорсткий периметр гостя
    # -----------------------------------------------------------------
    if role == "guest" and network != "school":
        return (
            "DENY",
            0,
            "High Risk",
            "Guest role restriction: access allowed only within school network",
            {resource: "DENY" for resource in ALL_RESOURCES},
        )

    # -----------------------------------------------------------------
    # ШАР 2: CONTEXT — обчислення Trust Score
    # -----------------------------------------------------------------
    trust_score = _calculate_trust_score(device, network, vpn, mfa_verified)
    trust_level = _trust_level_label(trust_score)

    # -----------------------------------------------------------------
    # ШАР 1 + 3: IDENTITY GATE (які ресурси роль бачить) поєднано з
    #            RESOURCE SENSITIVITY (який рівень доступу дає Trust Score)
    # -----------------------------------------------------------------
    permissions = {resource: "DENY" for resource in ALL_RESOURCES}
    eligible = ROLE_ELIGIBLE_RESOURCES.get(role, set())
    audit_only = ROLE_AUDIT_ONLY_RESOURCES.get(role, set())

    for resource in eligible:
        tier = RESOURCE_SENSITIVITY[resource]
        level = _access_level_for_tier(tier, trust_score)

        if resource in audit_only:
            # Аудит-ресурс: стеля READ_ONLY, навіть якщо tier дав би FULL/LIMITED
            level = "READ_ONLY" if level in ("FULL", "READ_ONLY", "LIMITED") else "DENY"
        else:
            override_label = ROLE_FULL_ACCESS_LABEL_OVERRIDE.get((role, resource))
            if level == "FULL" and override_label:
                level = override_label

        permissions[resource] = level

    # Гостьова e_library — спеціальний виняток: завжди LIMITED, ніколи FULL
    if role == "guest" and "e_library" in permissions:
        if permissions["e_library"] != "DENY":
            permissions["e_library"] = "LIMITED"

    # -----------------------------------------------------------------
    # ШАР 4: PEP VERDICT — формування ключа причини для перекладу
    # -----------------------------------------------------------------
    if trust_level == "Trusted":
        reason_key = (
            "Admin authorized" if role == "admin" else f"{role.capitalize()} authorized"
        )
    elif trust_level == "Medium Risk":
        reason_key = f"{role.capitalize()} limited access: Medium Trust Level restriction"
    else:
        reason_key = f"{role.capitalize()} limited access: Low Trust Level restriction"

    return "ACCESS_GRANTED", trust_score, trust_level, reason_key, permissions