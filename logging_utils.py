"""
Zero Trust Security Event Logger v2.0

Три типи подій (event_type):
  AUTH        — кожна спроба автентифікації та авторизації доступу.
  ADMIN_OP    — адміністративні операції (create_user / delete_user / change_password).
  UNAUTH_ACCESS — спроба прямого звернення до захищеного URL без потрібної ролі.

Структура запису спільна для всіх типів, щоб дашборд міг фільтрувати
за тими самими полями (security_metrics.decision, incident_response.suspicious_flag тощо).
Поля, специфічні для типу, зберігаються в окремому блоці event_details.
"""

import json
import os
from datetime import datetime, timezone

LOG_FILE = "logs/access_logs.json"

# ---------------------------------------------------------------------------
# ВНУТРІШНІЙ ХЕЛПЕР
# ---------------------------------------------------------------------------


def _compute_access_level(permissions: dict | None) -> str:
    """
    Зводить словник permissions до єдиного рядка для security_metrics.access_level.
    Показує найвищий реально наданий рівень (не DENY).
    """
    if not permissions:
        return "DENY"
    priority = ("FULL", "REVIEW_ONLY", "SUBMIT_ONLY", "READ_ONLY", "LIMITED", "DENY")
    values = set(permissions.values())
    for level in priority:
        if level in values:
            return level
    return "DENY"


def _suspicious(role, device, network, decision, trust_score, event_type) -> bool:
    """
    Визначає підозрілі події за розширеними критеріями.
    Будь-яка UNAUTH_ACCESS подія є підозрілою за визначенням.
    """
    if event_type == "UNAUTH_ACCESS":
        return True
    # AUTH: адмін з небезпечного контексту
    if role == "admin" and (device == "unmanaged" or network == "public"):
        return True
    # AUTH/ADMIN_OP: будь-який DENY
    if decision == "DENY":
        return True
    return False


def _write_entry(entry: dict):
    """Атомарно дописує запис до JSON-файлу логів."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    logs.append(entry)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=4, ensure_ascii=False)

    return entry


# ---------------------------------------------------------------------------
# ФУНКЦІЯ 1: AUTH — кожна спроба автентифікації
# ---------------------------------------------------------------------------


def log_event(
    username,
    role,
    device,
    network,
    vpn,
    decision,
    trust_score,
    reason,
    mfa=False,
    permissions=None,
):
    """
    Реєструє кожну спробу доступу після проходження PDP.

    Нові поля порівняно з v1:
      security_metrics.access_level — зведений рівень доступу (FULL/READ_ONLY/LIMITED/DENY)
      security_metrics.trust_score  — числове значення Trust Score (0-100)
      security_metrics.permissions  — повна матриця прав по ресурсах
      event_type                    — "AUTH"
    """
    access_level = _compute_access_level(permissions)
    susp = _suspicious(role, device, network, decision, trust_score, "AUTH")

    entry = {
        "event_type": "AUTH",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username,
        "role": role,
        "context": {
            "device": device,
            "network": network,
            "vpn": vpn,
            "mfa": bool(mfa),
        },
        "security_metrics": {
            "decision": decision,
            "access_level": access_level,
            "trust_score": trust_score,
            "reason": reason,
            "permissions": permissions or {},
        },
        "incident_response": {
            "suspicious_flag": susp,
        },
    }

    _write_entry(entry)

    symbol = (
        "🔴" if decision == "DENY" else ("🟡" if access_level == "LIMITED" else "🟢")
    )
    print(
        f"\n[AUDIT AUTH] {symbol} {decision}/{access_level} | "
        f"User: {username} ({role}) | Score: {trust_score} | "
        f"VPN: {vpn} | MFA: {bool(mfa)} | Suspicious: {susp}"
    )
    print(f"[REASON] {reason}")
    return entry


# ---------------------------------------------------------------------------
# ФУНКЦІЯ 2: ADMIN_OP — адміністративні операції
# ---------------------------------------------------------------------------


def log_admin_operation(
    admin_username,
    operation,
    target_username,
    target_role=None,
    success=True,
    details=None,
    device=None,
    network=None,
    vpn=None,
    mfa=False,
):
    """
    Реєструє адміністративні операції: create_user, delete_user, change_password.

    Параметри:
      admin_username  — хто виконав дію
      operation       — "create_user" | "delete_user" | "change_password"
      target_username — над ким виконана дія
      target_role     — роль цільового користувача (None якщо невідомо)
      success         — True якщо операція успішна
      details         — довільний рядок з додатковим контекстом
      device/network/vpn/mfa — контекст сесії адміна на момент операції
    """
    decision = "ALLOW" if success else "DENY"
    reason = f"Admin operation: {operation}" + (f" — {details}" if details else "")
    susp = _suspicious(
        "admin", device or "unknown", network or "unknown", decision, 100, "ADMIN_OP"
    )

    entry = {
        "event_type": "ADMIN_OP",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": admin_username,
        "role": "admin",
        "context": {
            "device": device or "unknown",
            "network": network or "unknown",
            "vpn": vpn or "no",
            "mfa": bool(mfa),
        },
        "security_metrics": {
            "decision": decision,
            "access_level": "FULL" if success else "DENY",
            "trust_score": None,
            "reason": reason,
            "permissions": {},
        },
        "event_details": {
            "operation": operation,
            "target_username": target_username,
            "target_role": target_role,
            "success": success,
            "details": details,
        },
        "incident_response": {
            "suspicious_flag": susp,
        },
    }

    _write_entry(entry)

    symbol = "🟢" if success else "🔴"
    print(
        f"\n[AUDIT ADMIN_OP] {symbol} {operation} | "
        f"Admin: {admin_username} | Target: {target_username} ({target_role}) | "
        f"Success: {success}"
    )
    return entry


# ---------------------------------------------------------------------------
# ФУНКЦІЯ 3: UNAUTH_ACCESS — несанкціонований прямий доступ до URL
# ---------------------------------------------------------------------------


def log_unauthorized_access(
    username,
    role,
    attempted_url,
    required_role,
    device=None,
    network=None,
    vpn=None,
    mfa=False,
):
    """
    Реєструє спробу прямого звернення до URL, захищеного вищими привілеями.
    Завжди suspicious_flag = True, decision = DENY.

    Параметри:
      username      — хто намагався отримати доступ (або 'anonymous')
      role          — поточна роль користувача
      attempted_url — URL, до якого намагались отримати доступ
      required_role — роль, яка насправді потрібна
    """
    reason = (
        f"Unauthorized access attempt: role '{role}' tried to access "
        f"'{attempted_url}' (requires '{required_role}')"
    )

    entry = {
        "event_type": "UNAUTH_ACCESS",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": username or "anonymous",
        "role": role or "anonymous",
        "context": {
            "device": device or "unknown",
            "network": network or "unknown",
            "vpn": vpn or "no",
            "mfa": bool(mfa),
        },
        "security_metrics": {
            "decision": "DENY",
            "access_level": "DENY",
            "trust_score": None,
            "reason": reason,
            "permissions": {},
        },
        "event_details": {
            "attempted_url": attempted_url,
            "required_role": required_role,
        },
        "incident_response": {
            "suspicious_flag": True,
        },
    }

    _write_entry(entry)

    print(
        f"\n[AUDIT UNAUTH] 🔴 DENY | "
        f"User: {username or 'anonymous'} ({role}) | "
        f"Attempted: {attempted_url} | Required: {required_role}"
    )
    return entry


# ---------------------------------------------------------------------------
# УТИЛІТА: ініціалізація файлу логів
# ---------------------------------------------------------------------------


def create_log_file():
    """Створює пустий файл логів, якщо він відсутній."""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    try:
        with open(LOG_FILE, "x", encoding="utf-8") as f:
            json.dump([], f)
        print(f"[INIT] Файл логів успішно створено: {LOG_FILE}")
    except FileExistsError:
        print(f"[INIT] Файл логів уже існує: {LOG_FILE}")
