# policies.py


def evaluate_access(role, device, network, vpn="no", mfa_verified=False):
    """
    Динамічний рушій політик Zero Trust (Policy Decision Point) v8.0-cloud.
    100-бальна математична модель контексту:
    - Device: Managed = 50, Unmanaged = 20
    - Network: School = 50, Home = 20, Public = 10
    - Extra Security (WireGuard VPN або MFA): +20 балів (макс бонус = 20)
    """
    if not role:
        role = "guest"

    if role == "guest":
        if network != "school":
            return (
                "DENY",
                0,
                "High Risk",
                "Guest role restriction: access allowed only within school network",
                {
                    "admin_panel": "DENY",
                    "sys_config": "DENY",
                    "staff_panel": "DENY",
                    "academic_ledger": "DENY",
                    "student_hub": "DENY",
                    "submissions": "DENY",
                    "e_library": "DENY",
                    "public_res": "DENY",
                },
            )

    # 1. ОБЧИСЛЕННЯ TRUST SCORE
    device_score = 50 if device == "managed" else 20
    network_score = 50 if network == "school" else (20 if network == "home" else 10)
    extra_score = 20 if (vpn == "yes" or mfa_verified) else 0

    trust_score = device_score + network_score + extra_score

    if trust_score >= 80:
        trust_level = "Trusted"
    elif 50 <= trust_score <= 79:
        trust_level = "Medium Risk"
    else:
        trust_level = "High Risk"

    # 2. ІНІЦІАЛІЗАЦІЯ МАТРИЦІ ДОЗВОЛІВ
    permissions = {
        "admin_panel": "DENY",
        "sys_config": "DENY",
        "staff_panel": "DENY",
        "academic_ledger": "DENY",
        "student_hub": "DENY",
        "submissions": "DENY",
        "e_library": "DENY",
        "public_res": "DENY",
    }

    if trust_score >= 40:
        permissions["public_res"] = "FULL"

    # 3.2 Роль: ADMIN
    if role == "admin":
        if device == "managed":
            if trust_score >= 80:
                permissions["admin_panel"] = "FULL"
                permissions["sys_config"] = "FULL"
                permissions["e_library"] = "FULL"
            elif 50 <= trust_score <= 79:
                permissions["admin_panel"] = "LIMITED"
                permissions["sys_config"] = "LIMITED"
                permissions["e_library"] = "LIMITED"
            if trust_score >= 50:
                permissions["staff_panel"] = "READ_ONLY"
                permissions["academic_ledger"] = "READ_ONLY"
                permissions["student_hub"] = "READ_ONLY"
                permissions["submissions"] = "READ_ONLY"

        # BYOD-правило: якщо адмін на unmanaged у школі + увімкнув WireGuard або здав MFA -> отримав 80 балів!
        if device == "unmanaged" and network == "school":
            if trust_score >= 80:
                permissions["admin_panel"] = "LIMITED"
                permissions["sys_config"] = "LIMITED"
                permissions["e_library"] = "FULL"
                permissions["staff_panel"] = "READ_ONLY"
                permissions["academic_ledger"] = "READ_ONLY"
                permissions["student_hub"] = "READ_ONLY"
                permissions["submissions"] = "READ_ONLY"
            elif 50 <= trust_score <= 79:
                permissions["admin_panel"] = "DENY"
                permissions["sys_config"] = "DENY"
                permissions["e_library"] = "LIMITED"

    # 3.3 Роль: TEACHER
    if role == "teacher":
        if trust_score >= 80:
            permissions["staff_panel"] = "FULL"
            permissions["academic_ledger"] = "FULL"
        elif 50 <= trust_score <= 79:
            permissions["staff_panel"] = "LIMITED"
            permissions["academic_ledger"] = "LIMITED"

        if trust_score >= 50:
            permissions["e_library"] = "FULL"
        else:
            permissions["e_library"] = "LIMITED"

        if trust_score >= 50:
            permissions["submissions"] = "REVIEW_ONLY"

    # 3.4 Роль: STUDENT
    if role == "student":
        if trust_score >= 50:
            permissions["student_hub"] = "FULL"
            permissions["e_library"] = "FULL"
            permissions["submissions"] = "SUBMIT_ONLY"
        else:
            permissions["student_hub"] = "LIMITED"
            permissions["e_library"] = "LIMITED"
            permissions["submissions"] = "DENY"

    # 3.5 Роль: GUEST
    if role == "guest" and network == "school":
        permissions["public_res"] = "FULL"
        permissions["e_library"] = "LIMITED"

    # 4. PEP VERDICT
    if (
        role == "admin"
        and device == "unmanaged"
        and network != "school"
        and not mfa_verified
    ):
        return (
            "DENY",
            trust_score,
            "High Risk",
            "Admin limited access: Low Trust Level restriction",
            permissions,
        )

    if trust_score < 40 and role not in ["student", "teacher"]:
        return ("DENY", trust_score, trust_level, "Guest role restriction", permissions)

    # Залізобетонні мовні ключі, які 100% є у твому translations.py
    if trust_level in ["Approve", "Trusted"]:
        reason_key = (
            "Admin authorized" if role == "admin" else f"{role.capitalize()} authorized"
        )
    elif trust_level == "Medium Risk":
        reason_key = (
            f"{role.capitalize()} limited access: Medium Trust Level restriction"
        )
    else:
        reason_key = f"{role.capitalize()} limited access: Low Trust Level restriction"

    return "ACCESS_GRANTED", trust_score, trust_level, reason_key, permissions
