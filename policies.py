def evaluate_access(role, device, network):
    """
    Динамічний рушій політик Zero Trust (Policy Decision Point).
    Вираховує Trust Score на основі контексту запиту.
    """
    # Захист за замовчуванням (Deny by Default)
    if role == "guest" or not role:
        return "DENY", 0, "Guest role or unauthenticated access"

    # 1. Нарахування базових балів за пристрій (Device Trust)
    device_score = 0
    if device == "managed":
        device_score = 40
    elif device == "unmanaged":
        device_score = 10

    # 2. Нарахування базових балів за мережу (Network Trust)
    network_score = 0
    if network == "school":
        network_score = 40
    elif network == "home":
        network_score = 30
    elif network == "public":
        network_score = 0

    # Розрахунок фінального Trust Score
    trust_score = device_score + network_score

    # 3. Перевірка рольових обмежень та прийняття рішення (Context-Aware Logic)

    # Адміністратори мають дуже суворі критерії безпеки
    if role == "admin":
        if device != "managed" or network == "public":
            return (
                "DENY",
                trust_score,
                "Admin restriction: Managed device and secure network required",
            )
        return "ALLOW", trust_score, "Admin authorized"

    # Логіка для вчителів (Teachers)
    if role == "teacher":
        if trust_score >= 70:
            return "ALLOW", trust_score, "Teacher full access"
        elif 40 <= trust_score < 70:
            return (
                "LIMITED",
                trust_score,
                "Teacher limited access (Remote/BYOD context)",
            )
        else:
            return "DENY", trust_score, "Insufficient trust level for Teacher"

    # Логіка для студентів (Students)
    if role == "student":
        # Студентам заборонено доступ з публічних мереж у будь-якому випадку
        if network == "public":
            return (
                "DENY",
                trust_score,
                "Student restriction: Public networks are blocked",
            )

        if trust_score >= 70:
            return "ALLOW", trust_score, "Student full access within school"
        elif 40 <= trust_score < 70:
            return (
                "LIMITED",
                trust_score,
                "Student limited access (BYOD in school or home access)",
            )
        else:
            return "DENY", trust_score, "Insufficient trust level for Student"

    return "DENY", 0, "Unknown security policy state"
