def evaluate_access(role, device, network):
    """
    Динамічний рушій політик Zero Trust (Policy Decision Point) v3.0.
    Повністю інтегрований з матрицею доступу магістерського дослідження.
    """
    # 1. Захист за замовчуванням (Гість або неавторизований)
    if role == "guest" or not role:
        return "DENY", 0, "Guest role restriction"

    # 2. Розрахунок Trust Score
    device_score = 50 if device == "managed" else 20
    network_score = 50 if network == "school" else (20 if network == "home" else 0)
    trust_score = device_score + network_score

    # 3. Визначення Trust Level
    if 80 <= trust_score <= 100:
        trust_level = "High"
    elif 50 <= trust_score <= 79:
        trust_level = "Medium"
    else:
        trust_level = "Low"

    # =========================================================================
    # 4. АДАПТИВНИЙ КОНТРОЛЬ ДОСТУПУ ЗГІДНО З ТАБЛИЦЕЮ КОРИСТУВАЧА
    # =========================================================================

    # СУВОРІ ПОЛІТИКИ ДЛЯ АДМІНІСТРАТОРА
    if role == "admin":
        if trust_level == "High":  # (Managed + School = 100)
            return "ALLOW", trust_score, "Admin authorized"
        elif (
            trust_level == "Medium"
        ):  # (Managed+Home=70, BYOD+School=70, Managed+Public=50)
            return (
                "LIMITED",
                trust_score,
                "Admin limited access: Medium Trust Level restriction",
            )
        elif trust_level == "Low":  # (BYOD+Home=40, BYOD+Public=20)
            return (
                "LIMITED",
                trust_score,
                "Admin limited access: Low Trust Level restriction",
            )

    # ПОЛІТИКИ ДЛЯ ВЧИТЕЛІВ
    if role == "teacher":
        if trust_level == "High":  # (100)
            return "ALLOW", trust_score, "Teacher authorized"
        elif trust_level == "Medium":  # (70, 50)
            return (
                "LIMITED",
                trust_score,
                "Teacher limited access: Medium Trust Level restriction",
            )
        elif trust_level == "Low":  # (40, 20)
            return (
                "LIMITED",
                trust_score,
                "Teacher limited access: Low Trust Level restriction",
            )

    # ПОЛІТИКИ ДЛЯ СТУДЕНТІВ
    if role == "student":
        if trust_level == "High":  # (100)
            return "ALLOW", trust_score, "Student authorized"
        elif trust_level == "Medium":  # (70, 50)
            return (
                "LIMITED",
                trust_score,
                "Student limited access: Medium Trust Level restriction",
            )
        elif trust_level == "Low":  # (40, 20)
            return (
                "LIMITED",
                trust_score,
                "Student limited access: Low Trust Level restriction",
            )

    return "DENY", 0, "Unknown security policy state"
