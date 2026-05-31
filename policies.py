def evaluate_access(role, device, network, vpn="no"):
    """
    Динамічний рушій політик Zero Trust (Policy Decision Point) v5.0.
    Враховує суворе обмеження для гостей: доступ дозволено ТІЛЬКИ всередині School Network.
    """
    # ТИМЧАСОВИЙ ФІКС: Якщо роль порожня, маркуємо як guest
    if not role:
        role = "guest"

    # =========================================================================
    # СУВОРИЙ БЕЗПЕКОВИЙ ФІЛЬТР ДЛЯ ГОСТЯ (Guest Perimeter Protection)
    # =========================================================================
    if role == "guest":
        if network != "school":
            # Якщо гість поза шкільною мережею — тотальна заборона доступу
            return (
                "DENY",
                0,
                "High Risk",
                "Guest role restriction: access allowed only within school network",
                {
                    "admin_panel": "DENY",
                    "sys_config": "DENY",
                    "teaching_db": "DENY",
                    "academic_ledger": "DENY",
                    "student_hub": "DENY",
                    "e_library": "DENY",
                    "public_res": "DENY",
                },
            )

    # --- Розрахунок балів для легітимних сесій (включаючи гостей у шкільній мережі) ---
    # 1. Розрахунок балів за пристрій (Device Trust)
    device_score = 40 if device == "managed" else 20

    # 2. Розрахунок балів за мережу (Network Trust)
    network_score = 50 if network == "school" else (25 if network == "home" else 10)

    # 3. Розрахунок VPN бонуса
    vpn_score = 25 if vpn == "yes" else 0

    # Загальний Trust Score (Максимум 100)
    trust_score = min(device_score + network_score + vpn_score, 100)

    # 4. Визначення інтегрального рівня довіри/ризику (Trust Level)
    if 80 <= trust_score <= 100:
        trust_level = "Trusted"
    elif 60 <= trust_score <= 79:
        trust_level = "Low Risk"
    elif 40 <= trust_score <= 59:
        trust_level = "Medium Risk"
    else:
        trust_level = "High Risk"

    # =========================================================================
    # ПООБ'ЄКТНА МАТРИЦЯ ГРАНУЛЬОВАНОГО КОНТРОЛЮ ДОСТУПУ (Granular Authorization)
    # =========================================================================
    permissions = {
        "admin_panel": "DENY",
        "sys_config": "DENY",
        "teaching_db": "DENY",
        "academic_ledger": "DENY",
        "student_hub": "DENY",
        "e_library": "DENY",
        "public_res": "FULL",  # Завжди доступно для ALLOW сесій
    }

    # --- 1. ПРАВИЛА ДЛЯ РОЛІ: GUEST (Тільки якщо пройшов фільтр шкільної мережі) ---
    if role == "guest":
        # Гість у шкільній мережі отримує обмежений доступ до бібліотеки
        permissions["e_library"] = "LIMITED"
        reason = f"Guest context verified within perimeter. Trust Level: {trust_level}."
        return "ACCESS_GRANTED", trust_score, trust_level, reason, permissions

    # --- 2. АДМІНІСТРАТИВНІ РЕСУРСИ (Admin Panel & SysConfig) ---
    if role == "admin":
        if device == "managed" and network == "school":
            permissions["admin_panel"] = "FULL"
            permissions["sys_config"] = "FULL"
        elif device == "managed" and network == "home":
            permissions["admin_panel"] = "FULL"
            permissions["sys_config"] = "LIMITED"
        elif device == "managed" and network == "public" and vpn == "yes":
            permissions["admin_panel"] = "LIMITED"
            permissions["sys_config"] = "LIMITED"

    # --- 3. НАВЧАЛЬНІ РЕСУРСИ (Teaching Dashboard & Academic Ledger) ---
    if role == "teacher":
        if device == "managed" and network == "school":
            permissions["teaching_db"] = "FULL"
            permissions["academic_ledger"] = "FULL"
        elif device == "managed" and network == "home":
            permissions["teaching_db"] = "FULL"
        elif device == "byod" and network == "school":
            permissions["teaching_db"] = "FULL"
        elif device == "byod" and network == "home":
            permissions["teaching_db"] = "FULL"
            permissions["academic_ledger"] = "FULL"
        elif device == "byod" and network == "public":
            permissions["teaching_db"] = "LIMITED"
            permissions["academic_ledger"] = "LIMITED"

    # Аудит для адміністратора на вчительських об'єктах
    if role == "admin" and device == "managed":
        permissions["teaching_db"] = "READ_ONLY"
        permissions["academic_ledger"] = "READ_ONLY"

    # --- 4. СТУДЕНТСЬКІ РЕСУРСИ (Student Hub) ---
    if role == "student":
        if device == "byod" and network in ["school", "home"]:
            permissions["student_hub"] = "FULL"
        elif device == "byod" and network == "public":
            permissions["student_hub"] = "LIMITED"

    if role == "admin" and device == "managed":
        permissions["student_hub"] = "READ_ONLY"

    # --- 5. ЦИФРОВА БІБЛІОТЕКА (E-Library для авторизованих користувачів) ---
    if (device == "managed" or device == "byod") and (
        network == "school" or network == "home"
    ):
        permissions["e_library"] = "FULL"
    elif device == "byod" and network == "public":
        permissions["e_library"] = "LIMITED"

    reason = f"Access context processed for {role}. Trust Level: {trust_level}."
    return "ACCESS_GRANTED", trust_score, trust_level, reason, permissions
