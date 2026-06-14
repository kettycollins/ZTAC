# policies.py


def evaluate_access(role, device, network, vpn="no"):
    """
    Динамічний рушій політик Zero Trust (Policy Decision Point) v7.0.
    Повністю адаптований під оновлену 100-бальну математичну модель контексту:
    - Device: Managed = 50, BYOD = 30
    - Network: School = 50, Home = 30, Public = 10
    - Extra Protection (VPN/MFA): On = 20, Off = 0
    """
    # Якщо роль порожня, маркуємо як guest
    if not role:
        role = "guest"

    # =========================================================================
    # СУВОРИЙ БЕЗПЕКОВИЙ ФІЛЬТР ДЛЯ ГОСТЯ (Guest Perimeter Protection)
    # =========================================================================
    if role == "guest":
        if network != "school":
            # Якщо гість поза шкільною мережею — тотальна превентивна заборона доступу (0 балів)
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

    # =========================================================================
    # 1. ОБЧИСЛЕННЯ ДИНАМІЧНОГО TRUST SCORE (ДЛЯ ЛЕГІТИМНИХ КОНТЕКСТІВ)
    # =========================================================================
    device_score = 50 if device == "managed" else 30
    network_score = 50 if network == "school" else (30 if network == "home" else 10)
    extra_score = 20 if vpn == "yes" else 0

    trust_score = device_score + network_score + extra_score

    # Визначення інтегрального рівня ризику на основі вашої шкали thresholds
    if trust_score >= 80:
        trust_level = "Trusted"
    elif 50 <= trust_score <= 79:
        trust_level = "Medium Risk"
    else:
        trust_level = "High Risk"

    # =========================================================================
    # 2. ІНІЦІАЛІЗАЦІЯ МАТРИЦІ ДОЗВОЛІВ ЗА ПРИНЦИПОМ DEFAULT DENY
    # =========================================================================
    permissions = {
        "admin_panel": "DENY",  # 🛡️ Панель адміна
        "sys_config": "DENY",  # ⚙️ Конфігурація
        "staff_panel": "DENY",  # 📝 Панель викладача
        "academic_ledger": "DENY",  # 📊 Система оцінювання / Журнал
        "student_hub": "DENY",  # 📖 Особистий кабінет учня
        "submissions": "DENY",  # 🎓 Student Submissions
        "e_library": "DENY",  # 📚 Цифрова бібліотека
        "public_res": "DENY",  # 🌐 Відкриті ресурси
    }

    # =========================================================================
    # 3. ГРАНУЛЬОВАНЕ НАРІЗАННЯ ПРАВ ЗГІДНО З ПОРОГАМИ ДОСТУПУ ТАБЛИЦІ
    # =========================================================================

    # 3.1 Загальні ресурси (Public resources)
    # Доступні всім, при Score >= 40 (Гості поза школою відсіклися вище)
    if trust_score >= 40:
        permissions["public_res"] = "FULL"

    # 3.2 Роль: ADMIN
    if role == "admin":
        if device == "managed":
            # Категорія: Критичні ресурси адміна (Поріг: >=80 Full, 50-79 Limited, <50 Deny)
            if trust_score >= 80:
                permissions["admin_panel"] = "FULL"
                permissions["sys_config"] = "FULL"
                permissions["e_library"] = "FULL"

            elif 50 <= trust_score <= 79:
                permissions ["admin_panel"] = "LIMITED"
                permissions["sys_config"] = "LIMITED"
                permissions["e_library"] = "LIMITED"

            # Особливе правило аудиту: адмін бачить кабінети інших ролей у Read-only (якщо Score >= 50)
            if trust_score >= 50:
                permissions["staff_panel"] = "READ_ONLY"
                permissions["academic_ledger"] = "READ_ONLY"
                permissions["student_hub"] = "READ_ONLY"
                permissions["submissions"] = "READ_ONLY"

        # Якщо Admin заходить з BYOD -> Залишається DENY за ТЗ, окрім шкільної мережі
        if device == "unmanaged" and network == "school":
            if trust_score >= 60:
                permissions["admin_panel"] = "LIMITED"
                permissions["sys_config"] = "LIMITED"
                permissions["e_library"] = "FULL"
                permissions["staff_panel"] = "READ_ONLY"
                permissions["academic_ledger"] = "READ_ONLY"
                permissions["student_hub"] = "READ_ONLY"
                permissions["submissions"] = "READ_ONLY"

    # 3.3 Роль: TEACHER
    if role == "teacher":
        # Категорія: Критичні ресурси вчителя (Поріг: >=80 Full, 50-79 Limited, <50 Deny)
        if trust_score >= 80:
            permissions["staff_panel"] = "FULL"
            permissions["academic_ledger"] = "FULL"  # Редагування оцінок
        elif 50 <= trust_score <= 79:
            permissions["staff_panel"] = "LIMITED"  # Тільки перегляд
            permissions["academic_ledger"] = "LIMITED"

        # Категорія: Некритичні ресурси (Библиотека: >=50 Full, <50 Limited читання без редагування)
        if trust_score >= 50:
            permissions["e_library"] = "FULL"
        else:
            permissions["e_library"] = "LIMITED"

        # Студентські роботи: Перегляд/Рецензування (якщо сесія жива)
        if trust_score >= 50:
            permissions["submissions"] = "REVIEW_ONLY"

    # 🎓 3.4 Роль: STUDENT
    if role == "student":
        # Категорія: Некритичні ресурси (Кабінет учня, Бібліотека)
        # Поріг: >=50 Full, <50 Limited (Тільки читання книг, без здачі робіт чи редагування)
        if trust_score >= 50:
            permissions["student_hub"] = "FULL"
            permissions["e_library"] = "FULL"
            permissions["submissions"] = "SUBMIT_ONLY"  # Можна завантажувати ДЗ
        else:
            permissions["student_hub"] = "LIMITED"
            permissions["e_library"] = (
                "LIMITED"  # Тільки читати книги в кафе без захисту
            )
            permissions["submissions"] = (
                "DENY"  # Здача робіт заблокована через небезпечну мережу
            )

    # 3.5 Роль: GUEST
    if role == "guest" and network == "school":
        # Тільки всередині школи гість отримує повний доступ до оголошень та обмежену бібліотеку
        permissions["public_res"] = "FULL"
        permissions["e_library"] = "LIMITED"

    # =========================================================================
    # 4. КІНЦЕВЕ ВИЗНАЧЕННЯ СТАТУСУ СЕСІЇ (PEP VERDICT)
    # =========================================================================
    # Якщо загальний скоринг впав до критичного рівня і користувач заблокований на базових вузлах
    if role == "admin" and device == "unmanaged" and network != "school":
        return (
            "DENY",
            trust_score,
            "High Risk",
            "Guest role restriction",
            permissions,
        )

    if trust_score < 40 and role not in ["student", "teacher"]:
        return (
            "DENY",
            trust_score,
            trust_level,
            "Guest role restriction",
            permissions,
        )

    # ДИНАМІЧНИЙ ПІДБІР СТАТИЧНОГО КЛЮЧА ДЛЯ СЛОВНИКА ПЕРЕКЛАДІВ
    if trust_level == "Approve" or trust_level == "Trusted":
        reason_key = f"{role.capitalize()} authorized"
    elif trust_level == "Medium Risk":
        reason_key = (
            f"{role.capitalize()} limited access: Medium Trust Level restriction"
        )
    else:
        reason_key = f"{role.capitalize()} limited access: Low Trust Level restriction"

    return "ACCESS_GRANTED", trust_score, trust_level, reason_key, permissions
