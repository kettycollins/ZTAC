import re

MIN_LENGTH = 10


def validate_password(password, username=None):
    """
    Перевіряє пароль на відповідність політиці безпеки Zero Trust:
      - мінімум MIN_LENGTH символів
      - хоча б одна велика літера (A-Z)
      - хоча б одна мала літера (a-z)
      - хоча б одна цифра
      - хоча б один спецсимвол
      - не повинен містити username (якщо переданий) — захист від паролів типу "admin1admin1"

    Повертає кортеж (is_valid: bool, reason_key: str | None).
    reason_key — це ключ для словника TRANSLATIONS, який викличе app.py
    при формуванні повідомлення про помилку.
    """
    if not password or len(password) < MIN_LENGTH:
        return False, "pwd_error_length"

    if not re.search(r"[A-Z]", password):
        return False, "pwd_error_upper"

    if not re.search(r"[a-z]", password):
        return False, "pwd_error_lower"

    if not re.search(r"\d", password):
        return False, "pwd_error_digit"

    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "pwd_error_special"

    if username and username.lower() in password.lower():
        return False, "pwd_error_username"

    return True, None
