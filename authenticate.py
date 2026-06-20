import sqlite3
import pyotp
from werkzeug.security import check_password_hash
from database import get_db_connection

def authenticate_user(username, password):
    """
    Шукає користувача у вашій базі даних users.db (Захист від SQLi).
    Підтримує і нові хешовані паролі (werkzeug), і старі прості демо-паролі —
    щоб не треба було мігрувати вже існуючих admin1/teacher1/student1/guest1.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, password, role FROM users WHERE username = ?",
            (username,),
        )
        user_row = cursor.fetchone()
        conn.close()

        if not user_row:
            return None

        stored_password = user_row["password"]

        # Хешовані паролі (нові, створені через адмін-форму) завжди мають ці префікси
        if stored_password.startswith(("pbkdf2:", "scrypt:")):
            password_valid = check_password_hash(stored_password, password)
        else:
            # Старі демо-акаунти — звичайне порівняння рядків
            password_valid = stored_password == password

        if password_valid:
            return {"username": user_row["username"], "role": user_row["role"]}

    except sqlite3.OperationalError as e:
        print(f"[ERROR] Помилка підключення до таблиці 'users': {e}")
        return None

    return None


def get_or_create_totp_secret(username):
    """
    Повертає TOTP secret користувача для генерації QR-коду.
    Якщо секрету ще немає — створює новий і зберігає у БД.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if row and row["totp_secret"]:
        secret = row["totp_secret"]
    else:
        secret = pyotp.random_base32()
        cursor.execute(
            "UPDATE users SET totp_secret = ? WHERE username = ?", (secret, username)
        )
        conn.commit()

    conn.close()
    return secret


def verify_totp(username, otp_code):
    """
    Перевіряє TOTP код з Google Authenticator.

    ВАЖЛИВО: якщо користувач увімкнув тоглер MFA, але секрет ще не згенеровано
    (QR ще не відскановано) — перевірка ПРОВАЛЮЄТЬСЯ (False), а не пропускається.
    Інакше будь-хто міг би увімкнути MFA, ввести випадкові цифри і отримати
    бонус довіри без реального підтвердження пристрою — це підриває весь сенс MFA.
    """
    if not otp_code:
        return False

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not row["totp_secret"]:
        return False  # MFA увімкнено, але ще не налаштовано — код не може бути валідним

    # valid_window=1 дозволяє приймати код, який поспішає/відстає на 30 сек
    totp = pyotp.TOTP(row["totp_secret"])
    return totp.verify(otp_code, valid_window=1)
