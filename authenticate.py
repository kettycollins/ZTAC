import sqlite3
import pyotp
from database import get_db_connection



def authenticate_user(username, password):
    """Шукає користувача у вашій базі даних users.db (Захист від SQLi)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, role FROM users WHERE username = ? AND password = ?",
            (username, password),
        )
        user_row = cursor.fetchone()
        conn.close()
        if user_row:
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
