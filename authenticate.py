# authenticate.py
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


def verify_totp(username, otp_code):
    """Перевіряє TOTP код з Google Authenticator. Якщо secret немає — пропускає."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT totp_secret FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and row["totp_secret"]:
        # valid_window=1 дозволяє приймати код, який поспішає або відстає на 30 сек
        totp = pyotp.TOTP(row["totp_secret"])
        return totp.verify(otp_code, valid_window=1)

    return True  # Якщо секрет не встановлено — пропускати (для зворотної сумісності вчителів/студентів)
