import sqlite3
from database import get_db_connection


def authenticate_user(username, password):
    """
    Шукає користувача у вашій базі даних users.db.
    Захищає додаток від SQL-ін'єкцій за допомогою параметризації запитів.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Безпечний запит до SQLite
        cursor.execute(
            "SELECT username, role FROM users WHERE username = ? AND password = ?",
            (username, password),
        )
        user_row = cursor.fetchone()
        conn.close()

        # Якщо користувача з таким логіном і паролем знайдено
        if user_row:
            return {"username": user_row["username"], "role": user_row["role"]}

    except sqlite3.OperationalError as e:
        print(f"[ERROR] Помилка підключення до таблиці 'users': {e}")
        print("[ERROR] Перевірте, чи збігаються назви колонок у вашій базі даних.")
        return None

    # Якщо облікові дані невірні
    return None
