# database.py
import sqlite3
import os
from config import Config


def get_db_connection():
    """Встановлює безпечне з'єднання з файлом бази даних SQLite."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Ініціалізує структуру бази даних та забезпечує зворотну сумісність для MFA."""
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Створюємо таблицю users
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            totp_secret TEXT
        )
    """)

    # Міграція: Перевіряємо, чи існує колонка totp_secret (якщо базу було створено раніше без неї)
    try:
        cursor.execute("SELECT totp_secret FROM users LIMIT 1")
    except sqlite3.OperationalError:
        print("[DATABASE] Міграція: додавання колонки totp_secret до таблиці users...")
        cursor.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")

    # Перевіряємо наповнення тестовими даними
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Для admin1 жорстко прописуємо базовий secret: JBSWY3DPEHPK3PXP
        # Ти можеш ввести його в додаток Google Authenticator вручну або через QR
        test_users = [
            ("admin1", "admin123", "admin", "JBSWY3DPEHPK3PXP"),
            ("teacher1", "teacher123", "teacher", None),
            ("student1", "student123", "student", None),
            ("guest1", "guest123", "guest", None),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, role, totp_secret) VALUES (?, ?, ?, ?)",
            test_users,
        )
        print("[DATABASE] Базових користувачів та MFA-секрети успішно ініціалізовано.")
    else:
        # На всяк випадок оновимо секрет для admin1, якщо колонка була порожньою після міграції
        cursor.execute(
            "UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP' WHERE username = 'admin1' AND totp_secret IS NULL"
        )
        print(
            "[DATABASE] Структуру бази даних підтверджено. Зворотну сумісність збережено."
        )

    conn.commit()
    conn.close()
    print("[DATABASE] Ініціалізацію підсистеми збереження даних завершено.")


def get_all_users():
    """
    Повертає список усіх користувачів для адмін-сторінки управління.
    mfa_configured = True, якщо для користувача вже згенеровано TOTP-секрет.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role, totp_secret FROM users ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "mfa_configured": bool(row["totp_secret"]),
        }
        for row in rows
    ]


def create_user(username, password_hash, role):
    """
    Додає нового користувача до бази даних.
    password_hash має бути вже хешований (через werkzeug.security.generate_password_hash)
    до виклику цієї функції — сама функція хешуванням не займається.

    Піднімає sqlite3.IntegrityError, якщо username вже зайнятий
    (поле UNIQUE у схемі таблиці) — обробку винятку робить виклична сторона.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        conn.commit()
    finally:
        conn.close()


def get_user_by_id(user_id):
    """Повертає одного користувача за id, або None якщо не знайдено."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
    return None


def update_user_password(user_id, password_hash):
    """Оновлює пароль користувача. password_hash має бути вже хешований."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password = ? WHERE id = ?", (password_hash, user_id)
    )
    conn.commit()
    conn.close()


def delete_user_by_id(user_id):
    """Видаляє користувача з бази даних за id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def count_admins():
    """Повертає кількість користувачів з роллю admin (для захисту від видалення останнього адміна)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    count = cursor.fetchone()[0]
    conn.close()
    return count
