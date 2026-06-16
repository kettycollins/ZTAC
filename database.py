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
