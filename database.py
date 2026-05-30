import sqlite3
import os
from config import Config


def get_db_connection():
    """
    Встановлює безпечне з'єднання з файлом бази даних SQLite.
    Використовує шлях, прописаний у конфігураційному файлі.
    """
    conn = sqlite3.connect(Config.DATABASE_PATH)
    # Row дозволяє читати рядки з бази як словники: user['role'] замість user[2]
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Перевіряє наявність таблиць у вашій існуючій базі даних.
    Якщо база порожня — створює структуру та додає тестових користувачів.
    """
    # Перевіряємо, чи існує папка data (якщо ні — створюємо)
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Створюємо таблицю users ТІЛЬКИ якщо її ще немає у вашому файлі users.db
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # Перевіряємо, чи є в таблиці користувачі
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # Якщо таблиця була абсолютно порожньою, наповнюємо її базовими ролями для тестів
        test_users = [
            ("admin1", "admin123", "admin"),
            ("teacher1", "teacher123", "teacher"),
            ("student1", "student123", "student"),
            ("guest1", "guest123", "guest"),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)", test_users
        )
        print(
            "[DATABASE] Таблиця була порожньою. Тестових користувачів успішно додано."
        )
    else:
        print(
            "[DATABASE] Виявлено існуючу таблицю користувачів. Перезапис не потрібен."
        )

    conn.commit()
    conn.close()
    print("[DATABASE] Ініціалізацію підсистеми збереження даних завершено.")
