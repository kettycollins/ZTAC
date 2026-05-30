import os


class Config:
    """Централізований клас конфігурації для Zero Trust MVP."""

    # Базова директорія проекту
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # Секретний ключ для захисту сесій користувачів
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "supersecret_zero_trust_key_2026")

    # Шлях до бази даних SQLite
    DATABASE_PATH = os.path.join(BASE_DIR, "data", "users.db")

    # Шлях до файлу JSON-логів
    LOG_FILE = os.path.join(BASE_DIR, "logs", "access_logs.json")
