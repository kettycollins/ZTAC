import json
from datetime import datetime

LOG_FILE = "logs/access_logs.json"


def log_event(username, role, device, network, decision, trust_score, reason):
    """
    Розширене логування подій безпеки для Zero Trust системи.
    Фіксує контекст, фінальний вердикт, рівень довіри та прапорці підозрілої активності.
    """

    # Визначення підозрілої активності (Anomalous/Suspicious Behavior)
    suspicious_flag = False

    # Сценарій 1: Спроба доступу адміністратора з небезпечного контексту
    if role == "admin" and (device == "unmanaged" or network == "public"):
        suspicious_flag = True

    # Сценарій 2: Тотальна заборона доступу через критично низьку довіру
    elif decision == "DENY" and trust_score <= 10:
        suspicious_flag = True

    # Формування розширеного запису логу
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "role": role,
        "context": {"device": device, "network": network},
        "security_metrics": {
            "trust_score": trust_score,
            "decision": decision,
            "reason": reason,
        },
        "incident_response": {"suspicious_flag": suspicious_flag},
    }

    # Читання існуючих логів
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            logs = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    # Додавання нового запису
    logs.append(log_entry)

    # Запис у JSON-файл
    with open(LOG_FILE, "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4, ensure_ascii=False)

    # Вивід у консоль для зручності демонстрації під час захисту
    status_symbol = (
        "🔴" if decision == "DENY" else ("🟡" if decision == "LIMITED" else "🟢")
    )
    print(
        f"\n[AUDIT LOG] {status_symbol} Decision: {decision} | User: {username} ({role}) | Trust Score: {trust_score} | Suspicious: {suspicious_flag}"
    )
    print(f"[REASON] {reason}")

    return log_entry


def create_log_file():
    """Створює пустий файл логів, якщо він відсутній."""
    import os

    # Створюємо папку logs, якщо її немає
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    try:
        with open(LOG_FILE, "x", encoding="utf-8") as file:
            json.dump([], file)
            print(f"[INIT] Файл логів успішно створено: {LOG_FILE}")
    except FileExistsError:
        print(f"[INIT] Файл логів уже існує: {LOG_FILE}")

    return
