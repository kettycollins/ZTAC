import json
from datetime import datetime

LOG_FILE = "logs/access_logs.json"


def log_event(username, role, device, network, vpn, decision, trust_score, reason, mfa=False):
    """
    Розширене логування подій безпеки для Zero Trust системи.
    Фіксує контекст (включаючи стан VPN та MFA), фінальний вердикт, рівень довіри та аномалії.

    Параметр mfa має default=False, щоб виклики log_event() зі старого коду
    (без передачі MFA) не ламались — нові записи просто отримають mfa=False.
    """

    # Визначення підозрілої активності (Anomalous/Suspicious Behavior)
    suspicious_flag = False

    # Сценарій 1: Спроба доступу адміністратора з небезпечного контексту
    if role == "admin" and (device == "unmanaged" or network == "public"):
        suspicious_flag = True

    # Сценарій 2: Тотальна заборона доступу через критично низьку довіру
    elif decision == "DENY" and trust_score <= 10:
        suspicious_flag = True

    # Формування розширеного запису логу (Додано параметр vpn та mfa)
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "username": username,
        "role": role,
        "context": {
            "device": device,
            "network": network,
            "vpn": vpn,
            "mfa": bool(mfa),
        },
        "security_metrics": {
            "decision": decision,
            "trust_score": trust_score,
            "reason": reason
        },
        "incident_response": {
            "suspicious_flag": suspicious_flag
        }
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
        f"\n[AUDIT LOG] {status_symbol} Decision: {decision} | User: {username} ({role}) | Trust Score: {trust_score} | VPN: {vpn} | MFA: {bool(mfa)} | Suspicious: {suspicious_flag}"
    )
    print(f"[REASON] {reason}")

    return log_entry


def create_log_file():
    """Створює пустий файл логів, якщо він відсутній."""
    import os

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    try:
        with open(LOG_FILE, "x", encoding="utf-8") as file:
            json.dump([], file)
            print(f"[INIT] Файл логів успішно створено: {LOG_FILE}")
    except FileExistsError:
        print(f"[INIT] Файл логів уже існує: {LOG_FILE}")
    return