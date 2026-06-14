import os
import json
from flask import Flask, render_template, request, redirect, url_for, session
from config import Config
from database import init_db
from authenticate import authenticate_user
from policies import evaluate_access
from logging_utils import log_event
from translations import TRANSLATIONS

app = Flask(__name__)
app.jinja_env.filters["uppercase"] = lambda s: s.upper() if s else ""
app.config.from_object(Config)


@app.context_processor
def inject_translations():
    lang = session.get("lang", "uk")
    return dict(lang=lang, t=TRANSLATIONS.get(lang, TRANSLATIONS["uk"]))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        device = request.form.get("device")
        network = request.form.get("network")
        vpn = request.form.get("vpn", "no")  # Зчитуємо інтерактивний повзунок VPN

        user = authenticate_user(username, password)

        if user:
            try:
                # Первинний виклик рушія політик Zero Trust PDP
                status, score, trust_level, reason, permissions = evaluate_access(
                    user["role"], device, network, vpn
                )

                # Записуємо первинні контекстні метрики у сесію користувача
                session["user"] = user["username"]
                session["role"] = user["role"]
                session["device"] = device
                session["network"] = network
                session["vpn"] = vpn

                # ПЕРЕВІРКА ПЕРИМЕТРА: Якщо рушій політик повернув DENY (наприклад, гість поза School Net)
                if status == "DENY":
                    # Логуємо інцидент безпеки із суворим вердиктом DENY
                    log_event(
                        username,
                        user["role"],
                        device,
                        network,
                        vpn,
                        "DENY",
                        score,
                        reason,
                    )

                    user_data = {
                        "username": session.get("user"),
                        "role": session.get("role"),
                        "device": session.get("device"),
                        "network": session.get("network"),
                        "vpn": session.get("vpn"),
                    }
                    # Відображаємо екран жорсткого блокування
                    return render_template(
                        "denied.html",
                        decision="DENY",
                        score=score,
                        trust_level=trust_level,
                        reason=reason,
                        user=user_data,
                    )

                # Якщо перевірку пройдено (ACCESS_GRANTED), логуємо ALLOW і йдемо далі
                log_event(
                    username, user["role"], device, network, vpn, "ALLOW", score, reason
                )
                return redirect(url_for("decision_page"))

            except Exception as e:
                print(f"[SERVER ERROR] Помилка обробки політики доступу: {e}")
                return render_template(
                    "login.html", error="Внутрішня помилка PDP сервера."
                )
        else:
            lang = session.get("lang", "uk")
            return render_template(
                "login.html", error=TRANSLATIONS[lang]["login_error"]
            )

    return render_template("login.html")


@app.route("/decision")
def decision_page():
    """Проміжний екран вердикту PDP перед переходом до інфраструктури"""
    if "user" not in session:
        return redirect(url_for("login"))

    # ДИНАМІЧНИЙ ПЕРЕРАХУНОК: Беремо свіжий ключ причини з рушія політик
    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        session.get("device"),
        session.get("network"),
        session.get("vpn", "no"),
    )

    user_data = {
        "username": session.get("user"),
        "role": session.get("role"),
        "device": session.get("device"),
        "network": session.get("network"),
        "vpn": session.get("vpn"),
    }

    return render_template(
        "denied.html",
        decision="ALLOW",  # Для успішно авторизованих сесій
        score=score,
        trust_level=trust_level,
        reason=reason,  # Свіжий статичний ключ, який Jinja2 100% перекладе
        user=user_data,
    )


@app.route("/resources")
def resource_page():
    """Головний екран об'єктів інфраструктури з гранульованими картками"""
    if "user" not in session:
        return redirect(url_for("login"))

    # ДИНАМІЧНИЙ ПЕРЕРАХУНОК: Перевіряємо актуальний контекст безпеки сесії
    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        session.get("device"),
        session.get("network"),
        session.get("vpn", "no"),
    )

    user_data = {"username": session["user"], "role": session.get("role")}

    return render_template(
        "resource_page.html",
        user=user_data,
        score=score,
        trust_level=trust_level,
        permissions=permissions,  # Актуальна матриця карток для фронтенду
    )


@app.route("/set_language/<lang_code>")
def set_language(lang_code):
    if lang_code in ["uk", "en"]:
        session["lang"] = lang_code

    if session.get("role") == "guest" and session.get("network") != "school":
        # Якщо гість заблокований, динамічно перераховуємо скоринг перед рендером помилки блокування
        status, score, trust_level, reason, permissions = evaluate_access(
            session.get("role"),
            session.get("device"),
            session.get("network"),
            session.get("vpn", "no"),
        )

        user_data = {
            "username": session.get("user"),
            "role": session.get("role"),
            "device": session.get("device"),
            "network": session.get("network"),
            "vpn": session.get("vpn"),
        }
        return render_template(
            "denied.html",
            decision="DENY",
            score=score,
            trust_level=trust_level,
            reason=reason,
            user=user_data,
        )

    # Для всіх інших стандартних випадків повертаємося на попередню сторінку
    return redirect(request.referrer or url_for("index"))


@app.route("/admin/dashboard")
def admin_dashboard():
    """Екран моніторингу безпеки (SIEM) для адміністратора"""
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    log_file_path = "logs/access_logs.json"
    logs = []
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
                logs = logs[::-1]  # Найновіші події зверху
        except Exception:
            pass

    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template("admin_dashboard.html", user=user_data, logs=logs)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/api/logs")
def api_logs():
    """Ендпоінт для SIEM моніторингу адміністратора"""
    if "user" not in session or session.get("role") != "admin":
        return json.dumps([]), 403

    log_file_path = "logs/access_logs.json"
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
                return json.dumps(logs[::-1]), 200, {"Content-Type": "application/json"}
        except Exception:
            pass
    return json.dumps([]), 200, {"Content-Type": "application/json"}


# Роути для сторінок-заглушок (Notice Pages)
@app.route("/resources/teacher")
def notice_teacher():
    if "user" not in session:
        return redirect(url_for("login"))
    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template("notice_teacher.html", user=user_data)


@app.route("/resources/student")
def notice_student():
    if "user" not in session:
        return redirect(url_for("login"))
    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template("notice_student.html", user=user_data)


@app.route("/resources/guest")
def notice_guest():
    if "user" not in session:
        return redirect(url_for("login"))
    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template("notice_guest.html", user=user_data)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
