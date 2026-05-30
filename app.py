import os
import json
from flask import Flask, render_template, request, redirect, url_for, session
from config import Config
from database import init_db
from authenticate import authenticate_user
from policies import evaluate_access
from logging_utils import log_event

app = Flask(__name__)
app.jinja_env.filters["uppercase"] = lambda s: s.upper() if s else ""
app.config.from_object(Config)


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

        # 1. АВТЕНТИФІКАЦІЯ через SQLite
        user = authenticate_user(username, password)

        if user:
            # 2. ОБЧИСЛЕННЯ рішення Zero Trust через політики
            decision, score, reason = evaluate_access(user["role"], device, network)

            # 3. ЛОГУВАННЯ події
            log_event(username, user["role"], device, network, decision, score, reason)

            # Записуємо дані в сесію
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["device"] = device
            session["network"] = network
            session["access_level"] = decision
            session["trust_score"] = score
            session["reason"] = reason

            # ЛАНЦЮЖОК: Після логіну ЗАВЖДИ спочатку рендеримо проміжний екран вердикту denied.html
            return render_template(
                "denied.html", decision=decision, score=score, reason=reason
            )
        else:
            log_event(
                username, "UNKNOWN", device, network, "DENY", 0, "Invalid credentials"
            )
            return render_template(
                "login.html", error="Невірне ім'я користувача або пароль."
            )

    return render_template("login.html")


@app.route("/admin/api/logs")
def admin_api_logs():
    """API-ендпоінт для динамічного зчитування JSON-логів безпеки для SIEM консолі"""
    # Захист контексту: доступ тільки для адміністраторів із довіреним статусом ALLOW
    if (
        "user" not in session
        or session.get("role") != "admin"
        or session.get("access_level") != "ALLOW"
    ):
        return json.dumps([]), 403

    # Файл логів, куди ваш logging_utils.py записує JSON-рядки
    log_file_path = "security.log"
    logs = []

    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        # Парсимо кожен рядок як окремий JSON-об'єкт
                        logs.append(json.loads(line.strip()))
        except Exception as e:
            print(f"[ERROR] Помилка зчитування файлу логів: {e}")

    # Повертаємо логи у зворотному порядку (найновіші події зверху)
    return json.dumps(logs[::-1]), 200, {"Content-Type": "application/json"}


@app.route("/dashboard")
def dashboard():  # <-- ТУТ МАЄ БУТИ dashboard ЗАМІСТЬ resource_page
    """Головний екран об'єктів інфраструктури (resource_page.html)"""
    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("access_level") not in ["ALLOW", "LIMITED"]:
        return render_template(
            "denied.html",
            decision="DENY",
            score=session.get("trust_score"),
            reason=session.get("reason"),
        )

    user_role = session.get("role")
    access_level = session.get("access_level")
    score = session.get("trust_score")

    user_data = {"username": session["user"], "role": user_role}

    return render_template(
        "resource_page.html", user=user_data, access_level=access_level, score=score
    )


@app.route("/admin/dashboard")
def admin_dashboard():
    """Фінальна сторінка для адміністратора — SIEM консоль"""
    if (
        "user" not in session
        or session.get("role") != "admin"
        or session.get("access_level") != "ALLOW"
    ):
        return render_template(
            "denied.html",
            decision="DENY",
            score=session.get("trust_score", 0),
            reason="Доступ до консолі SIEM дозволено виключно адміністраторам із повним рівнем довіри (ALLOW).",
        )

    user_data = {"username": session["user"], "role": session["role"]}
    score = session.get("trust_score")
    return render_template("admin_dashboard.html", user=user_data, score=score)


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


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
