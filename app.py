import os
from flask import Flask, render_template, request, redirect, url_for, session
from config import Config
from database import init_db
from authenticate import authenticate_user
from policies import evaluate_access
from logging_utils import log_event

app = Flask(__name__)
# Додаємо ваш оригінальний фільтр uppercase та конфігурацію
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

        # 1. АВТЕНТИФІКАЦІЯ через ваш оригінальний модуль SQLite
        user = authenticate_user(username, password)

        if user:
            # 2. ОБЧИСЛЕННЯ рішення Zero Trust через ваші існуючі політики
            decision, score, reason = evaluate_access(user["role"], device, network)

            # 3. ЛОГУВАННЯ події через вашу утиліту логів
            log_event(username, user["role"], device, network, decision, score, reason)

            # Записуємо дані в сесію (синхронізовано для використання в шаблонах)
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


@app.route("/dashboard")
def dashboard():
    """
    Головний екран об'єктів інфраструктури (resource_page.html).
    Повернено назву функції 'dashboard', щоб усунути помилки BuildError під час авторизації.
    """
    # Захист від прямого переходу (якщо сесія відсутня)
    if "user" not in session:
        return redirect(url_for("login"))

    # Захист: якщо вердикт системи безпеки був DENY — показуємо екран відмови
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

    # Усі ролі (admin, teacher, student, guest) переходять на спільну карту 2x2
    return render_template(
        "resource_page.html", user=user_data, access_level=access_level, score=score
    )


@app.route("/admin/dashboard")
def admin_dashboard():
    """Фінальна сторінка для адміністратора — SIEM консоль (admin_dashboard.html)"""
    # Додатковий фільтр захисту контексту
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


# =====================================================================
# РОУТИ ДЛЯ АДАПТОВАНИХ СТОРІНОК-ЗАГЛУШОК MVP
# =====================================================================


@app.route("/resources/teacher")
def notice_teacher():
    """Фінальна сторінка-заглушка вчителя (notice_teacher.html)"""
    if "user" not in session:
        return redirect(url_for("login"))
    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template("notice_teacher.html", user=user_data)


@app.route("/resources/student")
def notice_student():
    """Фінальна сторінка-заглушка студента (notice_student.html)"""
    if "user" not in session:
        return redirect(url_for("login"))
    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template("notice_student.html", user=user_data)


@app.route("/resources/guest")
def notice_guest():
    """Фінальна сторінка-заглушка гостя (notice_guest.html)"""
    if "user" not in session:
        return redirect(url_for("login"))
    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template("notice_guest.html", user=user_data)


# =====================================================================


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("[INIT] Створення конфігураційних файлів логів...")
    print("[INIT] Иніціалізація бази даних SQLite...")
    init_db()

    print("[SYSTEM] Запуск Zero Trust веб-сервера...")
    app.run(debug=True, port=5000)
