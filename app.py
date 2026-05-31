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

        user = authenticate_user(username, password)

        if user:
            decision, score, reason = evaluate_access(user["role"], device, network)
            log_event(username, user["role"], device, network, decision, score, reason)

            session["user"] = user["username"]
            session["role"] = user["role"]
            session["device"] = device
            session["network"] = network
            session["access_level"] = decision
            session["trust_score"] = score
            session["reason"] = reason

            return redirect(url_for("decision_page"))
        else:
            lang = session.get("lang", "uk")
            return render_template(
                "login.html", error=TRANSLATIONS[lang]["login_error"]
            )

    return render_template("login.html")


@app.route("/decision")
def decision_page():
    if "user" not in session or "access_level" not in session:
        return redirect(url_for("login"))

    raw_reason = session.get("reason", "")
    lang = session.get("lang", "uk")

    translated_reason = raw_reason
    if lang == "uk" and raw_reason in TRANSLATIONS["uk"]["reasons"]:
        translated_reason = TRANSLATIONS["uk"]["reasons"][raw_reason]

    return render_template(
        "denied.html",
        decision=session.get("access_level"),
        score=session.get("trust_score", 0),
        reason=translated_reason,
    )


@app.route("/set_language/<lang_code>")
def set_language(lang_code):
    if lang_code in ["uk", "en"]:
        session["lang"] = lang_code
    return redirect(request.referrer or url_for("index"))


# --- НОВИЙ МАРШРУТ ДЛЯ КАРТИ РЕСУРСІВ ДЛЯ ВСІХ РОЛЕЙ ---
@app.route("/resources")
def resource_page():
    """Головний екран об'єктів інфраструктури для всіх авторизованих користувачів"""
    if "user" not in session:
        return redirect(url_for("login"))

    # Дозволяємо вхід усім, у кого вердикт ALLOW або LIMITED
    if session.get("access_level") not in ["ALLOW", "LIMITED"]:
        user_data = {"username": session.get("user"), "role": session.get("role")}
        return render_template(
            "denied.html",
            decision="DENY",
            score=session.get("trust_score"),
            reason=session.get("reason"),
            user=user_data,
        )

    user_role = session.get("role")
    access_level = session.get("access_level")
    score = session.get("trust_score")
    user_data = {"username": session["user"], "role": user_role}

    return render_template(
        "resource_page.html", user=user_data, access_level=access_level, score=score
    )


# --- ЗАКРИТИЙ МАРШРУТ СУТО ДЛЯ SIEM-ПАНЕЛІ АДМІНІСТРАТОРА ---
@app.route("/admin/dashboard")
def admin_dashboard():
    """Фінальна сторінка суто для адміністратора — SIEM консоль"""
    if (
        "user" not in session
        or session.get("role") != "admin"
        or session.get("access_level") != "ALLOW"
    ):
        user_data = {"username": session.get("user"), "role": session.get("role")}

        reason_text = "Доступ до консолі SIEM дозволено виключно адміністраторам із повним рівнем довіри (ALLOW)."
        if session.get("lang") == "en":
            reason_text = "Access to the SIEM console is restricted to administrators with full trust level (ALLOW)."

        return render_template(
            "denied.html",
            decision="DENY",
            score=session.get("trust_score", 0),
            reason=reason_text,
            user=user_data,
        )

    logs_data = []
    log_file_path = "logs/access_logs.json"
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as f:
                logs_data = json.load(f)
                logs_data.reverse()
        except Exception:
            logs_data = []

    user_data = {"username": session["user"], "role": session["role"]}
    score = session.get("trust_score")

    return render_template(
        "admin_dashboard.html", user=user_data, score=score, logs=logs_data
    )


@app.route("/admin/api/logs")
def admin_api_logs():
    if (
        "user" not in session
        or session.get("role") != "admin"
        or session.get("access_level") != "ALLOW"
    ):
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
    app.run(debug=True, port=5001)
