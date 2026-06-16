# app.py
import os
import json
import ipaddress
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix
from config import Config
from database import init_db
from authenticate import authenticate_user, verify_totp
from policies import evaluate_access
from logging_utils import log_event
from translations import TRANSLATIONS

app = Flask(__name__)
app.jinja_env.filters["uppercase"] = lambda s: s.upper() if s else ""
app.config.from_object(Config)

# Налаштування довіри до зворотного проксі Nginx у Google Cloud
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def detect_device_from_cert(req):
    """Визначає пристрій: managed = наявність валідного mTLS сертифіката."""
    cert_status = req.headers.get("X-Client-Verified", "NONE")
    cert_dn = req.headers.get("X-Client-DN", "")
    if cert_status == "SUCCESS" and "laptop-managed" in cert_dn:
        return "managed"
    return "unmanaged"


def detect_vpn_from_ip(client_ip):
    """Автоматично визначає VPN підключення за IP адресою клієнта (підмережа OpenVPN/WireGuard)."""
    try:
        # Обробляємо випадок, коли проксі передає декілька IP через кому
        ip_string = client_ip.split(",")[0].strip()
        ip = ipaddress.ip_address(ip_string)
        vpn_network = ipaddress.ip_network("10.8.0.0/24")
        return ip in vpn_network
    except ValueError:
        return False


@app.context_processor
def inject_translations():
    lang = session.get("lang", "uk")
    return dict(lang=lang, t=TRANSLATIONS.get(lang, TRANSLATIONS["uk"]))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # Визначаємо інфраструктурний статус пристрою за сертифікатом
    device_status = detect_device_from_cert(request)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        otp_code = request.form.get("otp_code", "").strip()
        network = request.form.get("network")

        # Автоматичне визначення VPN за IP + резервний зчитувач форми
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        vpn_auto = "yes" if detect_vpn_from_ip(client_ip) else "no"
        vpn_form = request.form.get("vpn", "no")
        vpn = vpn_auto if vpn_auto == "yes" else vpn_form

        # 1. Первинна автентифікація по паролю
        user = authenticate_user(username, password)

        if user:
            try:
                # 2. Сувора перевірка другого фактора (MFA)
                if not verify_totp(username, otp_code):
                    lang = session.get("lang", "uk")
                    return render_template(
                        "login.html",
                        device_status=device_status,
                        error="Невірний MFA код.",
                    )

                # =============================================================
                # СУВОРЕ БЕЗПЕКОВЕ ПРАВИЛО БЕКЕНДУ: Заборона VPN для ролі студент
                # =============================================================
                if user["role"] == "student":
                    vpn = "no"

                # 3. Виклик PDP-рушія Zero Trust (device визначається виключно хмарою)
                status, score, trust_level, reason, permissions = evaluate_access(
                    user["role"], device_status, network, vpn
                )

                # Записуємо контекстні метрики у сесію
                session["user"] = user["username"]
                session["role"] = user["role"]
                session["device"] = device_status
                session["network"] = network
                session["vpn"] = vpn

                # ПЕРЕВІРКА ПЕРИМЕТРА БЕЗПЕКИ (Якщо повернуто DENY)
                if status == "DENY":
                    log_event(
                        username,
                        user["role"],
                        device_status,
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
                    return render_template(
                        "denied.html",
                        decision="DENY",
                        score=score,
                        trust_level=trust_level,
                        reason=reason,
                        user=user_data,
                    )

                # Успішний вхід (ACCESS_GRANTED)
                log_event(
                    username,
                    user["role"],
                    device_status,
                    network,
                    vpn,
                    "ALLOW",
                    score,
                    reason,
                )
                return redirect(url_for("decision_page"))

            except Exception as e:
                print(f"[SERVER ERROR] Помилка обробки політики доступу: {e}")
                return render_template(
                    "login.html",
                    device_status=device_status,
                    error="Внутрішня помилка PDP сервера.",
                )
        else:
            lang = session.get("lang", "uk")
            return render_template(
                "login.html",
                device_status=device_status,
                error=TRANSLATIONS[lang]["login_error"],
            )

    return render_template("login.html", device_status=device_status)


@app.route("/decision")
def decision_page():
    if "user" not in session:
        return redirect(url_for("login"))

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
        decision="ALLOW",
        score=score,
        trust_level=trust_level,
        reason=reason,
        user=user_data,
    )


@app.route("/resources")
def resource_page():
    if "user" not in session:
        return redirect(url_for("login"))

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
        permissions=permissions,
    )


@app.route("/set_language/<lang_code>")
def set_language(lang_code):
    if lang_code in ["uk", "en"]:
        session["lang"] = lang_code

    if session.get("role") == "guest" and session.get("network") != "school":
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

    return redirect(request.referrer or url_for("index"))


@app.route("/admin/dashboard")
def admin_dashboard():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    log_file_path = "logs/access_logs.json"
    logs = []
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
                logs = logs[::-1]
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
