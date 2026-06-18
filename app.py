import os
import json
import io
import base64
import ipaddress

import pyotp
import qrcode

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from database import init_db
from authenticate import authenticate_user, verify_totp, get_or_create_totp_secret
from policies import evaluate_access
from logging_utils import log_event
from translations import TRANSLATIONS

app = Flask(__name__)
app.jinja_env.filters["uppercase"] = lambda s: s.upper() if s else ""
app.config.from_object(Config)

# Довіряємо заголовкам від Nginx (реальний IP клієнта та протокол) #
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


@app.context_processor
def inject_translations():
    lang = session.get("lang", "uk")
    return dict(lang=lang, t=TRANSLATIONS.get(lang, TRANSLATIONS["uk"]))


# =============================================================================
# АВТОМАТИЧНЕ ВИЗНАЧЕННЯ КОНТЕКСТУ ZERO TRUST (без участі користувача)
# =============================================================================


def detect_device_from_cert(req):
    """
    Managed device = валідний mTLS клієнтський сертифікат, підписаний нашим CA.
    Nginx передає результат верифікації у заголовках X-Client-Verified / X-Client-DN.
    """
    cert_status = req.headers.get("X-Client-Verified", "NONE")
    cert_dn = req.headers.get("X-Client-DN", "")
    if cert_status == "SUCCESS" and "laptop-managed" in cert_dn:
        return "managed"
    return "unmanaged"


VPN_GATEWAY_PUBLIC_IP = "35.195.43.82"


def detect_vpn_from_ip(req):
    """VPN активний, якщо запит прийшов через зовнішній IP нашого WireGuard-гейтвея."""
    client_ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    return client_ip == VPN_GATEWAY_PUBLIC_IP


# =============================================================================
# ОПЦІЙНИЙ MFA (TOTP) — користувач сам вмикає тоглер на сторінці логіну
# =============================================================================


@app.route("/mfa/qrcode/<username>")
def mfa_qrcode(username):
    """
    Генерує QR-код для налаштування MFA у Google Authenticator.
    Викликається асинхронно (fetch) зі сторінки логіну, коли користувач вмикає тоглер MFA.
    """
    secret = get_or_create_totp_secret(username)
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="ZTAC School")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    qr_base64 = base64.b64encode(buf.read()).decode("ascii")

    return jsonify({"qr_base64": qr_base64})


# =============================================================================
# ОСНОВНІ МАРШРУТИ
# =============================================================================


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    device_status = detect_device_from_cert(request)
    vpn_status = "yes" if detect_vpn_from_ip(request) else "no"

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        network = request.form.get("network")  # залишається ручним вибором

        want_mfa = request.form.get("want_mfa", "no")
        otp_code = request.form.get("otp_code", "").strip()

        user = authenticate_user(username, password)

        if user:
            # Опційне MFA: перевіряється тільки якщо увімкнено тоглер
            mfa_verified = False
            if want_mfa == "yes":
                if not verify_totp(username, otp_code):
                    lang = session.get("lang", "uk")
                    return render_template(
                        "login.html",
                        error=TRANSLATIONS[lang]["mfa_error"],
                        device_status=device_status,
                        vpn_status=vpn_status,
                    )
                mfa_verified = True

            try:
                # Первинний виклик рушія політик Zero Trust PDP
                status, score, trust_level, reason, permissions = evaluate_access(
                    user["role"], device_status, network, vpn_status, mfa_verified
                )

                # Записуємо метрики у сесію користувача
                session["user"] = user["username"]
                session["role"] = user["role"]
                session["device"] = device_status
                session["network"] = network
                session["vpn"] = vpn_status
                session["mfa_verified"] = mfa_verified

                # ПЕРЕВІРКА ПЕРИМЕТРА: Якщо рушій політик повернув DENY
                if status == "DENY":
                    log_event(
                        username,
                        user["role"],
                        device_status,
                        network,
                        vpn_status,
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

                # Якщо перевірку пройдено (ACCESS_GRANTED), логуємо ALLOW і йдемо далі
                log_event(
                    username, user["role"], device_status, network, vpn_status, "ALLOW", score, reason
                )
                return redirect(url_for("decision_page"))

            except Exception as e:
                print(f"[SERVER ERROR] Помилка обробки політики доступу: {e}")
                return render_template(
                    "login.html",
                    error=f"Внутрішня помилка PDP сервера. Деталі: {e}",
                    device_status=device_status,
                    vpn_status=vpn_status,
                )
        else:
            lang = session.get("lang", "uk")
            return render_template(
                "login.html",
                error=TRANSLATIONS[lang]["login_error"],
                device_status=device_status,
                vpn_status=vpn_status,
            )

    return render_template("login.html", device_status=device_status, vpn_status=vpn_status)
@app.route("/decision")
def decision_page():
    """Проміжний екран вердикту PDP перед переходом до інфраструктури"""
    if "user" not in session:
        return redirect(url_for("login"))

    # ДИНАМІЧНИЙ ПЕРЕРАХУНОК: пристрій і VPN перевіряються живим запитом (continuous verification),
    # мережа — ручний вибір, MFA — підтверджується одноразово при логіні
    device = detect_device_from_cert(request)
    vpn_status = "yes" if detect_vpn_from_ip(request) else "no"
    session["device"] = device
    session["vpn"] = vpn_status

    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        device,
        session.get("network"),
        vpn_status,
        session.get("mfa_verified", False),
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
    """Головний екран об'єктів інфраструктури з гранульованими картками"""
    if "user" not in session:
        return redirect(url_for("login"))

    device = detect_device_from_cert(request)
    vpn_status = "yes" if detect_vpn_from_ip(request) else "no"
    session["device"] = device
    session["vpn"] = vpn_status

    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        device,
        session.get("network"),
        vpn_status,
        session.get("mfa_verified", False),
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
        device = detect_device_from_cert(request)
        vpn = "yes" if detect_vpn_from_ip(request) else "no"
        session["device"] = device
        session["vpn"] = vpn

        status, score, trust_level, reason, permissions = evaluate_access(
            session.get("role"),
            device,
            session.get("network"),
            vpn,
            session.get("mfa_verified", False),
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
    """Екран моніторингу безпеки (SIEM) для адміністратора"""
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
