# app.py
import os
import json
import ipaddress
import pyotp
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

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


def detect_device_from_cert(req):
    """Managed device = валідний клієнтський сертифікат mTLS від Nginx."""
    cert_status = req.headers.get("X-Client-Verified", "NONE")
    cert_dn = req.headers.get("X-Client-DN", "")
    if cert_status == "SUCCESS" and "laptop-managed" in cert_dn:
        return "managed"
    return "unmanaged"


def detect_vpn_from_ip(client_ip):
    """Автоматично визначає WireGuard VPN підключення за IP адресою клієнта."""
    try:
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
    # Автоматичне зчитування пристрою хмарою через сертифікат
    device_status = detect_device_from_cert(request)

    # Автоматичне зчитування WireGuard VPN за IP клієнта
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    vpn_status = "yes" if detect_vpn_from_ip(client_ip) else "no"

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        otp_code = request.form.get("otp_code", "").strip()
        network = request.form.get("network")

        user = authenticate_user(username, password)

        if user:
            try:
                mfa_verified = False

                # ОПЦІЙНИЙ MFA ФІЛЬТР: Перевіряємо код, тільки якщо користувач його ввів
                if otp_code != "":
                    if verify_totp(username, otp_code):
                        mfa_verified = True
                    else:
                        return render_template(
                            "login.html",
                            device_status=device_status,
                            vpn_status=vpn_status,
                            error="Невірний MFA код.",
                        )

                # Заборона VPN для студентів
                current_vpn = "no" if user["role"] == "student" else vpn_status

                # Виклик PDP рушія з передачею прапора опційного MFA
                status, score, trust_level, reason, permissions = evaluate_access(
                    user["role"], device_status, network, current_vpn, mfa_verified
                )

                session["user"] = user["username"]
                session["role"] = user["role"]
                session["device"] = device_status
                session["network"] = network
                session["vpn"] = current_vpn
                session["mfa_verified"] = mfa_verified

                if status == "DENY":
                    log_event(
                        username,
                        user["role"],
                        device_status,
                        network,
                        current_vpn,
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

                log_event(
                    username,
                    user["role"],
                    device_status,
                    network,
                    current_vpn,
                    "ALLOW",
                    score,
                    reason,
                )
                return redirect(url_for("decision_page"))

            except Exception as e:
                print(f"[SERVER ERROR] Помилка PDP: {e}")
                return render_template(
                    "login.html",
                    device_status=device_status,
                    vpn_status=vpn_status,
                    error="Внутрішня помилка PDP сервера.",
                )
        else:
            lang = session.get("lang", "uk")
            return render_template(
                "login.html",
                device_status=device_status,
                vpn_status=vpn_status,
                error=TRANSLATIONS[lang]["login_error"],
            )

    return render_template(
        "login.html", device_status=device_status, vpn_status=vpn_status
    )


@app.route("/decision")
def decision_page():
    if "user" not in session:
        return redirect(url_for("login"))

    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        session.get("device"),
        session.get("network"),
        session.get("vpn", "no"),
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
    if "user" not in session:
        return redirect(url_for("login"))

    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        session.get("device"),
        session.get("network"),
        session.get("vpn", "no"),
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
    return redirect(request.referrer or url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5001)
