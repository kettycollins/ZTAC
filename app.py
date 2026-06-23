##app.py
import os
import json
import io
import base64
import ipaddress

import pyotp
import qrcode

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash

from config import Config
from database import init_db, get_all_users, create_user, get_user_by_id, update_user_password, delete_user_by_id, count_admins
from authenticate import authenticate_user, verify_totp, get_or_create_totp_secret
from policies import evaluate_access
from logging_utils import log_event, log_admin_operation, log_unauthorized_access
from translations import TRANSLATIONS
from password_policy import validate_password

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
# ЗАХИСТ ВІД ВИКОРИСТАННЯ ВИДАЛЕНИХ КОРИСТУВАЧІВ (після видалення акаунта, сесія стає недійсною)
# =============================================================================

# Рядки 52-62
def _is_active_session_user_valid():
    """Перевіряє, чи існує користувач із сесії в БД (захист від використання видалених акаунтів)."""
    if "user" in session:
        all_users = get_all_users()
        user_exists = any(u["username"] == session["user"] for u in all_users)
        if not user_exists:
            session.clear()
            return False
    return True


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
        network = request.form.get("network")

        want_mfa = request.form.get("want_mfa", "no")
        otp_code = request.form.get("otp_code", "").strip()

        user = authenticate_user(username, password)

        if user:
            # Опційне MFA
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
                print(f"[DEBUG] mfa_verified = {mfa_verified} (type: {type(mfa_verified)})")
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
                        permissions=permissions,
                    )

                    user_data = {
                        "username": session.get("user"),
                        "role": session.get("role"),
                        "device": session.get("device"),
                        "network": session.get("network"),
                        "vpn": session.get("vpn"),
                        "mfa": session.get("mfa_verified", False),
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
                    username, 
                    user["role"], 
                    device_status, 
                    network, 
                    vpn_status, 
                    "ALLOW", 
                    score, 
                    reason, 
                    mfa_verified,
                    permissions=permissions,
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
    """Миттєва інвалідація сесії, якщо користувача видалено"""
    if not _is_active_session_user_valid():
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

    if status == "DENY":
        view_decision = "DENY"
    elif trust_level == "Medium Risk":
        view_decision = "LIMITED"
    else:
        view_decision = "ALLOW"

    user_data = {
        "username": session.get("user"),
        "role": session.get("role"),
        "device": session.get("device"),
        "network": session.get("network"),
        "vpn": session.get("vpn"),
        "mfa": session.get("mfa_verified", False),
    }

    return render_template(
        "denied.html",
        decision=view_decision,
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
    """Миттєва інвалідація сесії, якщо користувача видалено"""
    if not _is_active_session_user_valid():
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

    if status == "DENY":
        user_data = {
            "username": session.get("user"),
            "role": session.get("role"),
            "device": session.get("device"),
            "network": session.get("network"),
            "vpn": session.get("vpn"),
            "mfa": session.get("mfa_verified", False),
        }
        return render_template(
            "denied.html",
            decision="DENY",
            score=score,
            trust_level=trust_level,
            reason=reason,
            user=user_data,
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
            "mfa": session.get("mfa_verified", False),
            
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
        log_unauthorized_access(
            username=session.get("user", "anonymous"),
            role=session.get("role", "anonymous"),
            attempted_url="/admin/dashboard",
            required_role="admin",
            device=session.get("device"),
            network=session.get("network"),
            vpn=session.get("vpn"),
            mfa=session.get("mfa_verified", False),
        )
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

ALLOWED_ROLES = ["admin", "teacher", "student", "guest"]


@app.route("/admin/users")
def admin_users():
    """Сторінка управління користувачами: список + форма створення"""
    if "user" not in session or session.get("role") != "admin":
        log_unauthorized_access(
            username=session.get("user", "anonymous"),
            role=session.get("role", "anonymous"),
            attempted_url="/admin/users",
            required_role="admin",
            device=session.get("device"),
            network=session.get("network"),
            vpn=session.get("vpn"),
            mfa=session.get("mfa_verified", False),
        )
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

    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template(
        "admin_users.html",
        user=user_data,
        all_users=get_all_users(),
        sys_config_permission=permissions.get("admin_users", "DENY"),
    )


@app.route("/admin/users/create", methods=["POST"])
def admin_users_create():
    """Обробка форми створення нового користувача"""
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    device = detect_device_from_cert(request)
    vpn_status = "yes" if detect_vpn_from_ip(request) else "no"

    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        device,
        session.get("network"),
        vpn_status,
        session.get("mfa_verified", False),
    )

    lang = session.get("lang", "uk")
    sys_config_permission = permissions.get("admin_users", "DENY")

    # Захист на бекенді: навіть якщо хтось обійде вимкнену кнопку через DevTools,
    # створення дозволено лише при sys_config = FULL (Trust Score >= 80)
    if sys_config_permission != "FULL":
        return render_template(
            "admin_users.html",
            user={"username": session.get("user"), "role": session.get("role")},
            all_users=get_all_users(),
            sys_config_permission=sys_config_permission,
            error=TRANSLATIONS[lang]["admin_users_error_low_trust"],
        )

    new_username = request.form.get("new_username", "").strip()
    new_password = request.form.get("new_password", "")
    new_role = request.form.get("new_role", "")

    error = None
    success = None

    if not new_username or not new_password or new_role not in ALLOWED_ROLES:
        error = TRANSLATIONS[lang]["admin_users_error_invalid"]
    else:
        is_valid, reason_key = validate_password(new_password, new_username)
        if not is_valid:
            error = TRANSLATIONS[lang][reason_key]
        else:
            try:
                hashed_password = generate_password_hash(new_password)
                create_user(new_username, hashed_password, new_role)
                success = TRANSLATIONS[lang]["admin_users_success"]
                log_admin_operation(
                    admin_username=session.get("user"),
                    operation="create_user",
                    target_username=new_username,
                    target_role=new_role,
                    success=True,
                    device=session.get("device"),
                    network=session.get("network"),
                    vpn=session.get("vpn"),
                    mfa=session.get("mfa_verified", False),
                )
            except Exception:
                error = TRANSLATIONS[lang]["admin_users_error_duplicate"]

    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template(
        "admin_users.html",
        user=user_data,
        all_users=get_all_users(),
        sys_config_permission=sys_config_permission,
        error=error,
        success=success,
    )


@app.route("/admin/users/change-password", methods=["POST"])
def admin_users_change_password():
    """Зміна пароля існуючого користувача"""
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    device = detect_device_from_cert(request)
    vpn_status = "yes" if detect_vpn_from_ip(request) else "no"
    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        device,
        session.get("network"),
        vpn_status,
        session.get("mfa_verified", False),
    )
    lang = session.get("lang", "uk")
    sys_config_permission = permissions.get("admin_users", "DENY")

    if sys_config_permission != "FULL":
        return render_template(
            "admin_users.html",
            user={"username": session.get("user"), "role": session.get("role")},
            all_users=get_all_users(),
            sys_config_permission=sys_config_permission,
            error=TRANSLATIONS[lang]["admin_users_error_low_trust"],
        )

    target_id = request.form.get("user_id")
    new_password = request.form.get("change_password", "")
    target_user = get_user_by_id(target_id) if target_id else None

    error = None
    success = None

    if not target_user:
        error = TRANSLATIONS[lang]["admin_users_error_not_found"]
    else:
        is_valid, reason_key = validate_password(new_password, target_user["username"])
        if not is_valid:
            error = TRANSLATIONS[lang][reason_key]
        else:
            hashed = generate_password_hash(new_password)
            update_user_password(target_id, hashed)
            success = TRANSLATIONS[lang]["admin_users_password_changed"]
            log_admin_operation(
                admin_username=session.get("user"),
                operation="change_password",
                target_username=target_user["username"],
                target_role=target_user["role"],
                success=True,
                device=session.get("device"),
                network=session.get("network"),
                vpn=session.get("vpn"),
                mfa=session.get("mfa_verified", False),
            )

    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template(
        "admin_users.html",
        user=user_data,
        all_users=get_all_users(),
        sys_config_permission=sys_config_permission,
        error=error,
        success=success,
    )


@app.route("/admin/users/delete", methods=["POST"])
def admin_users_delete():
    """Видалення користувача"""
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    device = detect_device_from_cert(request)
    vpn_status = "yes" if detect_vpn_from_ip(request) else "no"
    status, score, trust_level, reason, permissions = evaluate_access(
        session.get("role"),
        device,
        session.get("network"),
        vpn_status,
        session.get("mfa_verified", False),
    )
    lang = session.get("lang", "uk")
    sys_config_permission = permissions.get("admin_users", "DENY")

    if sys_config_permission != "FULL":
        return render_template(
            "admin_users.html",
            user={"username": session.get("user"), "role": session.get("role")},
            all_users=get_all_users(),
            sys_config_permission=sys_config_permission,
            error=TRANSLATIONS[lang]["admin_users_error_low_trust"],
        )

    target_id = request.form.get("user_id")
    target_user = get_user_by_id(target_id) if target_id else None

    error = None
    success = None

    if not target_user:
        error = TRANSLATIONS[lang]["admin_users_error_not_found"]
    elif target_user["username"] == session.get("user"):
        error = TRANSLATIONS[lang]["admin_users_error_self_delete"]
    elif target_user["role"] == "admin" and count_admins() <= 1:
        error = TRANSLATIONS[lang]["admin_users_error_last_admin"]
    else:
        delete_user_by_id(target_id)
        success = TRANSLATIONS[lang]["admin_users_user_deleted"]
        log_admin_operation(
            admin_username=session.get("user"),
            operation="delete_user",
            target_username=target_user["username"],
            target_role=target_user["role"],
            success=True,
            device=session.get("device"),
            network=session.get("network"),
            vpn=session.get("vpn"),
            mfa=session.get("mfa_verified", False),
        )

    user_data = {"username": session.get("user"), "role": session.get("role")}
    return render_template(
        "admin_users.html",
        user=user_data,
        all_users=get_all_users(),
        sys_config_permission=sys_config_permission,
        error=error,
        success=success,
    )


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
