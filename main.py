# Description: Main FastAPI application server, REST API endpoints, and background SMTP server lifecycle.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

import base64
import contextlib
import json
import logging
import os
import sys
from typing import Optional

# Increase max integer digits for 32768-bit RSA keys
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from cryptomail.database import Base, SessionLocal, engine, get_db
from cryptomail.models.message import Message
from cryptomail.models.user import User
from crypto.ecp import (
    export_ecp_private_key_pem,
    export_ecp_public_key_pem,
    generate_ecp_keypair,
    issue_self_signed_certificate,
    load_ecp_private_key_pem,
    load_ecp_public_key_pem,
    sign_message,
    verify_certificate,
    verify_message_signature,
)
from crypto.kuznyechik import Kuznyechik
from crypto.rsa import (
    export_private_key_pem,
    export_public_key_pem,
    generate_rsa_keypair,
    get_or_create_rsa_keypair,
    load_private_key_pem,
    load_public_key_pem,
    rsa_decrypt_hybrid,
    rsa_encrypt_hybrid,
)
from crypto.streebog import hmac_streebog512, streebog256, streebog512
from cryptomail.services.auth_service import (
    PENDING_3FA_SESSIONS,
    complete_password_reset,
    get_totp_token,
    initiate_password_reset,
    register_user,
    seed_default_users,
    start_3fa_login,
    validate_registration_inputs,
    verify_3fa_factor2,
    verify_3fa_factor3,
)
from cryptomail.services.export_service import (
    collect_admin_messages_data,
    collect_user_messages_data,
    export_to_json_bytes,
    export_to_pdf_bytes,
    generate_signed_message_pdf,
)
from cryptomail.services.mail_server import RECEIVED_EMAILS, clear_received_emails, smtp_server
from cryptomail.services.message_service import decrypt_message_content, send_message
from cryptomail.services.crypto_task_service import (
    clear_cached_decrypted_message,
    get_cached_decrypted_message,
    get_task,
    get_user_tasks,
    set_cached_decrypted_message,
    start_decryption_task,
    start_encryption_task,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cryptomail")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Startup: Create tables and seed default users
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_default_users(db)
    finally:
        db.close()

    # 2. Start local SMTP server for 3FA email delivery
    await smtp_server.start()
    logger.info("Application startup completed.")

    yield

    # 3. Shutdown: Stop local SMTP server
    await smtp_server.stop()
    logger.info("Application shutdown completed.")


app = FastAPI(title="CryptoMail", lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=os.environ.get("SESSION_SECRET", "cryptomail-gost-secret-session-key-2026"))

# Paths resolution
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "cryptomail", "templates")
STYLE_DIR = os.path.join(TEMPLATES_DIR, "style")

# Mount Material 3 Expressive Stylesheet & Theme Script
if os.path.exists(STYLE_DIR):
    app.mount("/templates/style", StaticFiles(directory=STYLE_DIR), name="templates_style")
    app.mount("/style", StaticFiles(directory=STYLE_DIR), name="style")
    app.mount("/cryptomail/style", StaticFiles(directory=STYLE_DIR), name="cryptomail_style")

templates = Jinja2Templates(directory=TEMPLATES_DIR)


# --- Static Fallbacks & Utilities ---
@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/main.css", include_in_schema=False)
def main_css():
    css_path = os.path.join(STYLE_DIR, "material3.css")
    if os.path.exists(css_path):
        return FileResponse(css_path, media_type="text/css")
    return Response(status_code=404)


@app.get("/app.js", include_in_schema=False)
def app_js():
    js_path = os.path.join(STYLE_DIR, "crypto_tracker.js")
    if os.path.exists(js_path):
        return FileResponse(js_path, media_type="application/javascript")
    return Response(status_code=404)


# --- Route Aliases for Legacy & Common URLs ---
@app.get("/inbox", include_in_schema=False)
def inbox_redirect():
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@app.get("/outbox", include_in_schema=False)
def outbox_redirect():
    return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)


@app.get("/compose", include_in_schema=False)
def compose_redirect():
    return RedirectResponse(url="/messages/compose", status_code=status.HTTP_302_FOUND)


@app.get("/message/{message_id}", include_in_schema=False)
def message_alias_redirect(message_id: int):
    return RedirectResponse(url=f"/messages/{message_id}", status_code=status.HTTP_302_FOUND)


@app.get("/keys", include_in_schema=False)
def keys_redirect():
    return RedirectResponse(url="/ecp", status_code=status.HTTP_302_FOUND)


@app.get("/forgot-password", include_in_schema=False)
def forgot_password_redirect():
    return RedirectResponse(url="/recover-password", status_code=status.HTTP_302_FOUND)



# --- Auth Dependency ---
def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def require_auth(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    user = require_auth(request, db)
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Требуются права Администратора.")
    return user


# =========================================================================
# HTML User & Navigation Routes
# =========================================================================

@app.get("/", response_class=HTMLResponse)
def index_view(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login")

    received = db.query(Message).filter(Message.recipient_id == user.id).order_by(Message.created_at.desc()).all()
    sent = db.query(Message).filter(Message.sender_id == user.id).order_by(Message.created_at.desc()).all()

    alert_msg = request.session.pop("alert_message", None)
    alert_type = request.session.pop("alert_type", "info")

    cached_ids = [m.id for m in received if get_cached_decrypted_message(user.id, m.id) is not None]

    return templates.TemplateResponse("index.html", {
        "request": request,
        "user": user,
        "received_messages": received,
        "sent_messages": sent,
        "cached_message_ids": cached_ids,
        "alert_message": alert_msg,
        "alert_type": alert_type,
    })


# --- Registration ---
@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "user": None})


@app.post("/register", response_class=HTMLResponse)
def register_action(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    rsa_key_size: int = Form(4096),
    db: Session = Depends(get_db),
):
    new_user, err = register_user(db, username.strip(), email.strip(), password, rsa_key_size=rsa_key_size)
    if err:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": err,
            "form_username": username,
            "form_email": email,
            "user": None,
        })

    # Show recovery codes and 3FA secrets
    return templates.TemplateResponse("register_success.html", {
        "request": request,
        "new_user": new_user,
        "recovery_codes": new_user.recovery_codes_list,
        "user": None,
    })


# --- 3FA Login Flow ---
@app.get("/login", response_class=HTMLResponse)
def login_factor1_form(request: Request):
    alert_msg = request.session.pop("alert_message", None)
    alert_type = request.session.pop("alert_type", "info")
    return templates.TemplateResponse("login_factor1.html", {
        "request": request,
        "user": None,
        "alert_message": alert_msg,
        "alert_type": alert_type,
    })


@app.post("/login", response_class=HTMLResponse)
def login_factor1_action(
    request: Request,
    login_input: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    session_id, user, err = start_3fa_login(db, login_input.strip(), password)
    if err:
        return templates.TemplateResponse("login_factor1.html", {
            "request": request,
            "error": err,
            "login_input": login_input,
            "user": None,
        })

    request.session["pending_3fa_session"] = session_id
    request.session["pending_user_email"] = user.email
    return RedirectResponse(url="/login/factor2", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login/factor2", response_class=HTMLResponse)
def login_factor2_form(request: Request):
    session_id = request.session.get("pending_3fa_session")
    user_email = request.session.get("pending_user_email", "")
    if not session_id or session_id not in PENDING_3FA_SESSIONS:
        return RedirectResponse(url="/login")

    return templates.TemplateResponse("login_factor2.html", {
        "request": request,
        "session_id": session_id,
        "user_email": user_email,
        "user": None,
    })


@app.post("/login/factor2", response_class=HTMLResponse)
def login_factor2_action(
    request: Request,
    session_id: str = Form(...),
    otp_code: str = Form(...),
):
    valid, err = verify_3fa_factor2(session_id, otp_code)
    if not valid:
        return templates.TemplateResponse("login_factor2.html", {
            "request": request,
            "session_id": session_id,
            "user_email": request.session.get("pending_user_email", ""),
            "error": err,
            "user": None,
        })

    return RedirectResponse(url="/login/factor3", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login/factor3", response_class=HTMLResponse)
def login_factor3_form(request: Request, db: Session = Depends(get_db)):
    session_id = request.session.get("pending_3fa_session")
    if not session_id or session_id not in PENDING_3FA_SESSIONS:
        return RedirectResponse(url="/login")

    sess = PENDING_3FA_SESSIONS[session_id]
    target_user = db.query(User).filter(User.id == sess["user_id"]).first()

    # Pre-calculate demo TOTP & sample recovery code for tester convenience
    demo_totp = get_totp_token(target_user.totp_secret) if target_user and target_user.totp_secret else None
    demo_rec = target_user.recovery_codes_list[0] if target_user and target_user.recovery_codes_list else None

    return templates.TemplateResponse("login_factor3.html", {
        "request": request,
        "session_id": session_id,
        "demo_totp": demo_totp,
        "demo_recovery_code": demo_rec,
        "user": None,
    })


@app.post("/login/factor3", response_class=HTMLResponse)
def login_factor3_action(
    request: Request,
    session_id: str = Form(...),
    code_input: str = Form(...),
    db: Session = Depends(get_db),
):
    user, err = verify_3fa_factor3(db, session_id, code_input)
    if not user:
        sess = PENDING_3FA_SESSIONS.get(session_id)
        target_user = db.query(User).filter(User.id == sess["user_id"]).first() if sess else None
        demo_totp = get_totp_token(target_user.totp_secret) if target_user and target_user.totp_secret else None
        demo_rec = target_user.recovery_codes_list[0] if target_user and target_user.recovery_codes_list else None

        return templates.TemplateResponse("login_factor3.html", {
            "request": request,
            "session_id": session_id,
            "error": err,
            "demo_totp": demo_totp,
            "demo_recovery_code": demo_rec,
            "user": None,
        })

    # Clear pending 3FA session and set authenticated user session
    request.session.pop("pending_3fa_session", None)
    request.session.pop("pending_user_email", None)
    request.session["user_id"] = user.id
    request.session["role"] = user.role

    request.session["alert_message"] = f"Успешный вход! Вы авторизованы под рангом: {user.role_title_ru}."
    request.session["alert_type"] = "success"
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login")


# --- Password Recovery Form & Code Dispatch ---
@app.get("/recover-password", response_class=HTMLResponse)
def recover_password_form(request: Request):
    return templates.TemplateResponse("recover_password.html", {"request": request, "user": None})


@app.post("/recover-password/send-code")
def send_recovery_code_action(
    request: Request,
    email_or_username: str = Form(...),
    db: Session = Depends(get_db),
):
    ident = email_or_username.strip()
    sess_id, err = initiate_password_reset(db, ident)
    if sess_id:
        request.session["reset_session"] = sess_id
        return templates.TemplateResponse("recover_password.html", {
            "request": request,
            "success_message": "Одноразовый код для сброса пароля успешно отправлен на почту! Проверьте MailTrap или ваш email.",
            "email_or_username": ident,
            "user": None,
        })
    else:
        return templates.TemplateResponse("recover_password.html", {
            "request": request,
            "error": err or "Пользователь не найден.",
            "email_or_username": ident,
            "user": None,
        })


@app.post("/recover-password", response_class=HTMLResponse)
def recover_password_action(
    request: Request,
    email_or_username: str = Form(...),
    verification_code: str = Form(...),
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    reset_session = request.session.get("reset_session")
    ok, err = complete_password_reset(db, reset_session, email_or_username, verification_code, new_password)
    if not ok:
        return templates.TemplateResponse("recover_password.html", {
            "request": request,
            "error": err,
            "email_or_username": email_or_username,
            "user": None,
        })

    request.session.pop("reset_session", None)
    return templates.TemplateResponse("recover_password.html", {
        "request": request,
        "success_message": "Пароль успешно обновлен (хэш ГОСТ Стрибог-512)! Теперь вы можете войти с новым паролем.",
        "user": None,
    })


# --- MailTrap (Embedded SMTP Inspector) ---
@app.get("/mailtrap", response_class=HTMLResponse)
def mailtrap_view(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    return templates.TemplateResponse("mailtrap.html", {
        "request": request,
        "user": user,
        "emails": RECEIVED_EMAILS,
    })


@app.get("/api/mailtrap/messages")
def api_mailtrap_messages(admin: User = Depends(require_admin)):
    """Returns received emails — restricted to administrators only."""
    return JSONResponse(RECEIVED_EMAILS)


@app.post("/mailtrap/clear")
def mailtrap_clear(request: Request):
    clear_received_emails()
    return RedirectResponse(url="/mailtrap", status_code=status.HTTP_303_SEE_OTHER)


# --- Messages: Compose & View ---
@app.get("/messages/compose", response_class=HTMLResponse)
def compose_view(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)

    potential_recipients = db.query(User).filter(User.id != user.id).all()
    for r in potential_recipients:
        bits = 2048
        if r.rsa_public_key:
            try:
                bits = load_public_key_pem(r.rsa_public_key).key_size
            except Exception:
                pass
        r.rsa_key_bits = bits

    return templates.TemplateResponse("compose.html", {
        "request": request,
        "user": user,
        "potential_recipients": potential_recipients,
    })


@app.post("/messages/compose", response_class=HTMLResponse)
def compose_action(
    request: Request,
    recipient_id: int = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    encryption_type: str = Form(...),
    kuz_passphrase: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = require_auth(request, db)
    msg, err = send_message(db, user, recipient_id, subject.strip(), body.strip(), encryption_type, kuz_passphrase=kuz_passphrase)
    if err:
        potential_recipients = db.query(User).filter(User.id != user.id).all()
        for r in potential_recipients:
            bits = 2048
            if r.rsa_public_key:
                try:
                    bits = load_public_key_pem(r.rsa_public_key).key_size
                except Exception:
                    pass
            r.rsa_key_bits = bits
        return templates.TemplateResponse("compose.html", {
            "request": request,
            "user": user,
            "potential_recipients": potential_recipients,
            "error": err,
        })

    request.session["alert_message"] = f"Сообщение успешно подписано ЭЦП и зашифровано алгоритмом {msg.encryption_type}!"
    request.session["alert_type"] = "success"
    return RedirectResponse(url=f"/messages/{msg.id}", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/messages/{message_id}", response_class=HTMLResponse)
def message_detail_view(message_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Сообщение не найдено.")

    # Permissions check
    if user.role != "admin" and user.id not in (msg.sender_id, msg.recipient_id):
        raise HTTPException(status_code=403, detail="Доступ запрещен.")

    sender = db.query(User).filter(User.id == msg.sender_id).first()
    recipient = db.query(User).filter(User.id == msg.recipient_id).first()

    # Check if message is already in memory cache
    force = request.query_params.get("force") == "1"
    cached = None if force else get_cached_decrypted_message(user.id, message_id)

    if cached:
        is_decrypted = True
        is_from_cache = True
        decrypted_text = cached["decrypted_content"]
        is_sig_valid = cached["is_sig_valid"]
        sig_status = cached["sig_status"]
    else:
        is_decrypted = False
        is_from_cache = False
        decrypted_text = ""
        is_sig_valid = False
        sig_status = "Сообщение зашифровано. Запуск автоматического дешифрования..."

    return templates.TemplateResponse("message_view.html", {
        "request": request,
        "user": user,
        "message": msg,
        "sender": sender,
        "recipient": recipient,
        "is_decrypted": is_decrypted,
        "is_from_cache": is_from_cache,
        "decrypted_content": decrypted_text,
        "is_sig_valid": is_sig_valid,
        "sig_status": sig_status,
    })


# --- ECP & Cryptographic Keys Management ---
@app.get("/ecp", response_class=HTMLResponse)
def ecp_view(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    cert_dict = None
    if user.ecp_certificate:
        try:
            cert_dict = json.loads(user.ecp_certificate)
        except Exception:
            pass

    rsa_key_size = 2048
    if user.rsa_public_key:
        try:
            rsa_key_size = load_public_key_pem(user.rsa_public_key).key_size
        except Exception:
            pass

    return templates.TemplateResponse("ecp.html", {
        "request": request,
        "user": user,
        "cert_dict": cert_dict,
        "rsa_key_size": rsa_key_size,
    })


@app.post("/ecp/reissue")
def ecp_reissue_action(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    priv, pub = generate_ecp_keypair()
    cert = issue_self_signed_certificate(user.username, user.id, priv, pub)
    user.ecp_public_key = export_ecp_public_key_pem(pub)
    user.ecp_private_key = export_ecp_private_key_pem(priv)
    user.ecp_certificate = json.dumps(cert)
    db.commit()

    request.session["alert_message"] = "Сертификат и ключевая пара ЭЦП успешно перевыпущены!"
    request.session["alert_type"] = "success"
    return RedirectResponse(url="/ecp", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/ecp/rsa/reissue")
def rsa_reissue_action(
    request: Request,
    key_size: int = Form(4096),
    db: Session = Depends(get_db),
):
    user = require_auth(request, db)
    priv, pub = get_or_create_rsa_keypair(key_size=key_size)
    user.rsa_public_key = export_public_key_pem(pub)
    user.rsa_private_key = export_private_key_pem(priv)
    db.commit()

    tag = "RSA-32K (32768 бит)" if key_size >= 32768 else f"RSA-{key_size} бит"
    request.session["alert_message"] = f"Ключевая пара {tag} успешно сгенерирована и сохранена!"
    request.session["alert_type"] = "success"
    return RedirectResponse(url="/ecp", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/ecp/rsa/download/public")
def download_rsa_public(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    if not user.rsa_public_key:
        raise HTTPException(status_code=404, detail="Открытый ключ RSA отсутствует")
    return Response(
        content=user.rsa_public_key,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="rsa_{user.username}_public.pem"'},
    )


@app.get("/ecp/rsa/download/private")
def download_rsa_private(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    if not user.rsa_private_key:
        raise HTTPException(status_code=404, detail="Закрытый ключ RSA отсутствует")
    return Response(
        content=user.rsa_private_key,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="rsa_{user.username}_private.pem"'},
    )


@app.get("/ecp/download/public")
def download_ecp_public(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    if not user.ecp_public_key:
        raise HTTPException(status_code=404, detail="Открытый ключ ЭЦП отсутствует")
    return Response(
        content=user.ecp_public_key,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="ecp_{user.username}_public.pem"'},
    )


@app.get("/ecp/download/cert")
def download_ecp_cert(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    if not user.ecp_certificate:
        raise HTTPException(status_code=404, detail="Сертификат ЭЦП отсутствует")
    return Response(
        content=user.ecp_certificate,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="cert_{user.username}.json"'},
    )



# --- Exports ---
@app.get("/export/my/json")
def export_my_messages_json(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    data = collect_user_messages_data(db, user)
    json_bytes = export_to_json_bytes(data, f"Личный архив сообщений пользователя {user.username}")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="messages_{user.username}.json"'},
    )


@app.get("/export/my/pdf")
def export_my_messages_pdf(request: Request, db: Session = Depends(get_db)):
    user = require_auth(request, db)
    data = collect_user_messages_data(db, user)
    pdf_bytes = export_to_pdf_bytes(data, f"Архив сообщений: {user.username} (Расшифрованные + Зашифрованные)", is_user_export=True)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="messages_{user.username}.pdf"'},
    )


@app.get("/messages/{message_id}/export/pdf")
def export_single_message_pdf(message_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Exports a single message to an official PDF containing plaintext, ciphertext,
    and digitally signs the generated PDF with user's ЭЦП (ГОСТ Стрибог-512).
    """
    user = require_auth(request, db)
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Сообщение не найдено.")
    if user.role != "admin" and user.id not in (msg.sender_id, msg.recipient_id):
        raise HTTPException(status_code=403, detail="Доступ запрещен.")

    pdf_bytes, sig_b64, meta = generate_signed_message_pdf(db, msg, user)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="message_{msg.id}_signed_ecp.pdf"',
            "X-CryptoMail-ECP-Signature": sig_b64,
        },
    )


@app.get("/messages/{message_id}/export/sig")
def export_single_message_sig(message_id: int, request: Request, db: Session = Depends(get_db)):
    """
    Exports detached digital signature (.sig JSON) for the generated PDF.
    """
    user = require_auth(request, db)
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Сообщение не найдено.")
    if user.role != "admin" and user.id not in (msg.sender_id, msg.recipient_id):
        raise HTTPException(status_code=403, detail="Доступ запрещен.")

    pdf_bytes, sig_b64, meta = generate_signed_message_pdf(db, msg, user)
    sig_payload = json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8")
    return Response(
        content=sig_payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="message_{msg.id}_signature.sig"'},
    )


# --- Admin Panel & Admin Exports ---
@app.get("/admin", response_class=HTMLResponse)
def admin_panel_view(request: Request, db: Session = Depends(get_db)):
    admin_user = require_admin(request, db)
    users = db.query(User).order_by(User.id.asc()).all()

    alert_msg = request.session.pop("alert_message", None)
    alert_type = request.session.pop("alert_type", "info")

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": admin_user,
        "users": users,
        "current_admin_id": admin_user.id,
        "alert_message": alert_msg,
        "alert_type": alert_type,
    })


@app.post("/admin/users/{user_id}/role")
def admin_change_role(user_id: int, request: Request, role: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    target = db.query(User).filter(User.id == user_id).first()
    if target and role in ("user", "admin"):
        target.role = role
        db.commit()
        request.session["alert_message"] = f"Ранг пользователя {target.username} изменен на: {target.role_title_ru}."
        request.session["alert_type"] = "success"
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(user_id: int, request: Request, new_password: str = Form(...), db: Session = Depends(get_db)):
    require_admin(request, db)
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    valid_pwd, err_pwd = validate_registration_inputs("dummy", "dummy@mail.com", new_password)
    if not valid_pwd:
        request.session["alert_message"] = f"Ошибка: {err_pwd}"
        request.session["alert_type"] = "error"
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

    from crypto.streebog import pbkdf2_streebog512
    salt = os.urandom(16)
    dk = pbkdf2_streebog512(new_password, salt, iterations=1000, dklen=64)
    target.password_hash = dk.hex()
    target.salt = salt.hex()
    db.commit()

    request.session["alert_message"] = f"Пароль для пользователя {target.username} успешно обновлен (хэш Стрибог-512)!"
    request.session["alert_type"] = "success"
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    admin_user = require_admin(request, db)
    if user_id == admin_user.id:
        request.session["alert_message"] = "Нельзя удалить собственный аккаунт администратора."
        request.session["alert_type"] = "error"
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

    target = db.query(User).filter(User.id == user_id).first()
    if target:
        # Delete associated messages
        db.query(Message).filter((Message.sender_id == user_id) | (Message.recipient_id == user_id)).delete()
        db.delete(target)
        db.commit()
        request.session["alert_message"] = f"Пользователь {target.username} и его сообщения удалены."
        request.session["alert_type"] = "success"
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/export/json")
def admin_export_all_json(request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    data = collect_admin_messages_data(db, target_user_id=None)
    json_bytes = export_to_json_bytes(data, "Полный аудит сообщений системы CryptoMail (Расшифрованный вид)")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="admin_all_messages.json"'},
    )


@app.get("/admin/export/pdf")
def admin_export_all_pdf(request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    data = collect_admin_messages_data(db, target_user_id=None)
    pdf_bytes = export_to_pdf_bytes(data, "Полный аудит сообщений системы CryptoMail (Расшифрованный вид)")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="admin_all_messages.pdf"'},
    )


@app.get("/admin/users/{user_id}/export/json")
def admin_export_user_json(user_id: int, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    target = db.query(User).filter(User.id == user_id).first()
    uname = target.username if target else f"user_{user_id}"
    data = collect_admin_messages_data(db, target_user_id=user_id)
    json_bytes = export_to_json_bytes(data, f"Сообщения пользователя {uname} (Расшифрованный вид)")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="admin_user_{uname}_messages.json"'},
    )


@app.get("/admin/users/{user_id}/export/pdf")
def admin_export_user_pdf(user_id: int, request: Request, db: Session = Depends(get_db)):
    require_admin(request, db)
    target = db.query(User).filter(User.id == user_id).first()
    uname = target.username if target else f"user_{user_id}"
    data = collect_admin_messages_data(db, target_user_id=user_id)
    pdf_bytes = export_to_pdf_bytes(data, f"Отчет по сообщениям пользователя {uname} (Расшифрованный вид)")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="admin_user_{uname}_messages.pdf"'},
    )


# =========================================================================
# Background Live Crypto Task Tracker Endpoints
# =========================================================================

@app.post("/api/crypto/encrypt_task")
async def api_crypto_encrypt_task(
    request: Request,
    recipient_id: int = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    encryption_type: str = Form(...),
    kuz_passphrase: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = require_auth(request, db)
    task_id = start_encryption_task(user.id, recipient_id, subject.strip(), body.strip(), encryption_type, kuz_passphrase=kuz_passphrase)
    return JSONResponse({"ok": True, "task_id": task_id})


@app.post("/api/crypto/decrypt_task/{message_id}")
async def api_crypto_decrypt_task(
    message_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_auth(request, db)
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Сообщение не найдено.")
    if user.role != "admin" and user.id not in (msg.sender_id, msg.recipient_id):
        raise HTTPException(status_code=403, detail="Доступ запрещен.")
    task_id = start_decryption_task(user.id, message_id)
    return JSONResponse({"ok": True, "task_id": task_id})


@app.get("/api/crypto/tasks/{task_id}")
def api_crypto_get_task(
    task_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_auth(request, db)
    task = get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Задача не найдена.")
    if user.role != "admin" and task.get("user_id") != user.id:
        raise HTTPException(status_code=403, detail="Доступ к задаче запрещен.")
    return JSONResponse(task)


@app.get("/api/crypto/tasks/active")
def api_crypto_active_tasks(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_auth(request, db)
    tasks = get_user_tasks(user.id)
    return JSONResponse(tasks)


# =========================================================================
# REST API for External Modules and Command-Line Clients
# =========================================================================

class RSAGenRequest(BaseModel):
    bits: int = 2048


class RSAEncryptRequest(BaseModel):
    public_key_pem: str
    data: str


class RSADecryptRequest(BaseModel):
    private_key_pem: str
    bundle_json: str


class KuznyechikRequest(BaseModel):
    key_hex: str
    data: str
    mode: str = "cbc"


class StreebogRequest(BaseModel):
    data: str
    bits: int = 512
    key: Optional[str] = None


class ECPSignRequest(BaseModel):
    private_key_pem: str
    data: str


class ECPVerifyRequest(BaseModel):
    public_key_pem: str
    data: str
    signature_b64: str


@app.post("/api/v1/crypto/rsa/generate")
def api_rsa_generate(req: RSAGenRequest, _user: User = Depends(require_auth)):
    if req.bits > 32768 or req.bits < 512:
        raise HTTPException(status_code=400, detail="Размер ключа RSA должен быть в диапазоне от 512 до 32768 бит.")
    if req.bits >= 32768:
        priv, pub = get_or_create_rsa_keypair(key_size=req.bits)
    else:
        priv, pub = generate_rsa_keypair(key_size=req.bits)
    return {
        "bits": req.bits,
        "private_key_pem": export_private_key_pem(priv),
        "public_key_pem": export_public_key_pem(pub),
    }


@app.post("/api/v1/crypto/rsa/encrypt")
def api_rsa_encrypt(req: RSAEncryptRequest, _user: User = Depends(require_auth)):
    pub = load_public_key_pem(req.public_key_pem)
    bundle = rsa_encrypt_hybrid(pub, req.data)
    return {"encrypted_bundle": bundle}


@app.post("/api/v1/crypto/rsa/decrypt")
def api_rsa_decrypt(req: RSADecryptRequest, _user: User = Depends(require_auth)):
    priv = load_private_key_pem(req.private_key_pem)
    decrypted = rsa_decrypt_hybrid(priv, req.bundle_json)
    return {"decrypted_data": decrypted.decode("utf-8", errors="replace")}


@app.post("/api/v1/crypto/kuznyechik/encrypt")
def api_kuznyechik_encrypt(req: KuznyechikRequest, _user: User = Depends(require_auth)):
    key = bytes.fromhex(req.key_hex)
    cipher = Kuznyechik(key)
    raw = req.data.encode("utf-8")
    enc = cipher.encrypt_cbc(raw) if req.mode == "cbc" else cipher.encrypt_ctr(raw)
    return {"ciphertext_base64": base64.b64encode(enc).decode("ascii"), "mode": req.mode}


@app.post("/api/v1/crypto/kuznyechik/decrypt")
def api_kuznyechik_decrypt(req: KuznyechikRequest, _user: User = Depends(require_auth)):
    key = bytes.fromhex(req.key_hex)
    cipher = Kuznyechik(key)
    raw = base64.b64decode(req.data)
    dec = cipher.decrypt_cbc(raw) if req.mode == "cbc" else cipher.decrypt_ctr(raw)
    return {"decrypted_data": dec.decode("utf-8", errors="replace"), "mode": req.mode}


@app.post("/api/v1/crypto/streebog/hash")
def api_streebog_hash(req: StreebogRequest, _user: User = Depends(require_auth)):
    raw = req.data.encode("utf-8")
    if req.key:
        tag = hmac_streebog512(req.key.encode("utf-8"), raw)
        return {"hmac_streebog512": tag.hex()}
    if req.bits == 256:
        h = streebog256(raw)
        return {"hash_streebog256": h.hex()}
    h = streebog512(raw)
    return {"hash_streebog512": h.hex()}


@app.post("/api/v1/crypto/ecp/sign")
def api_ecp_sign(req: ECPSignRequest, _user: User = Depends(require_auth)):
    priv = load_ecp_private_key_pem(req.private_key_pem)
    sig = sign_message(priv, req.data)
    return {"signature_b64": sig, "digest_algorithm": "GOST R 34.11-2012 Streebog-512"}


@app.post("/api/v1/crypto/ecp/verify")
def api_ecp_verify(req: ECPVerifyRequest, _user: User = Depends(require_auth)):
    pub = load_ecp_public_key_pem(req.public_key_pem)
    valid = verify_message_signature(pub, req.data, req.signature_b64)
    return {"is_valid": valid}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
