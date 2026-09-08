# Description: FastAPI web application, routes, session management, RBAC and lifespan initialization.
# Author: Nazaryan Artem @Sl1dee36
# Date: 05/2026.

from contextlib import asynccontextmanager
from datetime import datetime
import json
import logging
import os
import secrets
import sys
from typing import Any, Dict, List, Optional

# Ensure high integer string limit for RSA-32768
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(200000)

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response as RawResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from cryptomail.database import SessionLocal, get_db, init_db
from cryptomail.models.audit import AuditLog
from cryptomail.models.message import Message
from cryptomail.models.user import User
from cryptomail.services.auth_service import (
    PENDING_3FA_SESSIONS,
    complete_password_reset,
    generate_recovery_codes,
    generate_totp_code,
    get_totp_token,
    hash_password,
    initiate_password_reset,
    register_user,
    request_password_reset,
    reset_password_with_email_code,
    reset_password_with_recovery_code,
    start_3fa_login,
    verify_3fa_factor2,
    verify_3fa_factor3,
    verify_password,
)
from cryptomail.services.crypto_task_service import (
    clear_cached_decrypted_message,
    get_cached_decrypted_message,
    get_task,
    get_task_status,
    get_user_tasks,
    set_cached_decrypted_message,
    start_decryption_task,
    start_encryption_task,
)
from cryptomail.services.export_service import (
    export_to_json_bytes,
    export_to_pdf_bytes,
    generate_signed_message_pdf,
)
from cryptomail.services.mail_server import (
    clear_received_emails,
    get_all_received_emails,
    start_mail_server,
    stop_mail_server,
)
from cryptomail.services.message_service import (
    decrypt_message_content,
    send_message,
)

logger = logging.getLogger("cryptomail.app")

# Paths resolution
CRYPTOMAIL_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(CRYPTOMAIL_DIR, "templates")
STYLE_DIR = os.path.join(TEMPLATES_DIR, "style")

# Session management: session_token -> user_id
ACTIVE_SESSIONS: Dict[str, int] = {}
SESSION_COOKIE_NAME = "cryptomail_session"


def seed_default_users(db: Optional[Session] = None):
    """Initializes standard test accounts if not already present."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True
    try:
        # 1. Admin
        if not db.query(User).filter(User.username == "admin").first():
            logger.info("Seeding default admin user...")
            register_user(
                db=db,
                username="admin",
                email="admin@cryptomail.local",
                password="AdminPassword123!",
                role="admin",
                rsa_key_size=4096,
            )

        # 2. Alice
        if not db.query(User).filter(User.username == "alice").first():
            logger.info("Seeding default alice user...")
            register_user(
                db=db,
                username="alice",
                email="alice@cryptomail.local",
                password="AlicePassword123!",
                role="user",
                rsa_key_size=4096,
            )

        # 3. Bob
        if not db.query(User).filter(User.username == "bob").first():
            logger.info("Seeding default bob user...")
            register_user(
                db=db,
                username="bob",
                email="bob@cryptomail.local",
                password="BobPassword123!",
                role="user",
                rsa_key_size=4096,
            )

        # 4. Guest
        if not db.query(User).filter(User.username == "guest").first():
            logger.info("Seeding default guest user...")
            register_user(
                db=db,
                username="guest",
                email="guest@cryptomail.local",
                password="GuestPassword123!",
                role="guest",
                rsa_key_size=2048,
            )

        # Replenish recovery codes if exhausted by test runs
        for u in db.query(User).all():
            if not u.recovery_codes_list:
                u.recovery_codes_list = generate_recovery_codes()
        db.commit()

        # 5. Seed sample welcome message if none exist
        if db.query(Message).count() == 0:
            admin_u = db.query(User).filter(User.username == "admin").first()
            alice_u = db.query(User).filter(User.username == "alice").first()
            if admin_u and alice_u:
                send_message(
                    db=db,
                    sender=admin_u,
                    recipient_id=alice_u.id,
                    subject="Добро пожаловать в CryptoMail!",
                    body="Приветствуем в защищенной почтовой системе CryptoMail.\n"
                         "Это тестовое сообщение зашифровано алгоритмом RSA-4096 и подписано ЭЦП ГОСТ Р 34.10-2012.\n"
                         "Данные на диске защищены прозрачным шифрованием ГОСТ «Кузнечик».",
                    encryption_type="RSA-4096",
                    sign_ecp=True,
                )
    except Exception as e:
        logger.error("Error seeding default users: %s", e)
    finally:
        if close_db:
            db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting CryptoMail initialization...")
    init_db()
    seed_default_users()
    start_mail_server()
    yield
    # Shutdown
    logger.info("Stopping CryptoMail services...")
    stop_mail_server()


app = FastAPI(
    title="CryptoMail",
    description="Secure Mailing Platform with GOST & RSA-32K Cryptography",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "cryptomail-gost-secret-session-key-2026"),
)

# Static and Templates configuration
if os.path.exists(STYLE_DIR):
    app.mount("/templates/style", StaticFiles(directory=STYLE_DIR), name="templates_style")
    app.mount("/style", StaticFiles(directory=STYLE_DIR), name="style")
    app.mount("/cryptomail/style", StaticFiles(directory=STYLE_DIR), name="cryptomail_style")

templates = Jinja2Templates(directory=TEMPLATES_DIR)


# Static Fallbacks & Utilities
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


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Retrieves authenticated user from session cookie or Starlette session."""
    if "session" in request.scope:
        user_id = request.session.get("user_id")
        if user_id:
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                return user
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    user_id = ACTIVE_SESSIONS.get(token)
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


def render(request: Request, template_name: str, context: Dict[str, Any] = None) -> HTMLResponse:
    """Helper to render Jinja2 templates with standard user and flash contexts."""
    ctx = context or {}
    ctx["request"] = request
    user = ctx.get("user") or ctx.get("current_user")
    if not user:
        db = SessionLocal()
        try:
            user = get_current_user(request, db)
        finally:
            db.close()
    ctx["user"] = user
    ctx["current_user"] = user
    return templates.TemplateResponse(template_name, ctx)


# ---------------------------------------------------------------------------
# Public and Auth Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index_route(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user:
        return RedirectResponse(url="/inbox", status_code=status.HTTP_302_FOUND)
    return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)


@app.get("/login", response_class=HTMLResponse)
def login_get(
    request: Request,
    error_msg: Optional[str] = None,
    db: Session = Depends(get_db),
):
    now = int(datetime.utcnow().timestamp())
    period = 30
    remaining = period - (now % period)
    preset_names = ["admin", "alice", "bob"]
    preset_data = []
    for uname in preset_names:
        u = db.query(User).filter(User.username == uname).first()
        if u and u.totp_secret:
            code = generate_totp_code(u.totp_secret, timestamp=now)
            preset_data.append({
                "username": uname,
                "role": u.role,
                "code": code,
                "password": f"{uname.capitalize()}Password123!",
            })
    return render(
        request,
        "login_factor1.html",
        {
            "error": error_msg,
            "error_msg": error_msg,
            "preset_users": preset_data,
            "remaining": remaining,
        },
    )


@app.get("/api/live-totp")
def api_live_totp(db: Session = Depends(get_db)):
    """API endpoint providing real-time live TOTP codes for preset users with remaining period seconds."""
    now = int(datetime.utcnow().timestamp())
    period = 30
    remaining = period - (now % period)
    preset_names = ["admin", "alice", "bob"]
    res = {}
    for uname in preset_names:
        u = db.query(User).filter(User.username == uname).first()
        if u and u.totp_secret:
            code = generate_totp_code(u.totp_secret, timestamp=now)
            res[uname] = {
                "username": uname,
                "role": u.role,
                "code": code,
                "password": f"{uname.capitalize()}Password123!",
            }
    return JSONResponse({"remaining": remaining, "period": period, "users": res})


@app.post("/login")
def login_post(
    request: Request,
    login_input: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    session_id, user, err = start_3fa_login(db, login_input, password)
    if err:
        return render(request, "login_factor1.html", {"error": err, "error_msg": err, "login_input": login_input})

    # If user has guest role, immediately authenticate without 3FA
    if user and user.is_guest:
        token = secrets.token_urlsafe(32)
        ACTIVE_SESSIONS[token] = user.id
        if "session" in request.scope:
            request.session["user_id"] = user.id
            request.session["role"] = user.role
        resp = RedirectResponse(url="/inbox", status_code=status.HTTP_302_FOUND)
        resp.set_cookie(SESSION_COOKIE_NAME, token, httponly=True, max_age=86400)
        return resp

    if "session" in request.scope:
        request.session["pending_3fa_session"] = session_id
        request.session["pending_user_email"] = user.email

    # Advance to Factor 2 (Email OTP)
    return RedirectResponse(
        url=f"/login/step2?session_id={session_id}&email={user.email}",
        status_code=status.HTTP_302_FOUND,
    )


@app.get("/login/guest")
def login_guest(db: Session = Depends(get_db)):
    """One-click login as Guest without credentials (guest has no permissions)."""
    guest_u = db.query(User).filter(User.role == "guest").first()
    if not guest_u:
        register_user(
            db=db,
            username="guest",
            email="guest@cryptomail.local",
            password="GuestPassword123!",
            role="guest",
        )
        guest_u = db.query(User).filter(User.role == "guest").first()

    token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[token] = guest_u.id
    resp = RedirectResponse(url="/inbox", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(SESSION_COOKIE_NAME, token, httponly=True, max_age=86400)
    return resp


@app.get("/login/step2", response_class=HTMLResponse)
@app.get("/login/factor2", response_class=HTMLResponse)
def login_step2_get(
    request: Request,
    session_id: Optional[str] = None,
    email: Optional[str] = "почту",
    error_msg: Optional[str] = None,
):
    if not session_id and "session" in request.scope:
        session_id = request.session.get("pending_3fa_session")
        email = request.session.get("pending_user_email", email)

    return render(
        request,
        "login_factor2.html",
        {
            "session_id": session_id,
            "target_email": email,
            "user_email": email,
            "error": error_msg,
            "error_msg": error_msg,
        },
    )


@app.post("/login/step2")
@app.post("/login/factor2")
def login_step2_post(
    request: Request,
    session_id: str = Form(...),
    otp_code: str = Form(...),
):
    valid, err = verify_3fa_factor2(session_id, otp_code)
    if not valid:
        email = "почту"
        if "session" in request.scope:
            email = request.session.get("pending_user_email", email)
        return render(
            request,
            "login_factor2.html",
            {
                "session_id": session_id,
                "target_email": email,
                "user_email": email,
                "error": err,
                "error_msg": err,
            },
        )
    return RedirectResponse(
        url=f"/login/step3?session_id={session_id}",
        status_code=status.HTTP_302_FOUND,
    )


@app.get("/login/step3", response_class=HTMLResponse)
@app.get("/login/factor3", response_class=HTMLResponse)
def login_step3_get(
    request: Request,
    session_id: Optional[str] = None,
    error_msg: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if not session_id and "session" in request.scope:
        session_id = request.session.get("pending_3fa_session")

    demo_totp = None
    demo_rec = None
    if session_id and session_id in PENDING_3FA_SESSIONS:
        sess = PENDING_3FA_SESSIONS[session_id]
        target_user = db.query(User).filter(User.id == sess["user_id"]).first()
        if target_user:
            if target_user.totp_secret:
                demo_totp = generate_totp_code(target_user.totp_secret)
            if target_user.recovery_codes_list:
                demo_rec = target_user.recovery_codes_list[0]

    return render(
        request,
        "login_factor3.html",
        {
            "session_id": session_id,
            "error": error_msg,
            "error_msg": error_msg,
            "demo_totp": demo_totp,
            "demo_recovery_code": demo_rec,
        },
    )


@app.post("/login/step3")
@app.post("/login/factor3")
def login_step3_post(
    request: Request,
    session_id: str = Form(...),
    code: Optional[str] = Form(None),
    code_input: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    final_code = code_input or code or ""
    user, err = verify_3fa_factor3(session_id, final_code, db)
    if err or not user:
        demo_totp = None
        demo_rec = None
        if session_id and session_id in PENDING_3FA_SESSIONS:
            sess = PENDING_3FA_SESSIONS[session_id]
            target_user = db.query(User).filter(User.id == sess["user_id"]).first()
            if target_user:
                if target_user.totp_secret:
                    demo_totp = generate_totp_code(target_user.totp_secret)
                if target_user.recovery_codes_list:
                    demo_rec = target_user.recovery_codes_list[0]

        return render(
            request,
            "login_factor3.html",
            {
                "session_id": session_id,
                "error": err or "Ошибка авторизации",
                "error_msg": err or "Ошибка авторизации",
                "demo_totp": demo_totp,
                "demo_recovery_code": demo_rec,
            },
        )

    # 3FA successful! Set session token
    token = secrets.token_urlsafe(32)
    ACTIVE_SESSIONS[token] = user.id
    if "session" in request.scope:
        request.session.pop("pending_3fa_session", None)
        request.session.pop("pending_user_email", None)
        request.session["user_id"] = user.id
        request.session["role"] = user.role

    resp = RedirectResponse(url="/inbox", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(SESSION_COOKIE_NAME, token, httponly=True, max_age=86400)
    return resp


@app.get("/logout")
def logout_route(request: Request):
    if "session" in request.scope:
        request.session.clear()
    resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


# ---------------------------------------------------------------------------
# Registration Routes
# ---------------------------------------------------------------------------

@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request, error_msg: Optional[str] = None):
    return render(request, "register.html", {"error": error_msg, "error_msg": error_msg})


@app.post("/register")
def register_post(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    rsa_key_size: int = Form(4096),
    db: Session = Depends(get_db),
):
    user, err = register_user(
        db=db,
        username=username.strip(),
        email=email.strip().lower(),
        password=password,
        role="user",
        rsa_key_size=rsa_key_size,
    )
    if err or not user:
        return render(request, "register.html", {"error": err, "error_msg": err, "form_username": username, "form_email": email})

    return render(
        request,
        "register_success.html",
        {
            "new_user": user,
            "recovery_codes": user.recovery_codes_list,
            "success_msg": "Учетная запись успешно создана и сертификат ЭЦП выпущен!",
        },
    )


# ---------------------------------------------------------------------------
# Password Recovery Routes
# ---------------------------------------------------------------------------

@app.get("/recover-password", response_class=HTMLResponse)
@app.get("/forgot-password", response_class=HTMLResponse)
def recover_password_get(request: Request, error_msg: Optional[str] = None):
    return render(request, "recover_password.html", {"error": error_msg, "error_msg": error_msg})


@app.post("/recover-password/send-code")
def recover_password_send_code(
    request: Request,
    email_or_username: str = Form(...),
    db: Session = Depends(get_db),
):
    ident = email_or_username.strip()
    sess_id, err = request_password_reset(db, ident)
    if sess_id:
        if "session" in request.scope:
            request.session["reset_session"] = sess_id
        return render(
            request,
            "recover_password.html",
            {
                "success_message": "Одноразовый код для сброса пароля успешно отправлен на почту! Проверьте MailTrap или ваш email.",
                "email_or_username": ident,
            },
        )
    else:
        return render(
            request,
            "recover_password.html",
            {
                "error": err or "Пользователь не найден.",
                "email_or_username": ident,
            },
        )


@app.post("/recover-password")
@app.post("/reset-password")
@app.post("/forgot-password")
def recover_password_action(
    request: Request,
    email_or_username: Optional[str] = Form(None),
    login_input: Optional[str] = Form(None),
    verification_code: Optional[str] = Form(None),
    code: Optional[str] = Form(None),
    recovery_code: Optional[str] = Form(None),
    new_password: Optional[str] = Form(None),
    method: Optional[str] = Form(None),
    reset_token: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    ident = (email_or_username or login_input or "").strip()
    pwd = new_password or ""
    token = reset_token or (request.session.get("reset_session") if "session" in request.scope else None)

    # 1. Recovery code method
    if recovery_code and pwd:
        ok, err = reset_password_with_recovery_code(db, ident, recovery_code, pwd)
        if not ok:
            return render(request, "recover_password.html", {"error": err, "email_or_username": ident})
        return render(request, "login_factor1.html", {"success_msg": "Пароль успешно обновлен. Войдите с новым паролем."})

    # 2. Verification code from email
    v_code = verification_code or code
    if v_code and token and pwd:
        ok, err = reset_password_with_email_code(db, token, v_code, pwd)
        if not ok:
            return render(request, "recover_password.html", {"error": err, "email_or_username": ident})
        if "session" in request.scope:
            request.session.pop("reset_session", None)
        return render(request, "login_factor1.html", {"success_msg": "Пароль успешно изменен. Войдите с новым паролем."})

    # 3. Direct recovery with code in v_code field
    if v_code and pwd:
        ok, err = reset_password_with_recovery_code(db, ident, v_code, pwd)
        if ok:
            return render(request, "login_factor1.html", {"success_msg": "Пароль успешно обновлен. Войдите с новым паролем."})

    return render(request, "recover_password.html", {"error": "Неверные данные для восстановления.", "email_or_username": ident})


# ---------------------------------------------------------------------------
# Mailbox Routes (Inbox, Outbox, Compose, View)
# ---------------------------------------------------------------------------

@app.get("/inbox", response_class=HTMLResponse)
def inbox_route(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    received = (
        db.query(Message)
        .filter(Message.recipient_id == user.id)
        .order_by(Message.created_at.desc())
        .all()
    )
    sent = (
        db.query(Message)
        .filter(Message.sender_id == user.id)
        .order_by(Message.created_at.desc())
        .all()
    )
    cached_ids = []
    try:
        cached_ids = [m.id for m in received if get_cached_decrypted_message(user.id, m.id) is not None]
    except Exception:
        pass

    return render(
        request,
        "index.html",
        {
            "user": user,
            "current_user": user,
            "received_messages": received,
            "sent_messages": sent,
            "cached_message_ids": cached_ids,
            "active_page": "inbox",
        },
    )


@app.get("/outbox", response_class=HTMLResponse)
def outbox_route(request: Request, db: Session = Depends(get_db)):
    return RedirectResponse(url="/inbox", status_code=status.HTTP_302_FOUND)


@app.get("/compose", response_class=HTMLResponse)
@app.get("/messages/compose", response_class=HTMLResponse)
def compose_get(
    request: Request,
    reply_to: Optional[int] = None,
    subject: Optional[str] = None,
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    users = db.query(User).filter(User.is_active == True, User.id != user.id).all()
    return render(
        request,
        "compose.html",
        {
            "user": user,
            "current_user": user,
            "potential_recipients": users,
            "users": users,
            "reply_to": reply_to,
            "prefill_subject": subject or "",
            "active_page": "compose",
        },
    )


@app.post("/compose")
@app.post("/messages/compose")
def compose_post(
    request: Request,
    recipient_id: int = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    encryption_type: str = Form("RSA-4096"),
    rsa32k_mode: Optional[str] = Form(None),
    custom_p: Optional[str] = Form(None),
    custom_q: Optional[str] = Form(None),
    sign_ecp: Optional[str] = Form("1"),
    kuz_passphrase: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    if user.is_guest:
        users = db.query(User).filter(User.is_active == True, User.id != user.id).all()
        return render(
            request,
            "compose.html",
            {
                "user": user,
                "current_user": user,
                "potential_recipients": users,
                "users": users,
                "error": "Пользователь с рангом «Гость» не имеет прав на отправку сообщений.",
                "active_page": "compose",
            },
        )

    msg, err = send_message(
        db=db,
        sender=user,
        recipient_id=recipient_id,
        subject=subject,
        body=body,
        encryption_type=encryption_type,
        sign_ecp=bool(sign_ecp),
        kuz_passphrase=kuz_passphrase,
    )

    if err or not msg:
        users = db.query(User).filter(User.is_active == True, User.id != user.id).all()
        return render(
            request,
            "compose.html",
            {
                "user": user,
                "current_user": user,
                "potential_recipients": users,
                "users": users,
                "error": err or "Ошибка отправки сообщения",
                "active_page": "compose",
            },
        )

    return RedirectResponse(url=f"/messages/{msg.id}", status_code=status.HTTP_302_FOUND)


@app.get("/message/{message_id}", response_class=HTMLResponse)
@app.get("/messages/{message_id}", response_class=HTMLResponse)
def view_message_route(message_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Сообщение не найдено")

    # Authorize access: sender, recipient, or admin
    if user.id != message.sender_id and user.id != message.recipient_id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен: вы не участник переписки.")

    sender = db.query(User).filter(User.id == message.sender_id).first()
    recipient = db.query(User).filter(User.id == message.recipient_id).first()

    # Check cached decrypted message
    force = request.query_params.get("force") == "1"
    cached = None
    try:
        if not force:
            cached = get_cached_decrypted_message(user.id, message_id)
    except Exception:
        pass

    cert_details = None
    if cached:
        is_decrypted = True
        decrypted_text = cached.get("decrypted_content", "")
        is_sig_valid = cached.get("is_sig_valid", False)
        sig_status = cached.get("sig_status", "")
        cert_details = cached.get("cert_details")
    else:
        try:
            decrypted_text, is_sig_valid, sig_status, cert_details = decrypt_message_content(
                db=db,
                message=message,
                user=user,
            )
            is_decrypted = True
        except Exception:
            is_decrypted = False
            decrypted_text = ""
            is_sig_valid = False
            sig_status = "Сообщение зашифровано."
            cert_details = None

    return render(
        request,
        "message_view.html",
        {
            "user": user,
            "current_user": user,
            "message": message,
            "sender": sender,
            "recipient": recipient,
            "is_decrypted": is_decrypted,
            "decrypted_content": decrypted_text,
            "is_sig_valid": is_sig_valid,
            "sig_status": sig_status,
            "cert_details": cert_details,
            "active_page": "inbox" if user.id == message.recipient_id else "outbox",
        },
    )


# ---------------------------------------------------------------------------
# Keys, Security Profile & MailTrap
# ---------------------------------------------------------------------------

@app.get("/keys", response_class=HTMLResponse)
@app.get("/ecp", response_class=HTMLResponse)
def keys_profile_route(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    cert_dict = None
    if user.ecp_certificate:
        try:
            cert_dict = json.loads(user.ecp_certificate)
        except Exception:
            pass

    rsa_key_size = 2048
    if user.rsa_public_key and "MODULUS_LEN_" in user.rsa_public_key:
        try:
            rsa_key_size = int(user.rsa_public_key.split("MODULUS_LEN_")[1].split()[0])
        except Exception:
            pass

    return render(
        request,
        "ecp.html",
        {
            "user": user,
            "current_user": user,
            "cert_dict": cert_dict,
            "rsa_key_size": rsa_key_size,
            "active_page": "keys",
        },
    )


@app.post("/ecp/reissue")
def ecp_reissue_action(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or user.is_guest:
        return RedirectResponse(url="/ecp", status_code=status.HTTP_302_FOUND)

    from crypto.ecp import (
        generate_ecp_keypair,
        export_ecp_private_key_pem,
        export_ecp_public_key_pem,
        issue_self_signed_certificate,
    )
    d, Q = generate_ecp_keypair()
    user.ecp_private_key = export_ecp_private_key_pem(d)
    user.ecp_public_key = export_ecp_public_key_pem(Q)
    cert = issue_self_signed_certificate(
        username=user.username,
        user_id=user.id,
        private_key=d,
        public_key=Q,
        valid_days=365,
    )
    user.ecp_certificate = json.dumps(cert)
    db.commit()
    return RedirectResponse(url="/ecp", status_code=status.HTTP_302_FOUND)


@app.post("/keys/regenerate-recovery-codes")
def regen_codes(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or user.is_guest:
        return RedirectResponse(url="/keys", status_code=status.HTTP_302_FOUND)

    user.recovery_codes_list = generate_recovery_codes(8)
    db.commit()
    return RedirectResponse(url="/keys", status_code=status.HTTP_302_FOUND)


@app.get("/mailtrap", response_class=HTMLResponse)
def mailtrap_route(request: Request):
    emails = get_all_received_emails()
    return render(request, "mailtrap.html", {"emails": emails, "active_page": "mailtrap"})


@app.post("/mailtrap/clear")
def mailtrap_clear():
    clear_received_emails()
    return RedirectResponse(url="/mailtrap", status_code=status.HTTP_302_FOUND)


# ---------------------------------------------------------------------------
# Admin Panel & User Management
# ---------------------------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_panel_route(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен: требуется ранг Администратора.")

    users = db.query(User).order_by(User.id.asc()).all()
    total_messages = db.query(Message).count()
    return render(
        request,
        "admin.html",
        {
            "user": user,
            "current_user": user,
            "current_admin_id": user.id,
            "users": users,
            "total_messages": total_messages,
            "active_page": "admin",
        },
    )


@app.post("/admin/user/{user_id}/role")
@app.post("/admin/users/{user_id}/role")
def admin_change_role(
    user_id: int,
    request: Request,
    new_role: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    target_role = role or new_role
    target = db.query(User).filter(User.id == user_id).first()
    if target and target_role in ("guest", "user", "admin"):
        target.role = target_role
        db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)


@app.post("/admin/user/{user_id}/reset-password")
@app.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(
    user_id: int,
    request: Request,
    new_password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    target = db.query(User).filter(User.id == user_id).first()
    if target and new_password:
        pwd_hash, salt_hex = hash_password(new_password)
        target.password_hash = pwd_hash
        target.salt = salt_hex
        db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)


@app.post("/admin/user/{user_id}/delete")
@app.post("/admin/users/{user_id}/delete")
def admin_delete_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    if user.id == user_id:
        return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)

    target = db.query(User).filter(User.id == user_id).first()
    if target:
        # Delete related messages first
        db.query(Message).filter((Message.sender_id == user_id) | (Message.recipient_id == user_id)).delete()
        db.delete(target)
        db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_302_FOUND)


# ---------------------------------------------------------------------------
# Data Exports (JSON & PDF, Decrypted + Encrypted)
# ---------------------------------------------------------------------------

def _build_export_payload(
    db: Session,
    messages: List[Message],
    requested_by_user: User,
    variant: str = "all",
) -> Dict[str, Any]:
    """Prepares structured message list with both decrypted and encrypted representations."""
    items = []
    for m in messages:
        dec_body, sig_valid, sig_comm, cert = decrypt_message_content(db, m, requested_by_user)
        item = {
            "id": m.id,
            "created_at": m.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "sender_id": m.sender_id,
            "sender_username": m.sender.username if m.sender else f"id_{m.sender_id}",
            "recipient_id": m.recipient_id,
            "recipient_username": m.recipient.username if m.recipient else f"id_{m.recipient_id}",
            "subject": m.subject,
            "encryption_type": m.encryption_type,
            "is_read": m.is_read,
            "signature_status": sig_comm,
            "signature_valid": sig_valid,
        }

        # Decrypted content
        if variant in ("all", "decrypted"):
            item["decrypted_body"] = dec_body

        # Encrypted content
        if variant in ("all", "encrypted"):
            item["ciphertext"] = m.ciphertext
            item["key_bundle"] = m.key_bundle
            item["ecp_signature"] = m.ecp_signature
            item["ecp_cert_snapshot"] = m.ecp_cert_snapshot

        items.append(item)

    return {
        "export_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "requested_by": f"{requested_by_user.username} ({requested_by_user.role})",
        "variant": "Расшифрованный + Зашифрованный" if variant == "all" else variant,
        "total_messages": len(items),
        "messages": items,
    }


@app.get("/export/my")
@app.get("/export/my/json")
@app.get("/export/my/pdf")
def export_my_messages(
    format: str = "json",
    variant: str = "all",
    request: Request = None,
    db: Session = Depends(get_db),
):
    """User exports all personal sent and received messages in JSON or PDF."""
    user = get_current_user(request, db)
    if not user or user.is_guest:
        raise HTTPException(status_code=403, detail="Экспорт недоступен для гостевого режима")

    fmt = format
    if request and request.url.path.endswith("/pdf"):
        fmt = "pdf"
    elif request and request.url.path.endswith("/json"):
        fmt = "json"

    messages = (
        db.query(Message)
        .filter((Message.sender_id == user.id) | (Message.recipient_id == user.id))
        .order_by(Message.created_at.desc())
        .all()
    )

    data = _build_export_payload(db, messages, user, variant=variant)

    if fmt.lower() == "pdf":
        pdf_bytes = export_to_pdf_bytes(data, title=f"Выгрузка сообщений пользователя {user.username}")
        filename = f"cryptomail_export_{user.username}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        return RawResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        json_bytes = export_to_json_bytes(data)
        filename = f"cryptomail_export_{user.username}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        return RawResponse(
            content=json_bytes,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/admin/export/all")
@app.get("/admin/export/json")
@app.get("/admin/export/pdf")
def admin_export_all_messages(
    format: str = "json",
    variant: str = "all",
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Admin exports all messages across the entire platform in JSON or PDF."""
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Требуются права администратора")

    fmt = format
    if request and request.url.path.endswith("/pdf"):
        fmt = "pdf"
    elif request and request.url.path.endswith("/json"):
        fmt = "json"

    messages = db.query(Message).order_by(Message.created_at.desc()).all()
    data = _build_export_payload(db, messages, user, variant=variant)

    if fmt.lower() == "pdf":
        pdf_bytes = export_to_pdf_bytes(data, title="Глобальная выгрузка всех сообщений CryptoMail")
        filename = f"cryptomail_ALL_audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        return RawResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        json_bytes = export_to_json_bytes(data)
        filename = f"cryptomail_ALL_audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        return RawResponse(
            content=json_bytes,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/admin/export/user/{target_user_id}")
@app.get("/admin/users/{target_user_id}/export/json")
@app.get("/admin/users/{target_user_id}/export/pdf")
def admin_export_specific_user(
    target_user_id: int,
    format: str = "json",
    variant: str = "all",
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Admin exports all messages of a specific user in JSON or PDF."""
    user = get_current_user(request, db)
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Требуются права администратора")

    target = db.query(User).filter(User.id == target_user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    fmt = format
    if request and request.url.path.endswith("/pdf"):
        fmt = "pdf"
    elif request and request.url.path.endswith("/json"):
        fmt = "json"

    messages = (
        db.query(Message)
        .filter((Message.sender_id == target.id) | (Message.recipient_id == target.id))
        .order_by(Message.created_at.desc())
        .all()
    )
    data = _build_export_payload(db, messages, user, variant=variant)

    if fmt.lower() == "pdf":
        pdf_bytes = export_to_pdf_bytes(data, title=f"Выгрузка переписки: {target.username}")
        filename = f"cryptomail_user_{target.username}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
        return RawResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        json_bytes = export_to_json_bytes(data)
        filename = f"cryptomail_user_{target.username}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        return RawResponse(
            content=json_bytes,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/export/message/{message_id}")
@app.get("/messages/{message_id}/export/json")
def export_single_message(
    message_id: int,
    format: str = "json",
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Exports an individual message in JSON or PDF."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")

    message = db.query(Message).filter(Message.id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Сообщение не найдено")

    if user.id != message.sender_id and user.id != message.recipient_id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Доступ запрещен")

    data = _build_export_payload(db, [message], user, variant="all")

    if format.lower() == "pdf":
        pdf_bytes = export_to_pdf_bytes(data, title=f"Сообщение #{message.id}: {message.subject}")
        filename = f"message_{message.id}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        return RawResponse(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        json_bytes = export_to_json_bytes(data)
        filename = f"message_{message.id}_{datetime.utcnow().strftime('%Y%m%d')}.json"
        return RawResponse(
            content=json_bytes,
            media_type="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )


@app.get("/messages/{message_id}/export/pdf")
def export_single_message_pdf(message_id: int, request: Request, db: Session = Depends(get_db)):
    """Exports signed message PDF with GOST digital stamp."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Сообщение не найдено.")
    if not user.is_admin and user.id not in (msg.sender_id, msg.recipient_id):
        raise HTTPException(status_code=403, detail="Доступ запрещен.")

    pdf_bytes, sig_b64, meta = generate_signed_message_pdf(db, msg, user)
    return RawResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="message_{msg.id}_signed_ecp.pdf"',
            "X-CryptoMail-ECP-Signature": sig_b64,
        },
    )


@app.get("/messages/{message_id}/export/sig")
def export_single_message_sig(message_id: int, request: Request, db: Session = Depends(get_db)):
    """Exports detached digital signature (.sig JSON) for the generated PDF."""
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    msg = db.query(Message).filter(Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Сообщение не найдено.")
    if not user.is_admin and user.id not in (msg.sender_id, msg.recipient_id):
        raise HTTPException(status_code=403, detail="Доступ запрещен.")

    pdf_bytes, sig_b64, meta = generate_signed_message_pdf(db, msg, user)
    sig_payload = json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8")
    return RawResponse(
        content=sig_payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="message_{msg.id}_signature.sig"'},
    )


# ---------------------------------------------------------------------------
# Background Tasks Status & Crypto Operations API
# ---------------------------------------------------------------------------

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


@app.get("/api/tasks/{task_id}")
def api_task_status(task_id: str):
    status_info = get_task_status(task_id)
    if not status_info:
        return JSONResponse(status_code=404, content={"error": "Задача не найдена"})
    return JSONResponse(content=status_info)
