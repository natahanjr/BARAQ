"""Multi-user authentication and audit endpoints.

Operators log in with username + password to receive an HMAC-signed token that
the frontend sends as ``Authorization: Bearer <token>``. Admins can create /
disable accounts and pull the audit trail. The agent channel (X-Agent-Key) and
the legacy X-API-Key header remain supported alongside this.

SSO: when LDAP/AD is configured (BARAQ_LDAP_ENABLED=1), login falls back
to the directory when local credentials fail, auto-provisioning the operator
as a local account (see backend/ldap.py).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import defaultdict
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend import ldap as ldap_sso
from backend.audit import client_ip, log_action
from backend.auth import (
    create_mfa_challenge,
    create_token,
    hash_password,
    verify_password,
    verify_token,
)
from backend.config import AUTH_TOKEN_SECRET, COOKIE_SECURE, DEFAULT_ADMIN_PASSWORD
from backend.database.connection import get_db
from backend.database.models import AuditLog, User
from backend.security import (
    require_admin,
    require_auth,
    require_auth_enroll_mfa,
    require_auth_pending_change,
    resolve_user,
)
from backend.totp import generate_secret, provisioning_uri, verify_code

logger = logging.getLogger("baraq.api.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])

SESSION_COOKIE = "baraq_session"
CSRF_COOKIE = "baraq_csrf"

#: Brute-force protection on the login endpoint. In-memory sliding window:
#: at most LOGIN_MAX_ATTEMPTS failures per IP within LOGIN_WINDOW_SECONDS.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
_lockout: dict[str, list[float]] = defaultdict(list)


def _check_login_rate_limit(request: Request) -> None:
    """Track failed login attempts per client IP and raise 429 when exceeded."""
    ip = client_ip(request)
    now = time.monotonic()
    failures = [t for t in _lockout.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
    if len(failures) >= LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many failed login attempts. Try again in "
                f"{int(LOGIN_WINDOW_SECONDS - (now - failures[0]))} seconds."
            ),
        )
    _lockout[ip] = failures


def _record_login_failure(request: Request) -> None:
    ip = client_ip(request)
    _lockout.setdefault(ip, []).append(time.monotonic())
    # Keep the map bounded.
    if len(_lockout) > 10000:
        _lockout.clear()


def _clear_login_rate_limit(request: Request) -> None:
    _lockout.pop(client_ip(request), None)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RegisterRequest(BaseModel):
    """Self-service account creation; the account stays inactive (pending)
    until an administrator verifies it."""

    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=256)
    full_name: str = Field("", max_length=128)
    org: str = Field("", max_length=64)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class RenameRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")


def _username_taken(db: Session, username: str, exclude_id: int | None = None) -> bool:
    """Case-insensitive duplicate check (prevents 'nat' vs 'Nat' collisions)."""
    stmt = select(User).where(func.lower(User.username) == username.lower())
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return db.scalar(stmt) is not None


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: str = Field("analyst", pattern="^(admin|analyst)$")
    full_name: str = Field("", max_length=128)
    org: str = Field("", max_length=64)


class UserUpdate(BaseModel):
    is_active: bool | None = None
    role: str | None = Field(None, pattern="^(admin|analyst)$")
    full_name: str | None = Field(None, max_length=128)
    password: str | None = Field(None, min_length=8, max_length=256)
    org: str | None = Field(None, max_length=64)


def _public_user(user: User) -> dict:
    return user.to_dict()


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    _check_login_rate_limit(request)
    username = body.username.strip()
    user = db.scalar(select(User).where(User.username == username))
    password_ok = bool(user) and verify_password(body.password, user.password_hash)
    source = "local"
    if not password_ok:
        user = _ldap_login_fallback(db, username, body.password, request)
        if user is not None:
            source = "ldap"
            password_ok = True
    if not user or not password_ok:
        _record_login_failure(request)
        log_action(
            db,
            username,
            "login.failed",
            "user",
            username,
            f"invalid credentials via {source}",
            client_ip(request),
        )
        raise HTTPException(401, "Invalid username or password")
    if not user.is_active:
        _record_login_failure(request)
        status_hint = user.registration_status or ""
        if status_hint == "pending":
            detail = "Your account is pending verification by an administrator"
        elif status_hint == "rejected":
            detail = "Your account registration was rejected by an administrator"
        else:
            detail = "Account disabled"
        log_action(
            db,
            user.username,
            "login.rejected",
            "user",
            str(user.id),
            f"account not active ({status_hint or 'disabled'})",
            client_ip(request),
        )
        raise HTTPException(403, detail)
    _clear_login_rate_limit(request)
    if user.totp_enabled:
        challenge = create_mfa_challenge(user.id, user.username)
        log_action(
            db,
            user.username,
            "login.mfa_challenge",
            "user",
            str(user.id),
            f"password ok via {source}, TOTP required",
            client_ip(request),
        )
        return JSONResponse(
            {
                "mfa_required": True,
                "challenge": challenge,
                "user": _public_user(user),
                "must_change_password": bool(user.must_change_password),
            }
        )
    return _complete_login(request, db, user, source)


@router.post("/register")
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    """Self-service account creation.

    New accounts are created as inactive ``analyst`` accounts marked
    ``pending``; they cannot sign in until an administrator verifies them
    (``POST /api/auth/users/{id}/approve``). This keeps account creation
    open on the login screen without handing out access.
    """
    username = body.username.strip()
    if _username_taken(db, username):
        raise HTTPException(409, "Username already exists")
    user = User(
        username=username,
        password_hash=hash_password(body.password),
        role="analyst",
        full_name=body.full_name.strip(),
        org=body.org.strip(),
        is_active=False,
        registration_status="pending",
    )
    db.add(user)
    db.commit()
    log_action(
        db,
        username,
        "user.registered",
        "user",
        str(user.id),
        "self-service registration awaiting verification",
        client_ip(request),
    )
    logger.info("New registration '%s' awaiting admin verification", username)
    return {
        "ok": True,
        "pending": True,
        "message": "Account created - it will be activated once an administrator "
        "verifies it.",
    }


def _ldap_login_fallback(
    db: Session, username: str, password: str, request: Request
) -> User | None:
    if not ldap_sso.ldap_enabled():
        return None
    try:
        profile = ldap_sso.ldap_authenticate(username, password)
    except ldap_sso.LDAPError as exc:
        logger.warning("LDAP authentication unavailable for %r: %s", username, exc)
        log_action(
            db,
            username,
            "login.ldap_unavailable",
            "user",
            username,
            f"directory error: {exc}",
            client_ip(request),
        )
        return None
    if profile is None:
        log_action(
            db,
            username,
            "login.ldap_failed",
            "user",
            username,
            "directory rejected credentials",
            client_ip(request),
        )
        return None
    return _provision_sso_user(db, profile, request, source="ldap")


def _provision_sso_user(
    db: Session, profile: dict, request: Request, source: str = "ldap"
) -> User:
    """Create or profile-sync a local account from a successful SSO login.

    The local password hash is random/unusable so the external provider
    remains the only way in for that account. ``source`` is "ldap" or "oidc"
    and only affects the audit detail.
    """
    username = profile.get("username", "")
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        user = User(
            username=username,
            password_hash=hash_password(secrets.token_urlsafe(48)),  # unusable
            role=profile.get("role", "analyst"),
            full_name=profile.get("full_name", ""),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        log_action(
            db,
            username,
            "user.provisioned",
            "user",
            str(user.id),
            f"auto-provisioned via {source} role={user.role}",
            client_ip(request),
        )
        return user
    role = profile.get("role", user.role)
    full_name = profile.get("full_name", "")
    if role != user.role or full_name != user.full_name:
        user.role = role
        if full_name:
            user.full_name = full_name
        db.commit()
        log_action(
            db,
            username,
            "user.synced",
            "user",
            str(user.id),
            f"{source} profile sync role={user.role}",
            client_ip(request),
        )
    return user


# ---------------------------------------------------------------------------
# OpenID Connect SSO (SC5c)
#
# Step 1 (/oidc/login): generate state + nonce + PKCE verifier, stash them on
#   a signed "baraq_oidc" cookie, and 302 to the provider.
# Step 2 (/oidc/callback): exchange the code, validate the id_token (see
#   backend/oidc.py), provision the operator, restore the session and bounce
#   back to the SPA. Both routes are public (like /login): the code exchange
#   IS the authentication.
# ---------------------------------------------------------------------------

OIDC_COOKIE = "baraq_oidc"
OIDC_COOKIE_TTL = 600  # seconds to complete the flow


def _sso_hmac_key() -> bytes:
    return hashlib.sha256(AUTH_TOKEN_SECRET.encode("utf-8")).digest()


def _make_sso_token(state: str, nonce: str, verifier: str) -> str:
    """Signed one-time cookie value carrying the OIDC flow state."""
    payload = {
        "state": state,
        "nonce": nonce,
        "verifier": verifier,
        "exp": int(time.time()) + OIDC_COOKIE_TTL,
    }
    body = (
        base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8"))
        .rstrip(b"=")
        .decode("ascii")
    )
    sig = hmac.new(_sso_hmac_key(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def _verify_sso_token(token: str) -> dict | None:
    """Return the OIDC flow state if the signed cookie is valid and fresh."""
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(
            _sso_hmac_key(), body.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        if int(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


@router.get("/oidc/status")
def oidc_status():
    from backend import ldap as _ldap
    from backend import oidc as _oidc

    return {
        "oidc": _oidc.oidc_enabled(),
        "ldap": _ldap.ldap_enabled(),
    }


@router.get("/oidc/login")
def oidc_login(request: Request, db: Session = Depends(get_db)):
    from backend import oidc as _oidc

    if not _oidc.oidc_enabled():
        raise HTTPException(404, "OIDC single sign-on is not enabled")
    state = secrets.token_urlsafe(16)
    nonce = _oidc.make_nonce()
    verifier, challenge = _oidc.generate_pkce_pair()
    url = _oidc.build_authorization_url(state, nonce, challenge, str(request.base_url))
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        OIDC_COOKIE,
        _make_sso_token(state, nonce, verifier),
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
        max_age=OIDC_COOKIE_TTL,
    )
    log_action(
        db,
        "unknown",
        "oidc.started",
        "user",
        state[:16],
        "OIDC authorization flow started",
        client_ip(request),
    )
    return resp


@router.get("/oidc/callback")
def oidc_callback(
    code: str, state: str, request: Request, db: Session = Depends(get_db)
):
    """Exchange the authorization code, validate, provision and sign in."""
    from backend import oidc as _oidc

    if not _oidc.oidc_enabled():
        raise HTTPException(404, "OIDC single sign-on is not enabled")
    payload = _verify_sso_token(request.cookies.get(OIDC_COOKIE, ""))
    if not payload or payload.get("state") != state:
        log_action(
            db,
            "unknown",
            "oidc.callback_rejected",
            "user",
            state[:16],
            "state mismatch or expired OIDC flow",
            client_ip(request),
        )
        return RedirectResponse("/", status_code=302)
    try:
        tokens = _oidc.exchange_code(code, payload["verifier"], str(request.base_url))
        id_token = tokens.get("id_token")
        if not id_token:
            raise _oidc.OIDCError("token response carried no id_token")
        claims = _oidc.validate_id_token(id_token, payload["nonce"])
        profile = _oidc.profile_from_claims(claims)
    except _oidc.OIDCError as exc:
        logger.warning("OIDC callback rejected: %s", exc)
        log_action(
            db,
            "unknown",
            "oidc.callback_failed",
            "user",
            state[:16],
            f"provider/token error: {exc}",
            client_ip(request),
        )
        return RedirectResponse("/", status_code=302)
    user = _provision_sso_user(db, profile, request, source="oidc")
    if not user.is_active:
        log_action(
            db,
            user.username,
            "login.rejected",
            "user",
            str(user.id),
            "account disabled",
            client_ip(request),
        )
        return RedirectResponse("/", status_code=302)
    user.last_login_at = datetime.now(UTC)
    db.commit()
    token = create_token(user.id, user.username, user.role, user.org)
    log_action(
        db,
        user.username,
        "login",
        "user",
        str(user.id),
        f"role={user.role} via-oidc",
        client_ip(request),
    )
    resp = RedirectResponse("/", status_code=302)
    _set_session_cookie(resp, token)
    resp.delete_cookie(OIDC_COOKIE, path="/")
    return resp


class MfaVerifyRequest(BaseModel):
    challenge: str = Field(min_length=10, max_length=1024)
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


@router.post("/mfa/verify")
def mfa_verify(body: MfaVerifyRequest, request: Request, db: Session = Depends(get_db)):
    """Second step of a 2FA login: exchange the challenge for a session token."""
    _check_login_rate_limit(request)
    payload = verify_token(body.challenge)
    if not payload or not payload.get("mfa"):
        _record_login_failure(request)
        raise HTTPException(401, "Challenge expired — log in again")
    user = db.get(User, payload.get("uid"))
    if not user or not user.is_active or not user.totp_enabled:
        _record_login_failure(request)
        raise HTTPException(401, "Challenge invalid — log in again")
    if not verify_code(user.totp_secret, body.code):
        _record_login_failure(request)
        log_action(
            db,
            user.username,
            "login.mfa_failed",
            "user",
            str(user.id),
            "invalid TOTP code",
            client_ip(request),
        )
        raise HTTPException(401, "Invalid verification code")
    _clear_login_rate_limit(request)
    token = create_token(user.id, user.username, user.role, user.org)
    log_action(
        db,
        user.username,
        "login",
        "user",
        str(user.id),
        f"role={user.role} via-mfa",
        client_ip(request),
    )
    resp = JSONResponse(
        {
            "token": token,
            "user": _public_user(user),
            "must_change_password": bool(user.must_change_password),
        }
    )
    _set_session_cookie(resp, token)
    return resp


def _complete_login(request: Request, db: Session, user: User, source: str = "local"):
    user.last_login_at = datetime.now(UTC)
    db.commit()
    token = create_token(user.id, user.username, user.role, user.org)
    log_action(
        db,
        user.username,
        "login",
        "user",
        str(user.id),
        f"role={user.role}" + (f" via-{source}" if source != "local" else ""),
        client_ip(request),
    )
    resp = JSONResponse(
        {
            "token": token,
            "user": _public_user(user),
            "must_change_password": bool(user.must_change_password),
        }
    )
    _set_session_cookie(resp, token)
    return resp


def _set_session_cookie(resp: JSONResponse, token: str) -> None:
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=COOKIE_SECURE,
        path="/",
        max_age=7 * 24 * 3600,
    )
    # CSRF double-submit token: readable by JS (not httpOnly) so the SPA can
    # echo it in X-CSRF-Token on state-changing requests. Re-issued at every
    # login, so a stolen value never outlives the session.
    resp.set_cookie(
        CSRF_COOKIE,
        secrets.token_urlsafe(32),
        httponly=False,
        samesite="strict",
        secure=COOKIE_SECURE,
        path="/",
        max_age=7 * 24 * 3600,
    )


class MfaSetupResult(BaseModel):
    secret: str
    otpauth_url: str


@router.post("/mfa/setup", dependencies=[Depends(require_auth_enroll_mfa)])
def mfa_setup(request: Request, db: Session = Depends(get_db)):
    """Provision TOTP for the authenticated user (returns the shared secret
    exactly once; the secret is only activated after ``/mfa/confirm``)."""
    user = resolve_user(request, db)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    if user.totp_enabled:
        # Guard: a stray "Set Up 2FA" click must never silently disable an
        # active enrollment (previously the reset below turned MFA off).
        raise HTTPException(
            409,
            "Two-factor authentication is already enabled "
            "for this account - disable it first to re-enroll",
        )
    secret = generate_secret()
    user.totp_secret = secret
    user.totp_enabled = False
    db.commit()
    log_action(
        db,
        user.username,
        "mfa.setup",
        "user",
        str(user.id),
        "TOTP secret generated (pending confirmation)",
        client_ip(request),
    )
    return {"secret": secret, "otpauth_url": provisioning_uri(user.username, secret)}


class MfaConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^[0-9]{6}$")


@router.post("/mfa/confirm", dependencies=[Depends(require_auth_enroll_mfa)])
def mfa_confirm(
    body: MfaConfirmRequest, request: Request, db: Session = Depends(get_db)
):
    """Activate 2FA after the user proves they can generate codes."""
    user = resolve_user(request, db)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    if not user.totp_secret:
        raise HTTPException(400, "No pending TOTP secret — call /mfa/setup first")
    if not verify_code(user.totp_secret, body.code):
        log_action(
            db,
            user.username,
            "mfa.confirm_failed",
            "user",
            str(user.id),
            "TOTP code mismatch during activation",
            client_ip(request),
        )
        raise HTTPException(401, "Invalid verification code")
    user.totp_enabled = True
    db.commit()
    log_action(
        db,
        user.username,
        "mfa.enabled",
        "user",
        str(user.id),
        "TOTP second factor activated",
        client_ip(request),
    )
    return {"ok": True, "totp_enabled": True}


@router.post("/mfa/disable", dependencies=[Depends(require_auth_enroll_mfa)])
def mfa_disable(
    body: MfaConfirmRequest, request: Request, db: Session = Depends(get_db)
):
    """Disable 2FA (requires a valid code from the current authenticator)."""
    user = resolve_user(request, db)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    if not user.totp_enabled:
        return {"ok": True, "totp_enabled": False}
    if not verify_code(user.totp_secret, body.code):
        log_action(
            db,
            user.username,
            "mfa.disable_failed",
            "user",
            str(user.id),
            "TOTP code mismatch during deactivation",
            client_ip(request),
        )
        raise HTTPException(401, "Invalid verification code")
    user.totp_secret = ""
    user.totp_enabled = False
    db.commit()
    log_action(
        db,
        user.username,
        "mfa.disabled",
        "user",
        str(user.id),
        "TOTP second factor deactivated",
        client_ip(request),
    )
    return {"ok": True, "totp_enabled": False}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    payload = verify_token(token)
    log_action(
        db,
        payload.get("sub", "unknown") if payload else "unknown",
        "logout",
        "user",
        str(payload.get("uid", "")) if payload else "",
        "session ended",
        client_ip(request),
    )
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/me")
def me(request: Request, db: Session = Depends(get_db)):
    from backend.security import resolve_user

    user = resolve_user(request, db)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    return {"user": _public_user(user)}


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------


@router.get("/users", dependencies=[Depends(require_admin)])
def list_users(request: Request = None, db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.username)).all()
    return {"items": [_public_user(u) for u in users], "total": len(users)}


@router.post("/users", dependencies=[Depends(require_admin)])
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.username == body.username.strip()))
    if existing:
        raise HTTPException(409, "Username already exists")
    user = User(
        username=body.username.strip(),
        password_hash=hash_password(body.password),
        role=body.role,
        full_name=body.full_name.strip(),
        org=body.org.strip(),
        is_active=True,
    )
    db.add(user)
    db.commit()
    log_action(
        db,
        _actor(request),
        "user.create",
        "user",
        str(user.id),
        f"username={user.username} role={user.role}",
        client_ip(request),
    )
    return _public_user(user)


@router.post("/users/{user_id}/approve", dependencies=[Depends(require_admin)])
def approve_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    """Verify a self-registered account: activate it and clear the pending flag."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.registration_status != "pending" and user.is_active:
        raise HTTPException(409, "Account is already active")
    user.is_active = True
    user.registration_status = ""
    db.commit()
    log_action(
        db,
        _actor(request),
        "user.approved",
        "user",
        str(user.id),
        f"username={user.username} verified by administrator",
        client_ip(request),
    )
    return _public_user(user)


@router.post("/users/{user_id}/reject", dependencies=[Depends(require_admin)])
def reject_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    """Reject a self-registered account: stays inactive, marked 'rejected'."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.registration_status == "rejected" and not user.is_active:
        raise HTTPException(409, "Account is already rejected")
    user.is_active = False
    user.registration_status = "rejected"
    db.commit()
    log_action(
        db,
        _actor(request),
        "user.rejected",
        "user",
        str(user.id),
        f"username={user.username} registration rejected",
        client_ip(request),
    )
    return _public_user(user)


@router.post(
    "/settings/change-password", dependencies=[Depends(require_auth_pending_change)]
)
def change_password(
    body: PasswordChangeRequest, request: Request, db: Session = Depends(get_db)
):
    """Self-service password change (requires the current password).

    Also clears the ``must_change_password`` flag that gates the console for
    accounts still on the default bootstrap password.
    """
    user = resolve_user(request, db)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(403, "Current password is incorrect")
    if user.must_change_password and body.new_password == DEFAULT_ADMIN_PASSWORD:
        raise HTTPException(
            400,
            "Choose a different password - the default "
            "bootstrap password cannot be kept",
        )
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    db.commit()
    log_action(
        db,
        user.username,
        "user.password_changed",
        "user",
        str(user.id),
        "password changed via settings",
        client_ip(request),
    )
    return {"ok": True, "must_change_password": False}


@router.post("/settings/rename", dependencies=[Depends(require_auth)])
def rename_account(
    body: RenameRequest, request: Request, db: Session = Depends(get_db)
):
    """Self-service username change (requires the current password)."""
    user = resolve_user(request, db)
    if not user:
        raise HTTPException(401, "Invalid or expired session")
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(403, "Current password is incorrect")
    new_username = body.new_username.strip()
    if new_username.lower() == user.username.lower():
        raise HTTPException(409, "That is already your username")
    if _username_taken(db, new_username, exclude_id=user.id):
        raise HTTPException(409, "Username already exists")
    old_username = user.username
    user.username = new_username
    db.commit()
    log_action(
        db,
        old_username,
        "user.renamed",
        "user",
        str(user.id),
        f"username={old_username} -> {new_username}",
        client_ip(request),
    )
    return _public_user(user)


@router.patch("/users/{user_id}", dependencies=[Depends(require_admin)])
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        user.role = body.role
    if body.full_name is not None:
        user.full_name = body.full_name.strip()
    if body.is_active is not None:
        user.is_active = bool(body.is_active)
    if body.org is not None:
        user.org = body.org.strip()
    if body.password:
        user.password_hash = hash_password(body.password)
    db.commit()
    log_action(
        db,
        _actor(request),
        "user.update",
        "user",
        str(user.id),
        f"username={user.username} role={user.role} active={user.is_active}",
        client_ip(request),
    )
    return _public_user(user)


@router.delete("/users/{user_id}", dependencies=[Depends(require_admin)])
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """Delete an operator account. Safety guards: you cannot delete your own
    account, and the last admin account can never be removed (lockout guard).
    """
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.username == _actor(request):
        raise HTTPException(400, "You cannot delete your own account")
    if user.role == "admin":
        admin_count = len(
            [1 for u in db.scalars(select(User).where(User.role == "admin")).all()]
        )
        if admin_count <= 1:
            raise HTTPException(400, "Cannot delete the last admin account")
    username = user.username
    role = user.role
    db.delete(user)
    db.commit()
    log_action(
        db,
        _actor(request),
        "user.delete",
        "user",
        str(user_id),
        f"username={username} role={role}",
        client_ip(request),
    )
    return {"deleted": user_id, "username": username}


def _actor(request: Request | None) -> str:
    if request is None:
        return "unknown"
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        auth = f"Bearer {request.cookies.get('baraq_session', '')}"
    if auth.lower().startswith("bearer "):
        payload = verify_token(auth[7:].strip())
        if payload:
            return payload.get("sub", "unknown")
    return request.headers.get("X-API-Key", "unknown")


# ---------------------------------------------------------------------------
# Audit trail (admin only)
# ---------------------------------------------------------------------------


@router.get("/audit", dependencies=[Depends(require_admin)])
def list_audit(
    action: str | None = None,
    actor: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    rows = db.scalars(stmt).all()
    return {"items": [e.to_dict() for e in rows]}


@router.get("/audit/verify", dependencies=[Depends(require_admin)])
def verify_audit_chain(db: Session = Depends(get_db)):
    """Recompute the audit hash chain and confirm no entry was tampered with."""
    from backend.audit import verify_chain

    try:
        return verify_chain(db)
    except Exception as exc:
        return {"ok": False, "checked": 0, "broken_at": None, "error": str(exc)}


@router.post("/audit/clear", dependencies=[Depends(require_admin)])
def clear_audit(request: Request, db: Session = Depends(get_db)):
    """Delete the entire audit trail, force-generating an executive report first.

    The report is generated while the records still exist, so it captures the
    full activity before the trail is erased. The forced report remains the
    permanent record; the hash chain restarts from the new clear entry.
    """
    from backend.reports.generator import generate_report

    count = len(db.scalars(select(AuditLog)).all())
    if not count:
        return {
            "cleared": 0,
            "message": "Audit trail is already empty.",
            "report": None,
        }

    report = generate_report(db, "executive", "pdf")
    db.query(AuditLog).delete()
    db.commit()
    log_action(
        db,
        _actor(request),
        "audit.clear",
        "audit",
        "-",
        f"deleted {count} record(s); report={report['file_path']}",
        client_ip(request),
    )
    logger.info(
        "Cleared %d audit record(s); forced report generated: %s",
        count,
        report["file_path"],
    )
    return {
        "cleared": count,
        "message": f"Cleared {count} audit record(s). Report generated before clearing.",
        "report": report,
    }
