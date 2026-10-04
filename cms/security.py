"""Rate limiting, CSRF, auth helpers and response headers."""
import hashlib
import hmac
import os
from collections import defaultdict
from datetime import timedelta
from functools import wraps
from threading import Lock

from flask import abort, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .app import FRAME_ANCESTORS, IS_PRODUCTION, admin_login_enabled, app, logger, utc_now


def client_ip() -> str:
    """Real client address. Behind Vercel the proxy sets the forwarded headers."""
    if IS_PRODUCTION:
        fwd = request.headers.get("X-Vercel-Forwarded-For") or request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


# ── Rate limiting ──────────────────────────────────────────
# Counters live in MongoDB so they hold across serverless instances. The
# in-memory store is only a fallback when the database is unreachable.
_memory: dict[str, list] = defaultdict(list)
_memory_lock = Lock()


def rate_count(key: str, window: int) -> int:
    since = utc_now() - timedelta(seconds=window)
    col = getattr(g, "rate_col", None)
    if col is not None:
        try:
            return col.count_documents({"key": key, "ts": {"$gte": since}})
        except Exception as e:
            logger.warning(f"rate_count fell back to memory: {e}")
    now = utc_now().timestamp()
    with _memory_lock:
        return len([t for t in _memory[key] if now - t < window])


def rate_record(key: str):
    col = getattr(g, "rate_col", None)
    if col is not None:
        try:
            col.insert_one({"key": key, "ts": utc_now()})
            return
        except Exception as e:
            logger.warning(f"rate_record fell back to memory: {e}")
    with _memory_lock:
        _memory[key].append(utc_now().timestamp())


def rate_clear(key: str):
    col = getattr(g, "rate_col", None)
    if col is not None:
        try:
            col.delete_many({"key": key})
        except Exception:
            pass
    with _memory_lock:
        _memory.pop(key, None)


def rate_limit(max_calls: int, window_seconds: int):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            key = f"{f.__name__}:{client_ip()}"
            if rate_count(key, window_seconds) >= max_calls:
                logger.warning(f"Rate limit hit: {key}")
                return render_template("429.html"), 429
            rate_record(key)
            return f(*args, **kwargs)
        return wrapper
    return decorator


LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW = 900


def login_locked_out(ip: str) -> bool:
    return rate_count(f"loginfail:{ip}", LOGIN_WINDOW) >= LOGIN_MAX_FAILURES


# ── CSRF ───────────────────────────────────────────────────
def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = hashlib.sha256(os.urandom(32)).hexdigest()
    return session["csrf_token"]


def validate_csrf():
    """Call at the top of every state-changing handler."""
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
        logger.warning(f"CSRF failure from {client_ip()}")
        abort(403)


app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ── Auth ───────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def check_admin_credentials(username: str, password: str) -> bool:
    if not admin_login_enabled():
        return False
    user_ok = hmac.compare_digest(username, os.environ.get("ADMIN_USERNAME", "admin"))
    pw_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if pw_hash:
        pass_ok = check_password_hash(pw_hash, password)
    else:
        pass_ok = hmac.compare_digest(password, os.environ.get("ADMIN_PASSWORD", "password"))
    return user_ok and pass_ok


def safe_next_url(target):
    """Same-site absolute paths only. Rejects //host, /\\host and full URLs."""
    if not target or not target.startswith("/") or target.startswith(("//", "/\\")):
        return None
    return target


# ── Headers ────────────────────────────────────────────────
# Pages that carry privileges (sign-in, admin, the editor preview) must never be framed,
# otherwise another site could trick an admin into clicking buttons they can't see.
_NEVER_FRAMED = ("/admin", "/login", "/logout", "/_preview")


def _never_framed(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _NEVER_FRAMED)


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # Page content is admin-authored HTML/JS, so a strict script policy would break it.
    # These directives still close off plugins and <base> hijacking.
    csp = "object-src 'none'; base-uri 'self'; "
    if _never_framed(request.path):
        csp += "frame-ancestors 'none'"
        response.headers["X-Frame-Options"] = "DENY"
    else:
        # X-Frame-Options can't express "these origins", and it would override the policy
        # below in older browsers, so public pages don't send it at all.
        csp += f"frame-ancestors {FRAME_ANCESTORS}"
        response.headers.pop("X-Frame-Options", None)
    response.headers["Content-Security-Policy"] = csp

    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response
