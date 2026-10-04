"""Flask app object, configuration and the Vercel path shim."""
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from dotenv import load_dotenv
from flask import Flask

load_dotenv()

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_API = os.path.join(_ROOT, "api")

IS_PRODUCTION = bool(os.environ.get("VERCEL")) or os.environ.get("FLASK_ENV") == "production"
SITE_URL = os.environ.get("SITE_URL", "https://klhportfolio.vercel.app").rstrip("/")

# Who may embed the public pages in an <iframe> (CSP frame-ancestors). Space-separated list
# of origins, "*" for any site, or "'self'" for none. Admin and login pages ignore this and
# can never be framed. Anything that isn't "*", "'self'" or a plain http(s) origin is dropped.
_ORIGIN = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?$")


def _frame_ancestors() -> str:
    tokens = os.environ.get("FRAME_ANCESTORS", "*").split()
    allowed = [t for t in tokens if t in ("*", "'self'") or _ORIGIN.match(t)]
    return " ".join(allowed) or "'self'"


FRAME_ANCESTORS = _frame_ancestors()

_PLACEHOLDER_SECRETS = {"", "dev-key-change-in-production", "your_random_secret_key_here"}
_PLACEHOLDER_PASSWORDS = {"", "password", "your_password_here"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("cms")


def utc_now() -> datetime:
    """Naive UTC timestamp, which is what Mongo stores and returns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _resolve_secret_key() -> str:
    key = os.environ.get("SECRET_KEY", "")
    if key not in _PLACEHOLDER_SECRETS:
        return key
    if IS_PRODUCTION:
        # Fail closed: a random per-process key means nobody can hold a valid admin session.
        logger.critical("SECRET_KEY is not set. Admin sessions are disabled until it is.")
        return secrets.token_hex(32)
    return "dev-key-change-in-production"


def admin_login_enabled() -> bool:
    """In production the admin panel stays locked until real credentials exist."""
    if not IS_PRODUCTION:
        return True
    if os.environ.get("ADMIN_PASSWORD_HASH"):
        return True
    return os.environ.get("ADMIN_PASSWORD", "") not in _PLACEHOLDER_PASSWORDS


app = Flask(
    __name__,
    template_folder=os.path.join(_API, "templates"),
    static_folder=os.path.join(_API, "static"),
)
app.secret_key = _resolve_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)


class VercelPathMiddleware:
    """Recover the real request path after Vercel's catch-all rewrite.

    vercel.json rewrites every route to /api/index, so PATH_INFO arrives as
    "/api/index". The original path is passed in the __path query parameter
    (and in some forwarded headers); this puts it back.
    """

    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        qs_path = None
        for param in environ.get("QUERY_STRING", "").split("&"):
            if param.startswith("__path="):
                qs_path = unquote(param.split("=", 1)[1])
                break

        # The header and URI candidates are still percent-encoded ("my%20page"), unlike
        # PATH_INFO and the __path parameter above, so decode them once here.
        header_candidates = [
            environ.get("HTTP_X_INVOKE_PATH"),
            environ.get("HTTP_X_FORWARDED_URI"),
            environ.get("HTTP_X_FORWARDED_PATH"),
            environ.get("HTTP_X_REWRITE_URL"),
            environ.get("HTTP_X_ORIGINAL_URL"),
            environ.get("REQUEST_URI"),
            environ.get("RAW_URI"),
            environ.get("HTTP_X_MATCHED_PATH"),
        ]
        candidates = [qs_path] + [unquote(c) if c else c for c in header_candidates]
        real_path = None
        for candidate in candidates:
            if candidate:
                clean = candidate.split("?")[0]
                if clean not in ("/api/index", "/api/index.py", ""):
                    real_path = clean
                    break

        if real_path:
            environ["PATH_INFO"] = real_path
            environ["SCRIPT_NAME"] = ""
        elif environ.get("PATH_INFO") in ("/api/index", "/api/index.py"):
            environ["PATH_INFO"] = "/"
            environ["SCRIPT_NAME"] = ""

        return self.wsgi_app(environ, start_response)


app.wsgi_app = VercelPathMiddleware(app.wsgi_app)
