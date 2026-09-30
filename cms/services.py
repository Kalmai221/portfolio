"""Site settings, maintenance flag, audit log and visit tracking."""
import hashlib
from datetime import datetime, timedelta

from flask import g, request, session
from user_agents import parse

from .app import SITE_URL, app, logger, utc_now
from .security import client_ip, generate_csrf_token

# ── Settings (30s in-process cache) ────────────────────────
_settings_cache: dict = {}
_settings_expiry: datetime = datetime.min

_SETTINGS_DEFAULTS = {
    "site_name_first": "Kurtis-Lee",
    "site_name_last": "Hopewell",
    "site_description": "IT portfolio of Kurtis-Lee Hopewell: systems, full-stack development and databases.",
    "show_navbar": True,
    "nav_links": [],
}


def get_site_settings() -> dict:
    global _settings_cache, _settings_expiry
    if utc_now() < _settings_expiry and _settings_cache:
        return _settings_cache
    try:
        if g.settings_col is None:
            return dict(_SETTINGS_DEFAULTS)
        doc = g.settings_col.find_one({"name": "global_config"})
        if not doc:
            return dict(_SETTINGS_DEFAULTS)
        _settings_cache = {**_SETTINGS_DEFAULTS, **doc}
        _settings_expiry = utc_now() + timedelta(seconds=30)
        return _settings_cache
    except Exception:
        return dict(_SETTINGS_DEFAULTS)


def bust_settings_cache():
    global _settings_cache, _settings_expiry
    _settings_cache = {}
    _settings_expiry = datetime.min


# ── Maintenance flag (10s in-process cache) ────────────────
_maint_value = False
_maint_expiry: datetime = datetime.min


def is_maintenance_mode() -> bool:
    global _maint_value, _maint_expiry
    if utc_now() < _maint_expiry:
        return _maint_value
    try:
        if g.settings_col is None:
            return False
        config = g.settings_col.find_one({"name": "maintenance_mode"})
        active = config.get("active") if config else False
        if isinstance(active, str):
            active = active.lower() == "true"
        _maint_value = bool(active)
        _maint_expiry = utc_now() + timedelta(seconds=10)
        return _maint_value
    except Exception:
        return False


def bust_maintenance_cache():
    global _maint_expiry
    _maint_expiry = datetime.min


# ── Audit log ──────────────────────────────────────────────
def audit(action: str, detail: str = "", level: str = "info"):
    try:
        if g.audit_col is not None:
            g.audit_col.insert_one({
                "action": action,
                "detail": detail,
                "user": session.get("user", "anonymous"),
                "ip": client_ip(),
                "ua": request.headers.get("User-Agent", ""),
                "timestamp": utc_now(),
                "level": level,
            })
    except Exception as e:
        logger.error(f"Audit log failed: {e}")


# ── Analytics ──────────────────────────────────────────────
_BOT_KEYWORDS = frozenset([
    "bot", "crawler", "spider", "slurp", "lighthouse",
    "googlebot", "google-keyword-suggestion",
    "discordbot", "linkedinbot",
    "bingbot", "bingpreview", "msnbot",
    "vercel", "vercel-screenshot", "vercel-bot",
    "ahrefsbot", "semrushbot", "dotbot", "petalbot",
    "facebookexternalhit", "twitterbot", "whatsapp",
])


def is_bot(ua_string: str) -> bool:
    if parse(ua_string).is_bot:
        return True
    ua_lower = ua_string.lower()
    return any(kw in ua_lower for kw in _BOT_KEYWORDS)


def generate_visitor_hash() -> str:
    """Anonymous fingerprint that rotates daily. The raw IP is never stored."""
    ua = request.headers.get("User-Agent", "unknown")
    day_salt = utc_now().strftime("%Y-%m-%d")
    return hashlib.sha256(f"{client_ip()}{ua}{day_salt}".encode()).hexdigest()


def _referrer_label(custom_ref: str | None) -> str:
    raw_ref = request.referrer or ""
    if request.host in raw_ref and not custom_ref:
        return "Direct / Internal"
    ref_low = raw_ref.lower()
    if custom_ref:
        return f"Campaign: {custom_ref}"
    if "google" in ref_low:
        return "Google Search"
    if "linkedin" in ref_low:
        return "LinkedIn"
    if "github" in ref_low:
        return "GitHub"
    if "twitter" in ref_low or "x.com" in ref_low:
        return "Twitter / X"
    if "reddit" in ref_low:
        return "Reddit"
    if not raw_ref:
        return "Direct Entry"
    return raw_ref.split("//")[-1].split("/")[0]


def log_visit(path: str, status_code: int = 200):
    """Record a page view. Never raises."""
    try:
        if any(path.startswith(x) for x in ["admin", "static", "_preview", "trial"]):
            return
        if path == "favicon.ico":
            return
        if g.analytics_write_col is None:
            return
        ua_string = request.headers.get("User-Agent", "")
        g.analytics_write_col.insert_one({
            "path": path,
            "status_code": status_code,
            "timestamp": utc_now(),
            "visitor_hash": generate_visitor_hash(),
            "referrer": _referrer_label(request.args.get("redirectfrom")),
            "agent": ua_string,
            "is_bot": is_bot(ua_string),
            "country": request.headers.get("X-Vercel-IP-Country") or request.headers.get("CF-IPCountry", ""),
        })
    except Exception as e:
        logger.error(f"log_visit failed: {e}")


# ── Template context ───────────────────────────────────────
@app.context_processor
def inject_globals():
    return dict(
        settings=get_site_settings(),
        now=utc_now(),
        csrf_token=generate_csrf_token,
        site_url=SITE_URL,
    )
