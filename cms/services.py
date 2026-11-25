"""Site settings, maintenance flag, audit log and visit tracking."""
import hashlib
from datetime import datetime, timedelta

from flask import g, request, session
from pymongo.errors import ConnectionFailure
from user_agents import parse

from . import vault
from .app import SITE_URL, app, logger, utc_now
from .db import note_db_failure
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
    # If the database can't be reached, keep using the last settings this process saw
    # (navigation, site name) rather than dropping back to bare defaults.
    try:
        if g.settings_col is None:
            return _settings_cache or dict(_SETTINGS_DEFAULTS)
        doc = g.settings_col.find_one({"name": "global_config"})
        if not doc:
            return dict(_SETTINGS_DEFAULTS)
        _settings_cache = {**_SETTINGS_DEFAULTS, **doc}
        _settings_expiry = utc_now() + timedelta(seconds=30)
        return _settings_cache
    except ConnectionFailure:
        note_db_failure()
        return _settings_cache or dict(_SETTINGS_DEFAULTS)
    except Exception:
        return _settings_cache or dict(_SETTINGS_DEFAULTS)


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
    # If the database is unreachable, keep the last known state so a site that was in
    # maintenance mode doesn't suddenly look open.
    try:
        if g.settings_col is None:
            return _maint_value
        config = g.settings_col.find_one({"name": "maintenance_mode"})
        active = config.get("active") if config else False
        if isinstance(active, str):
            active = active.lower() == "true"
        _maint_value = bool(active)
        _maint_expiry = utc_now() + timedelta(seconds=10)
        return _maint_value
    except ConnectionFailure:
        note_db_failure()
        return _maint_value
    except Exception:
        return _maint_value


def bust_maintenance_cache():
    global _maint_expiry
    _maint_expiry = datetime.min


# ── Contact form settings ──────────────────────────────────
# Edited in the admin Settings window. The contact page's Python tab reads the same document
# ("contact_settings") on every request, so these are also its fallbacks when nothing is saved.
CONTACT_DEFAULTS = {
    "paused": False,              # hide the form and show the email address instead
    "discord_enabled": True,      # tell the private Discord channel when a message arrives
    "discord_include_message": False,  # also put the sender's email and message text in that alert
    "ip_limit_per_hour": 3,
    "cookie_limit_per_hour": 3,
    "email_limit_per_day": 3,
    "global_limit_per_hour": 30,  # circuit breaker across all visitors
    "min_fill_seconds": 3,        # a form sent faster than this is treated as a bot
    "spam_threshold": 3,          # spam score at which a message is saved as SPAM
}
CONTACT_LIMITS = {
    "ip_limit_per_hour": (1, 50),
    "cookie_limit_per_hour": (1, 50),
    "email_limit_per_day": (1, 50),
    "global_limit_per_hour": (1, 500),
    "min_fill_seconds": (0, 30),
    "spam_threshold": (1, 10),
}


def get_contact_settings() -> dict:
    """Saved contact settings merged over the defaults. Never raises."""
    out = dict(CONTACT_DEFAULTS)
    try:
        if g.settings_col is not None:
            doc = g.settings_col.find_one({"name": "contact_settings"}) or {}
            for key, default in CONTACT_DEFAULTS.items():
                value = doc.get(key)
                if isinstance(default, bool):
                    if isinstance(value, bool):
                        out[key] = value
                elif isinstance(value, int) and not isinstance(value, bool):
                    out[key] = value
    except ConnectionFailure:
        note_db_failure()
    except Exception:
        pass
    return out


# ── Site message: a banner shown at the top of every page (10s in-process cache) ──
SITE_MESSAGE_STYLES = ("info", "notice", "warning", "success")
SITE_MESSAGE_DEFAULTS = {
    "active": False,
    "text": "",
    "link_label": "",
    "link_url": "",
    "style": "info",
    "dismissible": True,
    "until": "",  # optional last day to show it, YYYY-MM-DD (UTC)
}
_sm_doc: dict = {**SITE_MESSAGE_DEFAULTS, "updated_at": None}
_sm_expiry: datetime = datetime.min


def get_site_message_doc() -> dict:
    """The stored site message with defaults filled in, whether or not it is switched on.

    If the database can't be reached this keeps returning the last copy it saw.
    """
    global _sm_doc, _sm_expiry
    if utc_now() < _sm_expiry:
        return _sm_doc
    try:
        if g.settings_col is None:
            return _sm_doc
        doc = g.settings_col.find_one({"name": "site_message"}) or {}
        _sm_doc = {**SITE_MESSAGE_DEFAULTS, **{k: doc[k] for k in SITE_MESSAGE_DEFAULTS if k in doc},
                   "updated_at": doc.get("updated_at")}
        _sm_expiry = utc_now() + timedelta(seconds=10)
    except ConnectionFailure:
        note_db_failure()
    except Exception:
        pass
    return _sm_doc


def get_site_message():
    """The banner to show right now, or None when it is off, empty or past its last day."""
    doc = get_site_message_doc()
    text = (doc.get("text") or "").strip()
    if not doc.get("active") or not text:
        return None
    until = doc.get("until") or ""
    if until:
        try:
            if utc_now().date() > datetime.strptime(until, "%Y-%m-%d").date():
                return None
        except ValueError:
            pass
    # The key changes whenever the message is edited, so people who dismissed an older one see the new one.
    raw = f"{text}|{doc.get('link_url')}|{doc.get('style')}|{doc.get('updated_at')}"
    return {**doc, "text": text, "key": hashlib.sha256(raw.encode()).hexdigest()[:12]}


def bust_site_message_cache():
    global _sm_expiry
    _sm_expiry = datetime.min


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
    raw = f"{client_ip()}{ua}{day_salt}"
    # A keyed code can't be rebuilt by trying every IP address. Without a key, fall back to the plain hash.
    if vault.ready():
        return vault.blind("visitor", raw)
    return hashlib.sha256(raw.encode()).hexdigest()


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
        site_message=get_site_message(),
    )
