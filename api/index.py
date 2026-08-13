import os
import sys
import io
import json
import hmac
import random
import hashlib
import traceback
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from collections import defaultdict
from threading import Lock

def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

import certifi
import requests
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for,
    abort, session, send_file, send_from_directory,
    render_template_string, jsonify, g
)
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.read_preferences import ReadPreference
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from user_agents import parse

load_dotenv()

# ─────────────────────────────────────────
#  APP SETUP
# ─────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,           # JS cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",          # CSRF mitigation
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,    # 2 MB max upload
)

# ─────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────
#  DATABASE
# ─────────────────────────────────────────
client = None

def get_mongo_client():
    global client
    if client is not None:
        try:
            client.admin.command("ping")
            return client
        except Exception:
            client = None

    uri = os.environ.get("MONGODB_URI")
    if not uri:
        return None
    try:
        c = MongoClient(
            uri,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=5000,
            read_preference=ReadPreference.PRIMARY_PREFERRED,
            retryWrites=True
        )
        c.admin.command("ping")
        logger.info("MongoDB connected successfully with PRIMARY_PREFERRED read preference")
        client = c
        return client
    except Exception as e:
        logger.warning(f"MongoDB connection attempt failed: {e}")
        return None

def get_db():
    """Returns the db handle, or raises 503 if unavailable."""
    c = get_mongo_client()
    if c is None:
        abort(503)
    return c.my_portfolio

@app.before_request
def attach_db():
    """Attach db handle to Flask g for this request."""
    c = get_mongo_client()
    if c is not None:
        try:
            g.db = c.my_portfolio
            g.pages         = g.db.pages
            g.settings_col  = g.db.settings
            g.analytics_col = g.db.analytics
            g.audit_col     = g.db.audit_log
            return
        except Exception as e:
            logger.warning(f"Failed to attach db collections: {e}")
    g.db            = None
    g.pages         = None
    g.settings_col  = None
    g.analytics_col = None
    g.audit_col     = None


# ─────────────────────────────────────────
#  RATE LIMITER  (in-memory, per IP)
# ─────────────────────────────────────────
_rate_store: dict[str, list] = defaultdict(list)
_rate_lock = Lock()

def rate_limit(max_calls: int, window_seconds: int):
    """
    Decorator: limits an endpoint to max_calls within window_seconds per IP.
    Returns 429 when exceeded.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = utc_now().timestamp()
            key = f"{f.__name__}:{ip}"
            with _rate_lock:
                calls = [t for t in _rate_store[key] if now - t < window_seconds]
                if len(calls) >= max_calls:
                    logger.warning(f"Rate limit hit: {key}")
                    return render_template("429.html"), 429
                calls.append(now)
                _rate_store[key] = calls
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────
#  CSRF  (double-submit cookie pattern)
# ─────────────────────────────────────────
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = hashlib.sha256(os.urandom(32)).hexdigest()
    return session["csrf_token"]

def validate_csrf():
    """Call at the top of any state-changing POST handler."""
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
        logger.warning(f"CSRF failure from {request.remote_addr}")
        abort(403)

app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ─────────────────────────────────────────
#  AUDIT LOG
# ─────────────────────────────────────────
def audit(action: str, detail: str = "", level: str = "info"):
    """Persist an admin action to the audit_log collection."""
    try:
        if g.audit_col is not None:
            g.audit_col.insert_one({
                "action":    action,
                "detail":    detail,
                "user":      session.get("user", "anonymous"),
                "ip":        request.remote_addr,
                "ua":        request.headers.get("User-Agent", ""),
                "timestamp": utc_now(),
                "level":     level,
            })
    except Exception as e:
        logger.error(f"Audit log failed: {e}")


# ─────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def _check_account_lockout(ip: str) -> bool:
    """Returns True if this IP is currently locked out."""
    now = utc_now().timestamp()
    key = f"login:{ip}"
    with _rate_lock:
        attempts = [t for t in _rate_store[key] if now - t < 900]  # 15-min window
        return len(attempts) >= 5

def _record_failed_login(ip: str):
    now = utc_now().timestamp()
    key = f"login:{ip}"
    with _rate_lock:
        _rate_store[key].append(now)

def _clear_login_attempts(ip: str):
    with _rate_lock:
        _rate_store.pop(f"login:{ip}", None)


# ─────────────────────────────────────────
#  SETTINGS HELPERS
# ─────────────────────────────────────────
_settings_cache: dict = {}
_settings_cache_expiry: datetime = datetime.min

def get_site_settings() -> dict:
    """Fetches global config from MongoDB with a 30-second in-process cache."""
    global _settings_cache, _settings_cache_expiry
    if utc_now() < _settings_cache_expiry and _settings_cache:
        return _settings_cache

    defaults = {
        "site_name_first": "Kurtis-Lee",
        "site_name_last":  "Hopewell",
        "show_navbar":     True,
        "nav_links":       [],
    }
    try:
        if g.settings_col is None:
            return defaults
        doc = g.settings_col.find_one({"name": "global_config"})
        if not doc:
            return defaults
        result = {**defaults, **doc}
        _settings_cache = result
        _settings_cache_expiry = utc_now() + timedelta(seconds=30)
        return result
    except Exception:
        return defaults

def bust_settings_cache():
    global _settings_cache, _settings_cache_expiry
    _settings_cache = {}
    _settings_cache_expiry = datetime.min

def is_maintenance_mode() -> bool:
    try:
        if g.settings_col is None:
            return False
        config = g.settings_col.find_one({"name": "maintenance_mode"})
        if not config:
            return False
        active = config.get("active")
        if isinstance(active, str):
            return active.lower() == "true"
        return bool(active)
    except Exception:
        return False


# ─────────────────────────────────────────
#  ANALYTICS HELPERS
# ─────────────────────────────────────────
_BOT_KEYWORDS = frozenset([
    "bot", "crawler", "spider", "slurp", "lighthouse",
    "googlebot", "google-keyword-suggestion",
    "discordbot", "linkedinbot",
    "bingbot", "bingpreview", "msnbot",
    "vercel", "vercel-screenshot", "vercel-bot",
    "ahrefsbot", "semrushbot", "dotbot", "petalbot",
    "facebookexternalhit", "twitterbot", "whatsapp",
])

def _is_bot(ua_string: str) -> bool:
    ua = parse(ua_string)
    if ua.is_bot:
        return True
    ua_lower = ua_string.lower()
    return any(kw in ua_lower for kw in _BOT_KEYWORDS)

def generate_visitor_hash() -> str:
    """Anonymous device fingerprint — never stores raw IP."""
    remote_addr = request.remote_addr or "127.0.0.1"
    ua = request.headers.get("User-Agent", "unknown")
    # Salt with a daily value so the hash rotates and isn't linkable across days
    day_salt = utc_now().strftime("%Y-%m-%d")
    fingerprint = f"{remote_addr}{ua}{day_salt}"
    return hashlib.sha256(fingerprint.encode()).hexdigest()

def log_visit(path: str, status_code: int = 200):
    """Fire-and-forget visit logger — never raises."""
    try:
        if any(path.startswith(x) for x in ["admin", "static", "_preview", "trial"]):
            return
        if path == "favicon.ico":
            return

        ua_string = request.headers.get("User-Agent", "")

        # Referrer resolution
        custom_ref  = request.args.get("redirectfrom")
        raw_ref     = request.referrer or ""
        current_host = request.host

        if current_host in raw_ref and not custom_ref:
            final_source = "Direct / Internal"
        else:
            ref_low = raw_ref.lower()
            if custom_ref:                   final_source = f"Campaign: {custom_ref}"
            elif "google"    in ref_low:     final_source = "Google Search"
            elif "linkedin"  in ref_low:     final_source = "LinkedIn"
            elif "github"    in ref_low:     final_source = "GitHub"
            elif "twitter"   in ref_low or "x.com" in ref_low: final_source = "Twitter / X"
            elif "reddit"    in ref_low:     final_source = "Reddit"
            elif not raw_ref:               final_source = "Direct Entry"
            else:                           final_source = raw_ref.split("//")[-1].split("/")[0]

        if g.analytics_col is not None:
            g.analytics_col.insert_one({
                "path":         path,
                "status_code":  status_code,
                "timestamp":    utc_now(),
                "visitor_hash": generate_visitor_hash(),
                "referrer":     final_source,
                "agent":        ua_string,
                "is_bot":       _is_bot(ua_string),
                "country":      request.headers.get("CF-IPCountry", ""),  # Cloudflare header
            })
    except Exception as e:
        logger.error(f"log_visit failed: {e}")


# ─────────────────────────────────────────
#  CONTEXT PROCESSOR
# ─────────────────────────────────────────
@app.context_processor
def inject_globals():
    if request.path.startswith("/trial"):
        _ensure_trial_state()
        trial_settings = session.get("trial_settings", {})
        return dict(
            settings=trial_settings,
            now=utc_now(),
            csrf_token=generate_csrf_token,
            is_trial=True
        )
    return dict(
        settings=get_site_settings(),
        now=utc_now(),
        csrf_token=generate_csrf_token,
        is_trial=False
    )


# ─────────────────────────────────────────
#  SECURITY HEADERS
# ─────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "SAMEORIGIN"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]      = "camera=(), microphone=(), geolocation=()"
    if os.environ.get("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# ─────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
@rate_limit(10, 60)
def login():
    if "user" in session:
        return redirect(url_for("admin_dashboard"))

    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"

        # Account lockout check
        if _check_account_lockout(ip):
            logger.warning(f"Locked out login attempt from {ip}")
            return render_template("login.html", error="Too many failed attempts. Try again in 15 minutes."), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin_user = os.environ.get("ADMIN_USERNAME", "admin")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "password")

        # Constant-time comparison (mitigates timing attacks)
        user_ok = hmac.compare_digest(username, admin_user)
        pass_ok = hmac.compare_digest(password, admin_pass)

        if user_ok and pass_ok:
            _clear_login_attempts(ip)
            session.clear()                          # Prevent session fixation
            session.permanent = True
            session["user"] = username
            session["login_at"] = utc_now().isoformat()
            audit("login", f"Successful login from {ip}")
            next_page = request.args.get("next") or url_for("admin_dashboard")
            # Safety: only redirect to internal paths
            if not next_page.startswith("/"):
                next_page = url_for("admin_dashboard")
            return redirect(next_page)
        else:
            _record_failed_login(ip)
            audit("login_fail", f"Failed login for '{username}' from {ip}", level="warn")
            error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────
#  ADMIN DASHBOARD
# ─────────────────────────────────────────
@app.route("/admin")
@login_required
def admin_dashboard():
    all_pages = list(g.pages.find().sort("updated_at", DESCENDING)) if g.pages is not None else []
    total_hits = g.analytics_col.count_documents({"status_code": 200}) if g.analytics_col is not None else 0
    return render_template(
        "admin.html",
        pages=all_pages,
        maintenance_active=is_maintenance_mode(),
        total_hits=total_hits,
    )


# ─────────────────────────────────────────
#  SETTINGS
# ─────────────────────────────────────────
@app.route("/admin/update-settings", methods=["POST"])
@login_required
def update_settings():
    if g.settings_col is None:
        return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
    validate_csrf()
    data = {
        "site_name_first": request.form.get("site_name_first", "").strip()[:40] or "Kurtis-Lee",
        "site_name_last":  request.form.get("site_name_last",  "").strip()[:40] or "Hopewell",
        "show_navbar":     request.form.get("show_navbar") == "true",
        "updated_at":      utc_now(),
    }
    g.settings_col.update_one({"name": "global_config"}, {"$set": data}, upsert=True)
    bust_settings_cache()
    audit("settings_update", str(data))
    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────
#  NAV LINKS
# ─────────────────────────────────────────
_ALLOWED_SCHEMES = ("http://", "https://", "/")

def _sanitise_nav_url(url: str) -> str | None:
    """Returns a safe URL or None if it's suspicious."""
    url = url.strip()
    if not url:
        return None
    # Reject javascript:, data:, etc.
    if not any(url.startswith(s) for s in _ALLOWED_SCHEMES):
        if "." in url and not url.startswith("/"):
            url = f"https://{url}"
        else:
            return None
    return url

@app.route("/admin/add-nav", methods=["POST"])
@login_required
def add_nav_link():
    if g.settings_col is None:
        return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
    validate_csrf()
    label = request.form.get("label", "").strip()[:30]
    url   = _sanitise_nav_url(request.form.get("url", ""))

    if not label or not url:
        return redirect(url_for("admin_dashboard"))

    config = g.settings_col.find_one({"name": "global_config"}) or {}
    links  = config.get("nav_links", [])

    # Slot cap & duplicate check
    if len(links) >= 8:
        return redirect(url_for("admin_dashboard"))
    if any(link.get("url", "").lower() == url.lower() for link in links):
        return redirect(url_for("admin_dashboard"))

    g.settings_col.update_one(
        {"name": "global_config"},
        {"$push": {"nav_links": {"label": label, "url": url}}},
        upsert=True,
    )
    bust_settings_cache()
    audit("nav_add", f"label={label} url={url}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-nav/<int:index>")
@login_required
def delete_nav_link(index):
    if g.settings_col is None:
        return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
    settings = get_site_settings()
    links = settings.get("nav_links", [])
    if 0 <= index < len(links):
        removed = links.pop(index)
        g.settings_col.update_one(
            {"name": "global_config"},
            {"$set": {"nav_links": links}},
        )
        bust_settings_cache()
        audit("nav_delete", f"index={index} label={removed.get('label')}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/api/reorder-nav", methods=["POST"])
@login_required
def api_reorder_nav():
    if g.settings_col is None:
        return jsonify(error="DB unavailable"), 503
    data = request.get_json(silent=True)
    if not data or "nav_links" not in data:
        return jsonify(error="Invalid payload"), 400

    # Re-validate every link before saving
    clean = []
    for item in data["nav_links"][:8]:
        label = str(item.get("label", "")).strip()[:30]
        url   = _sanitise_nav_url(str(item.get("url", "")))
        if label and url:
            clean.append({"label": label, "url": url})

    g.settings_col.update_one(
        {"name": "global_config"},
        {"$set": {"nav_links": clean}},
        upsert=True,
    )
    bust_settings_cache()
    audit("nav_reorder")
    return jsonify(status="ok"), 200


# ─────────────────────────────────────────
#  MAINTENANCE
# ─────────────────────────────────────────
@app.route("/admin/toggle-maintenance")
@login_required
def toggle_maintenance():
    if g.settings_col is None:
        return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
    current = is_maintenance_mode()
    g.settings_col.update_one(
        {"name": "maintenance_mode"},
        {"$set": {"active": not current, "updated_at": utc_now()}},
        upsert=True,
    )
    audit("maintenance_toggle", f"new_state={not current}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bypass-maintenance")
@login_required
def bypass_maintenance():
    session["maintenance_bypass"] = True
    return redirect(request.referrer or url_for("cms_router"))


# ─────────────────────────────────────────
#  PAGE EDITOR
# ─────────────────────────────────────────
@app.route("/admin/edit/<path:slug>", methods=["GET", "POST"])
@login_required
def edit_page(slug):
    if g.pages is None:
        return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
    slug = slug.strip("/").lower()

    if request.method == "POST":
        validate_csrf()
        new_slug = request.form.get("slug", slug).strip("/").lower()

        # Prevent slug hijack to reserved paths
        reserved = {"admin", "login", "logout", "static", "_preview", "sitemap.xml", "robots.txt"}
        if new_slug in reserved:
            return redirect(url_for("edit_page", slug=slug))

        data = {
            "slug":         new_slug,
            "title":        (request.form.get("title") or "Untitled")[:100],
            "content":      request.form.get("content", ""),
            "css":          request.form.get("css_content", ""),
            "js":           request.form.get("js_content", ""),
            "python_logic": request.form.get("python_logic", ""),
            "updated_at":   utc_now(),
            "updated_by":   session.get("user"),
        }
        g.pages.update_one({"slug": slug}, {"$set": data}, upsert=True)
        audit("page_save", f"slug={new_slug}")
        return redirect(url_for("admin_dashboard"))

    page = g.pages.find_one({"slug": slug})
    snippet_data = _load_snippets()
    return render_template("edit_page.html", page=page, slug=slug, snippets=snippet_data)


def _load_snippets() -> dict:
    path = os.path.join(app.root_path, "static", "data", "snippets.json")
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Could not load snippets: {e}")
    return {}


@app.route("/admin/delete/<path:slug>")
@login_required
def delete_page(slug):
    if g.pages is None:
        return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
    slug = slug.strip("/").lower()
    g.pages.delete_one({"slug": slug})
    audit("page_delete", f"slug={slug}", level="warn")
    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────
#  AUDIT LOG VIEWER
# ─────────────────────────────────────────
@app.route("/admin/audit")
@login_required
def admin_audit():
    """Shows the last 200 audit events."""
    entries = list(
        g.audit_col.find().sort("timestamp", DESCENDING).limit(200)
    ) if g.audit_col is not None else []
    return render_template("audit.html", entries=entries)


# ─────────────────────────────────────────
#  ANALYTICS
# ─────────────────────────────────────────
@app.route("/admin/analytics")
@login_required
def admin_analytics():
    now = utc_now()

    # ── Inputs ──
    time_range  = request.args.get("range", "7d")
    target_date = request.args.get("date")
    show_bots   = request.args.get("bots") == "true"

    # ── Time window ──
    if target_date:
        try:
            parsed_date = datetime.strptime(f"{target_date} {now.year}", "%b %d %Y")
            start_date, end_date = parsed_date, parsed_date + timedelta(days=1)
            display_range, date_format, steps, delta_unit = (
                f"Drill-down: {target_date}", "%Y-%m-%d %H:00", 23, "hours"
            )
        except ValueError:
            start_date, end_date = now - timedelta(days=7), now
            display_range, date_format, steps, delta_unit = "7d", "%Y-%m-%d", 7, "days"
    elif time_range == "24h":
        start_date, end_date = now - timedelta(hours=24), now
        display_range, date_format, steps, delta_unit = "24h", "%Y-%m-%d %H:00", 24, "hours"
    elif time_range == "4w":
        start_date, end_date = now - timedelta(weeks=4), now
        display_range, date_format, steps, delta_unit = "4w", "%Y-%m-%d", 28, "days"
    elif time_range == "all":
        first = g.analytics_col.find_one({"status_code": 200}, sort=[("timestamp", ASCENDING)])
        start_date = first["timestamp"] if first else now - timedelta(days=365)
        end_date, display_range, date_format = now, "All Time", "%Y-%m-%d"
        delta = end_date - start_date
        steps, delta_unit = delta.days, "days"
    else:  # 7d default
        start_date, end_date = now - timedelta(days=7), now
        display_range, date_format, steps, delta_unit = "7d", "%Y-%m-%d", 7, "days"

    # ── Filters ──
    valid_filters = ["path", "referrer", "browser", "os", "device", "country"]
    active_filters = {k: request.args.get(k) for k in valid_filters if request.args.get(k)}

    base_filter = {
        "status_code": 200,
        "timestamp":   {"$gte": start_date, "$lt": end_date},
    }
    if not show_bots:
        base_filter["is_bot"] = {"$ne": True}
    if "path"     in active_filters: base_filter["path"]     = active_filters["path"]
    if "referrer" in active_filters: base_filter["referrer"] = active_filters["referrer"]
    if "country"  in active_filters: base_filter["country"]  = active_filters["country"]

    # ── Chart pipeline ──
    raw_results = list(g.analytics_col.aggregate([
        {"$match": base_filter},
        {"$group": {
            "_id":   {"$dateToString": {"format": date_format, "date": "$timestamp"}},
            "logs":  {"$push": "$agent"},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ]))

    # Build a dict and apply browser/os/device filters
    raw_graph: dict[str, int] = {}
    for entry in raw_results:
        key = entry["_id"]
        count = 0
        for agent in entry["logs"]:
            ua = parse(agent or "")
            browser = ua.browser.family
            os_fam  = ua.os.family
            device  = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"
            if "browser" in active_filters and active_filters["browser"] != browser: continue
            if "os"      in active_filters and active_filters["os"]      != os_fam:  continue
            if "device"  in active_filters and active_filters["device"]  != device:  continue
            count += 1
        raw_graph[key] = count

    # ── Labels & values ──
    chart_labels, chart_values = [], []
    for i in range(steps, -1, -1):
        dt  = end_date - (timedelta(hours=i) if delta_unit == "hours" else timedelta(days=i))
        key = dt.strftime(date_format)
        chart_labels.append(dt.strftime("%b %d %H:00") if delta_unit == "hours" else dt.strftime("%b %d"))
        chart_values.append(raw_graph.get(key, 0))

    # ── Sidebar aggregation ──
    unique_visitors = len(g.analytics_col.distinct("visitor_hash", base_filter))
    online_count    = len(g.analytics_col.distinct(
        "visitor_hash",
        {"timestamp": {"$gt": now - timedelta(minutes=5)}}
    ))

    stats = {
        "browsers": {}, "os": {}, "devices": {},
        "referrers": {}, "referrers_detailed": {}, "countries": {},
    }
    logs = list(g.analytics_col.find(base_filter))
    filtered_count = 0

    for log in logs:
        ua      = parse(log.get("agent") or "")
        browser = ua.browser.family
        os_fam  = ua.os.family
        device  = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"
        country = log.get("country", "Unknown") or "Unknown"

        if "browser" in active_filters and active_filters["browser"] != browser: continue
        if "os"      in active_filters and active_filters["os"]      != os_fam:  continue
        if "device"  in active_filters and active_filters["device"]  != device:  continue

        filtered_count += 1
        stats["browsers"][browser]  = stats["browsers"].get(browser, 0) + 1
        stats["os"][os_fam]         = stats["os"].get(os_fam, 0) + 1
        stats["devices"][device]    = stats["devices"].get(device, 0) + 1
        stats["countries"][country] = stats["countries"].get(country, 0) + 1

        ref = log.get("referrer", "Direct Entry")
        stats["referrers"][ref] = stats["referrers"].get(ref, 0) + 1
        if ref not in stats["referrers_detailed"]:
            stats["referrers_detailed"][ref] = {"count": 0, "url": log.get("full_referrer_url", "")}
        stats["referrers_detailed"][ref]["count"] += 1

    # ── Top pages & errors ──
    top_pages = list(g.analytics_col.aggregate([
        {"$match": base_filter},
        {"$group": {"_id": "$path", "count": {"$sum": 1}}},
        {"$sort": {"count": DESCENDING}},
        {"$limit": 10},
    ]))

    error_logs = list(g.analytics_col.find(
        {"status_code": {"$gte": 400}, "timestamp": {"$gte": start_date, "$lt": end_date}}
    ).sort("timestamp", DESCENDING).limit(20))

    # ── Filter helpers (preserve all current params) ──
    def _base_params():
        p = {k: v for k, v in active_filters.items() if k != "bots"}
        p["range"] = time_range
        p["bots"]  = "true" if show_bots else "false"
        if target_date:
            p["date"] = target_date
        return p

    def add_filter(new_type, new_val):
        p = _base_params()
        p[new_type] = new_val
        return p

    def remove_filter(type_to_remove):
        p = _base_params()
        p.pop(type_to_remove, None)
        return p

    return render_template(
        "analytics.html",
        total_hits=filtered_count,
        unique_visitors=unique_visitors,
        online_count=online_count,
        chart_labels=chart_labels,
        chart_values=chart_values,
        stats=stats,
        top_pages=top_pages,
        error_logs=error_logs,
        active_filters=active_filters,
        active_range=display_range,
        delta_unit=delta_unit,
        target_date=target_date,
        add_filter=add_filter,
        remove_filter=remove_filter,
    )


# ─────────────────────────────────────────
#  PREVIEW
# ─────────────────────────────────────────
def render_preview_helper(content, css, js, logic, base_context=None):
    context = dict(base_context or {})

    if logic:
        try:
            exec(logic, {"__builtins__": __builtins__}, context)
        except Exception as e:
            exc_tb = traceback.format_exc()
            tb_lines = traceback.extract_tb(sys.exc_info()[2])
            line_no  = tb_lines[-1].lineno if tb_lines else "?"
            return f"""<!DOCTYPE html><html style="background:#09090b"><head><meta charset="UTF-8">
            <style>
                body{{font-family:monospace;margin:0;background:#09090b;display:flex;align-items:center;justify-content:center;min-height:100vh}}
                .card{{background:#111;border:1px solid #450a0a;border-radius:10px;overflow:hidden;max-width:700px;width:100%;margin:20px}}
                .hd{{background:#450a0a;padding:12px 20px;display:flex;justify-content:space-between;border-bottom:1px solid #991b1b}}
                .hd span{{color:#fff;font-size:11px;font-weight:bold;text-transform:uppercase;letter-spacing:.08em}}
                .bd{{padding:24px}}.etype{{color:#f87171;font-size:16px;font-weight:bold;margin-bottom:4px}}
                .emsg{{color:#a1a1aa;font-size:13px;line-height:1.5;margin-bottom:18px}}
                .trace{{background:#000;border:1px solid #27272a;border-radius:6px;padding:14px;font-size:10px;color:#71717a;line-height:1.6;white-space:pre-wrap;overflow-x:auto}}
            </style></head><body>
            <div class="card">
                <div class="hd"><span>⚠ Runtime Exception</span><span style="color:#f87171">Line {line_no}</span></div>
                <div class="bd">
                    <div class="etype">{type(e).__name__}</div>
                    <div class="emsg">{str(e)}</div>
                    <div class="trace">{exc_tb}</div>
                </div>
            </div></body></html>"""

    full_html = f"""<!DOCTYPE html>
<html class="dark" style="background:#000;margin:0;padding:0">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        html,body{{background:#000;color:#a1a1aa;min-height:100vh;margin:0;padding:0}}
        ::-webkit-scrollbar{{width:8px;height:8px}}
        ::-webkit-scrollbar-track{{background:#000}}
        ::-webkit-scrollbar-thumb{{background:rgba(121,121,121,.25);border:2px solid #000;border-radius:10px}}
        ::-webkit-scrollbar-thumb:hover{{background:rgba(121,121,121,.45)}}
        {css}
    </style>
</head>
<body style="margin:0;padding:0">
    {content}
    <script>{js}</script>
</body>
</html>"""

    try:
        return render_template_string(full_html, **context)
    except Exception as e:
        return f"<div style='background:#111;color:orange;padding:20px;font-family:monospace'>Template Error: {e}</div>"


@app.route("/_preview", methods=["GET", "POST"])
def preview_node():
    if "user" not in session and "trial_pages" not in session:
        abort(403)

    base_ctx = {
        "session":  session,
        "request":  request,
        "datetime": datetime,
        "now":      utc_now(),
    }

    if request.method == "GET":
        slug = request.args.get("target_slug", "home")
        page = g.pages.find_one({"slug": slug}) if g.pages is not None else None
        if not page:
            return "Node not found", 404
        return render_preview_helper(
            content=page.get("content", ""),
            css=page.get("css", ""),
            js=page.get("js", ""),
            logic=page.get("python_logic", ""),
            base_context=base_ctx,
        )

    return render_preview_helper(
        content=request.form.get("content", ""),
        css=request.form.get("css", ""),
        js=request.form.get("js", ""),
        logic=request.form.get("python_logic", ""),
        base_context=base_ctx,
    )


# ─────────────────────────────────────────
#  CMS ROUTER
# ─────────────────────────────────────────
@app.route("/", defaults={"path": "home"}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def cms_router(path):
    if path == "admin":
        return redirect(url_for("admin_dashboard"))

    is_admin  = "user" in session
    has_bypass = session.get("maintenance_bypass", False)
    global_maint = is_maintenance_mode()

    if global_maint and not (is_admin and has_bypass):
        return render_template("503.html", maintenance_active=True), 503

    try:
        page = g.pages.find_one({"slug": path}) if g.pages is not None else None
        if not page and path in DEFAULT_TRIAL_PAGES:
            page = DEFAULT_TRIAL_PAGES[path]

        if page:
            maint_val = page.get("maintenance", False)
            is_under_maint = maint_val.lower() == "true" if isinstance(maint_val, str) else bool(maint_val)

            if is_under_maint and not (is_admin and has_bypass):
                return render_template("page_maintenance.html", page=page, maintenance_active=True), 503

            log_visit(path, 200)

            ctx = {
                "db":               g.db,
                "session":          session,
                "request":          request,
                "datetime":         datetime,
                "timedelta":        timedelta,
                "page":             page,
                "maintenance_active": global_maint or is_under_maint,
            }

            if page.get("python_logic"):
                try:
                    exec(page["python_logic"], {"__builtins__": __builtins__}, ctx)
                except Exception as e:
                    log_visit(path, 500)
                    ctx["logic_error"]     = str(e)
                    ctx["error_traceback"] = traceback.format_exc()
                    logger.error(f"Logic exec error on /{path}: {e}")

            rendered = render_template_string(page.get("content", ""), **ctx)
            return render_template("page.html", rendered_node_content=rendered, **ctx)

    except (ConnectionFailure, ServerSelectionTimeoutError) as db_err:
        logger.critical(f"DB error serving /{path}: {db_err}")
        return render_template("503.html", maintenance_active=False), 503

    except Exception as e:
        logger.error(f"CMS router failure on /{path}: {e}")
        traceback.print_exc()
        return render_template("503.html", maintenance_active=global_maint), 503

    log_visit(path, 404)
    abort(404)


# ─────────────────────────────────────────
#  TRIAL (100% session-backed local demo)
# ─────────────────────────────────────────
DEFAULT_TRIAL_PAGES = {
    "home": {
        "title": "Home",
        "content": """<div class="space-y-12">
    <div class="relative p-8 md:p-12 rounded-2xl bg-zinc-900/60 border border-zinc-800 backdrop-blur-xl overflow-hidden">
        <div class="absolute -top-24 -right-24 w-72 h-72 bg-brand/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="relative z-10 space-y-6">
            <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand/10 border border-brand/20 text-brand text-xs font-mono font-medium">
                <span class="w-2 h-2 rounded-full bg-brand animate-ping"></span>
                <span>Session-Local Sandbox Active</span>
            </div>
            <h1 class="text-3xl md:text-5xl font-extrabold text-zinc-100 tracking-tight font-mono">
                Welcome to <span class="text-brand">Trial Mode</span>
            </h1>
            <p class="text-zinc-400 text-sm md:text-base max-w-2xl leading-relaxed">
                You are exploring a 100% local, session-isolated environment. All changes to nodes, navigation links, and settings persist solely in your browser session without touching any external database.
            </p>
            <div class="flex flex-wrap gap-4 pt-2">
                <a href="/trial" class="btn btn-primary text-xs uppercase font-bold tracking-widest px-6 py-3">Control Panel</a>
                <a href="/trial/edit/home" class="btn border border-zinc-700 bg-zinc-900 text-zinc-200 hover:border-zinc-500 text-xs uppercase font-bold tracking-widest px-6 py-3">Edit This Node</a>
            </div>
        </div>
    </div>
    
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div class="p-6 bg-zinc-900/40 border border-zinc-800 rounded-xl space-y-3">
            <div class="w-10 h-10 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center text-brand">
                <i class="fa-solid fa-code text-lg"></i>
            </div>
            <h3 class="text-zinc-100 font-bold text-base">Node IDE Editor</h3>
            <p class="text-zinc-500 text-xs leading-relaxed">Full HTML, CSS, and JS editor with real-time preview modal and code snippets.</p>
        </div>
        <div class="p-6 bg-zinc-900/40 border border-zinc-800 rounded-xl space-y-3">
            <div class="w-10 h-10 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center text-emerald-400">
                <i class="fa-solid fa-chart-line text-lg"></i>
            </div>
            <h3 class="text-zinc-100 font-bold text-base">Local Analytics</h3>
            <p class="text-zinc-500 text-xs leading-relaxed">Simulated traffic analytics charts, referrer statistics, and device breakdowns.</p>
        </div>
        <div class="p-6 bg-zinc-900/40 border border-zinc-800 rounded-xl space-y-3">
            <div class="w-10 h-10 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center text-amber-400">
                <i class="fa-solid fa-shield-halved text-lg"></i>
            </div>
            <h3 class="text-zinc-100 font-bold text-base">Local Security & Logs</h3>
            <p class="text-zinc-500 text-xs leading-relaxed">Local maintenance locking, drag-and-drop navigation management, and audit trailing.</p>
        </div>
    </div>
</div>""",
        "css": "/* Local node CSS */",
        "js": "// Local node JavaScript\nconsole.log('Trial Home Node Initialized');",
        "updated_at": utc_now().isoformat(),
    },
    "about": {
        "title": "About Me",
        "content": """<div class="space-y-8">
    <div class="border-b border-zinc-800 pb-6">
        <h1 class="text-3xl font-bold font-mono text-zinc-100">About Kurtis-Lee Hopewell</h1>
        <p class="text-zinc-500 text-xs font-mono mt-1">// Full-Stack Developer & Systems Architect</p>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div class="space-y-4">
            <p class="text-zinc-400 text-sm leading-relaxed">
                Experienced software developer specializing in Python, Flask, MongoDB, and modern web application development. Passionate about high-performance serverless architectures and elegant UI design systems.
            </p>
            <div class="space-y-2">
                <h4 class="text-xs font-mono font-bold uppercase tracking-widest text-zinc-500">Core Stack</h4>
                <div class="flex flex-wrap gap-2">
                    <span class="px-3 py-1 bg-zinc-900 border border-zinc-800 rounded text-xs font-mono text-zinc-300">Python / Flask</span>
                    <span class="px-3 py-1 bg-zinc-900 border border-zinc-800 rounded text-xs font-mono text-zinc-300">MongoDB Atlas</span>
                    <span class="px-3 py-1 bg-zinc-900 border border-zinc-800 rounded text-xs font-mono text-zinc-300">JavaScript / ES6+</span>
                    <span class="px-3 py-1 bg-zinc-900 border border-zinc-800 rounded text-xs font-mono text-zinc-300">Tailwind CSS</span>
                </div>
            </div>
        </div>
        <div class="bg-zinc-900/50 border border-zinc-800 rounded-xl p-6 space-y-4">
            <h3 class="text-sm font-bold font-mono uppercase tracking-widest text-zinc-300">Experience Highlights</h3>
            <ul class="space-y-3 text-xs text-zinc-400 font-mono">
                <li class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full bg-brand"></span> Built NoSQL Serverless CMS Engine</li>
                <li class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Engineered Privacy-First Analytics Pipeline</li>
                <li class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full bg-indigo-400"></span> Designed IDE Code Editor Interface</li>
            </ul>
        </div>
    </div>
</div>""",
        "css": "",
        "js": "",
        "updated_at": utc_now().isoformat(),
    },
    "projects": {
        "title": "Projects Showcase",
        "content": """<div class="space-y-8">
    <div class="border-b border-zinc-800 pb-6">
        <h1 class="text-3xl font-bold font-mono text-zinc-100">Featured Projects</h1>
        <p class="text-zinc-500 text-xs font-mono mt-1">// Selected works and architecture demonstrations</p>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="p-6 bg-zinc-900 border border-zinc-800 rounded-xl hover:border-zinc-700 transition-colors space-y-4">
            <div class="flex justify-between items-start">
                <h3 class="text-lg font-bold text-zinc-100">NoSQL CMS Engine</h3>
                <span class="text-[10px] font-mono px-2 py-0.5 bg-brand/10 border border-brand/20 text-brand rounded">v2.0</span>
            </div>
            <p class="text-xs text-zinc-400 leading-relaxed">Serverless Flask and MongoDB powered content management system with browser IDE and session trial demo.</p>
            <div class="flex gap-2 text-xs font-mono text-zinc-500">
                <span>#python</span> <span>#mongodb</span> <span>#flask</span>
            </div>
        </div>
        <div class="p-6 bg-zinc-900 border border-zinc-800 rounded-xl hover:border-zinc-700 transition-colors space-y-4">
            <div class="flex justify-between items-start">
                <h3 class="text-lg font-bold text-zinc-100">Privacy Analytics Core</h3>
                <span class="text-[10px] font-mono px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded">Active</span>
            </div>
            <p class="text-xs text-zinc-400 leading-relaxed">Anonymized fingerprint-hash visitor tracker and analytics breakdown without third-party cookies.</p>
            <div class="flex gap-2 text-xs font-mono text-zinc-500">
                <span>#analytics</span> <span>#security</span> <span>#crypto</span>
            </div>
        </div>
    </div>
</div>""",
        "css": "",
        "js": "",
        "updated_at": utc_now().isoformat(),
    },
    "contact": {
        "title": "Contact",
        "content": """<div class="max-w-2xl mx-auto space-y-8">
    <div class="text-center space-y-2">
        <h1 class="text-3xl font-bold font-mono text-zinc-100">Get In Touch</h1>
        <p class="text-zinc-500 text-xs font-mono">// Send a direct message or connect via professional networks</p>
    </div>
    <div class="p-8 bg-zinc-900 border border-zinc-800 rounded-xl space-y-6">
        <form onsubmit="alert('Trial mode form submitted locally!'); return false;" class="space-y-4">
            <div class="space-y-1">
                <label class="text-[10px] font-mono text-zinc-500 uppercase font-bold">Your Name</label>
                <input type="text" required placeholder="Jane Doe" class="w-full bg-zinc-950 border border-zinc-800 rounded px-4 py-2.5 text-sm text-zinc-200 outline-none focus:border-brand">
            </div>
            <div class="space-y-1">
                <label class="text-[10px] font-mono text-zinc-500 uppercase font-bold">Email Address</label>
                <input type="email" required placeholder="jane@example.com" class="w-full bg-zinc-950 border border-zinc-800 rounded px-4 py-2.5 text-sm text-zinc-200 outline-none focus:border-brand">
            </div>
            <div class="space-y-1">
                <label class="text-[10px] font-mono text-zinc-500 uppercase font-bold">Message</label>
                <textarea rows="4" required placeholder="Write your message..." class="w-full bg-zinc-950 border border-zinc-800 rounded px-4 py-2.5 text-sm text-zinc-200 outline-none focus:border-brand font-mono text-xs"></textarea>
            </div>
            <button type="submit" class="w-full btn btn-primary py-3 text-xs uppercase font-bold tracking-widest">Send Message (Local)</button>
        </form>
    </div>
</div>""",
        "css": "",
        "js": "",
        "updated_at": utc_now().isoformat(),
    }
}

def _ensure_trial_state():
    now = utc_now()
    if "trial_pages" not in session or not session["trial_pages"]:
        session["trial_pages"] = {k: dict(v) for k, v in DEFAULT_TRIAL_PAGES.items()}
    session.setdefault("trial_maintenance", False)
    session.setdefault("trial_seed", random.randint(1, 10**9))
    if "trial_started_at" not in session:
        session["trial_started_at"] = now.isoformat()
    if "trial_expires" not in session:
        session["trial_expires"] = (now + timedelta(hours=24)).isoformat()
    if "trial_nav_links" not in session:
        session["trial_nav_links"] = [
            {"label": "Home", "url": "/trial/view/home"},
            {"label": "About", "url": "/trial/view/about"},
            {"label": "Projects", "url": "/trial/view/projects"},
            {"label": "Contact", "url": "/trial/view/contact"},
        ]
    if "trial_settings" not in session:
        session["trial_settings"] = {
            "site_name_first": "Kurtis-Lee",
            "site_name_last": "Hopewell",
            "show_navbar": True,
            "nav_links": session["trial_nav_links"]
        }
    if "trial_audit" not in session:
        session["trial_audit"] = [
            {
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
                "action": "trial_init",
                "detail": "Trial session initialized with 4 sample nodes",
                "user": "trial_guest",
                "level": "info"
            }
        ]

def _add_trial_audit(action: str, detail: str = "", level: str = "info"):
    _ensure_trial_state()
    audit_list = session.get("trial_audit", [])
    audit_list.insert(0, {
        "timestamp": utc_now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "detail": detail,
        "user": "trial_guest",
        "level": level
    })
    session["trial_audit"] = audit_list[:100]

def _get_trial_pages_list():
    _ensure_trial_state()
    pages = []
    for slug, p in session.get("trial_pages", {}).items():
        updated_at = None
        try:
            if p.get("updated_at"):
                updated_at = datetime.fromisoformat(p["updated_at"])
        except Exception:
            pass
        pages.append({
            "slug":         slug,
            "title":        p.get("title", "(untitled)"),
            "content":      p.get("content", ""),
            "css":          p.get("css", ""),
            "js":           p.get("js", ""),
            "python_logic": "",  # Never expose python logic in trial
            "updated_at":   updated_at,
        })
    return pages

def _generate_fake_analytics():
    _ensure_trial_state()
    rng = random.Random(session.get("trial_seed"))
    now = utc_now()
    labels, values = [], []
    for i in range(7, -1, -1):
        d = now - timedelta(days=i)
        labels.append(d.strftime("%b %d"))
        base = max(1, len(session.get("trial_pages", {})))
        values.append(base * rng.randint(12, 45))
    browsers = {"Chrome": rng.randint(25, 60), "Firefox": rng.randint(10, 25), "Safari": rng.randint(8, 20), "Edge": rng.randint(4, 12)}
    os_data  = {"Windows": rng.randint(30, 70), "macOS": rng.randint(15, 35), "Linux": rng.randint(5, 15), "iOS/Android": rng.randint(10, 25)}
    return {
        "chart_labels": labels,
        "chart_values": values,
        "stats": {
            "browsers": browsers,
            "os": os_data,
            "devices": {"Desktop": rng.randint(40, 80), "Mobile": rng.randint(15, 40), "Tablet": rng.randint(2, 8)},
            "referrers": {"Direct Entry": rng.randint(30, 60), "Google Search": rng.randint(15, 35), "GitHub": rng.randint(10, 25), "LinkedIn": rng.randint(5, 15)},
            "referrers_detailed": {"Direct Entry": {"count": rng.randint(30, 60), "url": ""}},
            "countries": {"United Kingdom": rng.randint(25, 50), "United States": rng.randint(20, 45), "Germany": rng.randint(5, 15), "Canada": rng.randint(3, 10)},
        },
        "top_pages":  [{"_id": f"/trial/view/{s}", "count": rng.randint(10, 80)} for s in session.get("trial_pages", {})],
        "error_logs": [
            {"timestamp": (now - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S"), "path": "/trial/view/non-existent", "status_code": 404, "agent": "Mozilla/5.0 (Trial Engine)"}
        ],
        "total_hits": sum(values),
    }

@app.before_request
def _clear_expired_trial():
    try:
        if "trial_expires" in session:
            if utc_now() > datetime.fromisoformat(session["trial_expires"]):
                for k in ["trial_pages", "trial_maintenance", "trial_seed", "trial_expires", "trial_started_at", "trial_nav_links", "trial_settings", "trial_audit"]:
                    session.pop(k, None)
    except Exception:
        pass

@app.route("/trial")
def trial_dashboard():
    _ensure_trial_state()
    fake = _generate_fake_analytics()
    return render_template(
        "trial_admin.html",
        pages=_get_trial_pages_list(),
        maintenance_active=session.get("trial_maintenance", False),
        total_hits=fake["total_hits"],
    )

@app.route("/trial/edit/<path:slug>", methods=["GET", "POST"])
def trial_edit(slug):
    _ensure_trial_state()
    slug = slug.strip("/").lower()
    if request.method == "POST":
        trial_pages = session.get("trial_pages", {})
        new_slug = request.form.get("slug", slug).strip("/").lower()
        title = (request.form.get("title") or "Untitled Node")[:100]
        content = request.form.get("content", "")
        css = request.form.get("css_content", "")
        js = request.form.get("js_content", "")

        if slug != new_slug and slug in trial_pages:
            trial_pages.pop(slug, None)

        trial_pages[new_slug] = {
            "title": title,
            "content": content,
            "css": css,
            "js": js,
            "updated_at": utc_now().isoformat(),
        }
        session["trial_pages"] = trial_pages
        _add_trial_audit("trial_page_save", f"slug={new_slug} title={title}")
        return redirect(url_for("trial_dashboard"))

    page = session.get("trial_pages", {}).get(slug)
    return render_template("trial_edit_page.html", page=page, slug=slug, snippets=_load_snippets())

@app.route("/trial/delete/<path:slug>")
def trial_delete(slug):
    _ensure_trial_state()
    slug = slug.strip("/").lower()
    trial_pages = session.get("trial_pages", {})
    trial_pages.pop(slug, None)
    session["trial_pages"] = trial_pages
    _add_trial_audit("trial_page_delete", f"slug={slug}", level="warn")
    return redirect(url_for("trial_dashboard"))

@app.route("/trial/toggle-maintenance")
def trial_toggle_maintenance():
    _ensure_trial_state()
    new_state = not session.get("trial_maintenance", False)
    session["trial_maintenance"] = new_state
    _add_trial_audit("trial_maintenance_toggle", f"new_state={new_state}")
    return redirect(url_for("trial_dashboard"))

@app.route("/trial/update-settings", methods=["POST"])
def trial_update_settings():
    _ensure_trial_state()
    first = request.form.get("site_name_first", "").strip()[:40] or "Kurtis-Lee"
    last  = request.form.get("site_name_last",  "").strip()[:40] or "Hopewell"
    settings = session.get("trial_settings", {})
    settings["site_name_first"] = first
    settings["site_name_last"]  = last
    session["trial_settings"]   = settings
    _add_trial_audit("trial_settings_update", f"first={first} last={last}")
    return redirect(url_for("trial_dashboard"))

@app.route("/trial/add-nav", methods=["POST"])
def trial_add_nav():
    _ensure_trial_state()
    label = request.form.get("label", "").strip()[:30]
    url   = request.form.get("url", "").strip()
    if label and url:
        nav_links = session.get("trial_nav_links", [])
        if len(nav_links) < 8:
            nav_links.append({"label": label, "url": url})
            session["trial_nav_links"] = nav_links
            settings = session.get("trial_settings", {})
            settings["nav_links"] = nav_links
            session["trial_settings"] = settings
            _add_trial_audit("trial_nav_add", f"label={label} url={url}")
    return redirect(url_for("trial_dashboard"))

@app.route("/trial/delete-nav/<int:index>")
def trial_delete_nav(index):
    _ensure_trial_state()
    nav_links = session.get("trial_nav_links", [])
    if 0 <= index < len(nav_links):
        removed = nav_links.pop(index)
        session["trial_nav_links"] = nav_links
        settings = session.get("trial_settings", {})
        settings["nav_links"] = nav_links
        session["trial_settings"] = settings
        _add_trial_audit("trial_nav_delete", f"index={index} label={removed.get('label')}")
    return redirect(url_for("trial_dashboard"))

@app.route("/trial/api/reorder-nav", methods=["POST"])
def trial_reorder_nav():
    _ensure_trial_state()
    data = request.get_json(silent=True)
    if not data or "nav_links" not in data:
        return jsonify(error="Invalid payload"), 400
    clean = []
    for item in data["nav_links"][:8]:
        label = str(item.get("label", "")).strip()[:30]
        url   = str(item.get("url", "")).strip()
        if label and url:
            clean.append({"label": label, "url": url})
    session["trial_nav_links"] = clean
    settings = session.get("trial_settings", {})
    settings["nav_links"] = clean
    session["trial_settings"] = settings
    _add_trial_audit("trial_nav_reorder")
    return jsonify(status="ok"), 200

@app.route("/trial/audit")
def trial_audit():
    _ensure_trial_state()
    return render_template("audit.html", entries=session.get("trial_audit", []))

@app.route("/trial/analytics")
def trial_analytics():
    fake = _generate_fake_analytics()
    return render_template(
        "trial_analytics.html",
        chart_labels=fake["chart_labels"],
        chart_values=fake["chart_values"],
        stats=fake["stats"],
        top_pages=fake["top_pages"],
        error_logs=fake["error_logs"],
        total_hits=fake["total_hits"],
        active_filters={},
        active_range="7d",
        delta_unit="days",
        target_date=None,
        add_filter=lambda t, v: {},
        remove_filter=lambda t: {},
        unique_visitors=fake["total_hits"] // 2,
        online_count=3,
    )

@app.route("/trial/view/<path:slug>", methods=["GET", "POST"])
def trial_view(slug):
    _ensure_trial_state()
    slug = slug.strip("/").lower()
    page = session.get("trial_pages", {}).get(slug)
    if not page:
        abort(404)
    rendered = render_template_string(page.get("content", ""), session=session, request=request, datetime=datetime, page=page)
    return render_template("page.html", rendered_node_content=rendered, page=page, session=session, request=request, datetime=datetime)


# ─────────────────────────────────────────
#  STATIC / MISC
# ─────────────────────────────────────────
@app.route("/robots.txt")
def robots_dot_txt():
    return send_from_directory(app.static_folder, "robots.txt")

@app.route("/sitemap.xml")
def sitemap():
    base = "https://klhportfolio.vercel.app"
    pages = [{"url": f"{base}/", "lastmod": utc_now().strftime("%Y-%m-%d"), "priority": "1.0"}]
    excluded = {
        "/login", "/logout", "/sitemap.xml", "/robots.txt",
        "/og-image.png", "/_preview",
    }
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and not rule.arguments:
            p = str(rule.rule)
            if p == "/" or any(x in p.lower() for x in ["admin", "test", "trial"]):
                continue
            if p not in excluded:
                pages.append({"url": f"{base}{p}", "lastmod": utc_now().strftime("%Y-%m-%d"), "priority": "0.7"})
    try:
        for p in g.pages.find() if g.pages is not None else []:
            slug = (p.get("slug") or "").strip("/")
            if not slug or slug == "home" or any(x in slug.lower() for x in ["test", "admin"]):
                continue
            pages.append({
                "url":     f"{base}/{slug}",
                "lastmod": p.get("updated_at", utc_now()).strftime("%Y-%m-%d"),
                "priority": "0.8",
            })
    except Exception as e:
        logger.warning(f"Sitemap CMS error: {e}")
    return render_template("sitemap_template.xml", pages=pages), 200, {"Content-Type": "application/xml"}

@app.route("/og-image.png")
def dynamic_og_image():
    settings  = get_site_settings()
    site_title = f"{settings.get('site_name_first','')} {settings.get('site_name_last','')}".strip()
    api_url    = f"https://image.thum.io/get/width/1200/crop/630/delay/3/https://klhportfolio.vercel.app?isBot=true"
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; OGImageBot/1.0)"}
        r = requests.get(api_url, timeout=20, headers=headers)
        if r.status_code == 200:
            return send_file(io.BytesIO(r.content), mimetype="image/png")
    except Exception as e:
        logger.warning(f"OG image fetch failed: {e}")
    from urllib.parse import quote
    return redirect(f"https://placehold.co/1200x630/020617/ffffff/png?text={quote(site_title)}&font=playfair-display")


# ─────────────────────────────────────────
#  ERROR HANDLERS
# ─────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(503)
def service_unavailable(e):
    return render_template("503.html", maintenance_active=is_maintenance_mode()), 503


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_ENV") != "production")