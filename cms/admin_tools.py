"""Admin-only settings: the contact form controls and the site message banner."""
import re
import warnings
from datetime import datetime

from flask import g, jsonify, request
from jinja2.exceptions import TemplateSyntaxError

from . import discord_alerts, vault
from .admin import sanitise_nav_url
from .app import app, utc_now
from .security import login_required, validate_csrf
from .services import (
    CONTACT_DEFAULTS,
    CONTACT_LIMITS,
    SITE_MESSAGE_STYLES,
    audit,
    bust_site_message_cache,
    get_contact_settings,
)


def _body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _error(message: str, status: int = 400):
    return jsonify(ok=False, error=message), status


def _mask(email: str) -> str:
    """k***@outlook.com. The audit log needs to say whose messages went, not store the address."""
    name, _, domain = email.partition("@")
    return f"{name[:1]}***@{domain}"


# ── Code checks for the page editor ────────────────────────
# Nothing here runs the code. Python is only compiled and Jinja only parsed, so a page with an error
# can be flagged before it is saved and breaks on the live site.
def _problem(tab: str, line, col, message: str, severity: str = "error") -> dict:
    return {"tab": tab, "line": max(int(line or 1), 1), "col": max(int(col or 1), 1),
            "severity": severity, "message": message}


def check_python(source: str) -> list:
    problems = []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            compile(source, "<page>", "exec", dont_inherit=True)
        except SyntaxError as e:
            problems.append(_problem("py", e.lineno, e.offset, e.msg))
        except ValueError as e:  # for example a null byte
            problems.append(_problem("py", 1, 1, str(e)))
    for w in caught:  # things like an invalid escape sequence: legal today, wrong tomorrow
        if issubclass(w.category, (SyntaxWarning, DeprecationWarning)):
            problems.append(_problem("py", getattr(w, "lineno", 1), 1, str(w.message), "warning"))
    return problems


def check_jinja(source: str) -> list:
    try:
        app.jinja_env.from_string(source)  # compiles the template without rendering it
    except TemplateSyntaxError as e:
        return [_problem("html", e.lineno, 1, e.message)]
    return []


def check_css(source: str) -> list:
    """Unclosed or stray brackets, unterminated strings and comments. Not a full CSS parser."""
    problems, stack = [], []
    closers = {"{": "}", "(": ")", "[": "]"}
    i, line, col, n = 0, 1, 1, len(source)

    def advance(count=1):
        nonlocal i, line, col
        for _ in range(count):
            if i < n and source[i] == "\n":
                line, col = line + 1, 1
            else:
                col += 1
            i += 1

    while i < n:
        ch = source[i]
        if source.startswith("/*", i):
            start = (line, col)
            end = source.find("*/", i + 2)
            if end == -1:
                problems.append(_problem("css", *start, "Unclosed comment", "warning"))
                break
            advance(end + 2 - i)
        elif ch in "\"'":
            start, quote = (line, col), ch
            advance()
            while i < n and source[i] != quote and source[i] != "\n":
                advance(2 if source[i] == "\\" and i + 1 < n else 1)
            if i >= n or source[i] == "\n":
                problems.append(_problem("css", *start, "Unterminated string", "warning"))
            else:
                advance()
        elif ch in closers:
            stack.append((ch, line, col))
            advance()
        elif ch in "})]":
            if stack and closers[stack[-1][0]] == ch:
                stack.pop()
            else:
                problems.append(_problem("css", line, col, f"Unexpected '{ch}'", "warning"))
            advance()
        else:
            advance()
    for opener, ln, cl in stack:
        problems.append(_problem("css", ln, cl, f"Unclosed '{opener}'", "warning"))
    return problems


@app.route("/admin/api/check-code", methods=["POST"])
@login_required
def api_check_code():
    validate_csrf()
    data = _body()
    problems = (check_python(str(data.get("py", ""))) + check_jinja(str(data.get("html", "")))
                + check_css(str(data.get("css", ""))))
    return jsonify(ok=True, problems=problems[:100])


# ── Contact form settings ──────────────────────────────────
@app.route("/admin/api/contact-settings", methods=["POST"])
@login_required
def api_contact_settings():
    if g.settings_col is None:
        return _error("The database is unavailable.", 503)
    validate_csrf()
    data = _body()

    clean = {}
    for key, default in CONTACT_DEFAULTS.items():
        if isinstance(default, bool):
            clean[key] = bool(data.get(key, default))
            continue
        low, high = CONTACT_LIMITS[key]
        try:
            value = int(data.get(key, default))
        except (TypeError, ValueError):
            return _error(f"{key.replace('_', ' ').capitalize()} must be a whole number.")
        if not low <= value <= high:
            return _error(f"{key.replace('_', ' ').capitalize()} must be between {low} and {high}.")
        clean[key] = value

    was_paused = get_contact_settings()["paused"]
    g.settings_col.update_one({"name": "contact_settings"}, {"$set": {**clean, "updated_at": utc_now()}}, upsert=True)
    audit("contact_settings", ", ".join(f"{k}={v}" for k, v in clean.items()))
    if clean["paused"] != was_paused:
        discord_alerts.notify_form_paused(clean["paused"])
    return jsonify(ok=True)


# ── Discord alerts about the contact form ──────────────────
@app.route("/admin/api/discord-settings", methods=["POST"])
@login_required
def api_discord_settings():
    if g.settings_col is None:
        return _error("The database is unavailable.", 503)
    validate_csrf()
    try:
        clean = discord_alerts.clean_settings(_body())
    except ValueError as e:
        return _error(str(e))
    g.settings_col.update_one({"name": "discord_settings"}, {"$set": {**clean, "updated_at": utc_now()}}, upsert=True)
    audit("discord_settings", ", ".join(f"{k}={v}" for k, v in clean.items()))
    return jsonify(ok=True)


@app.route("/admin/api/discord-test", methods=["POST"])
@login_required
def api_discord_test():
    """Send a clearly labelled sample of one kind of alert, ignoring the switches, to check the webhook."""
    validate_csrf()
    if not discord_alerts.webhook_configured():
        return _error("DISCORD_WEBHOOK_URL isn't set where this site is running, so there's nowhere to send the alert.")
    try:
        ok = discord_alerts.send_test(str(_body().get("kind", "new_message")))
    except ValueError:
        return _error("Pick one of the alert types.")
    audit("discord_test", f"kind={_body().get('kind')} sent={bool(ok)}", level="info" if ok else "warn")
    if not ok:
        return _error("Discord didn't accept the alert. Check that the webhook still exists.", 502)
    return jsonify(ok=True)


@app.route("/admin/api/contact-delete", methods=["POST"])
@login_required
def api_contact_delete():
    """Count, then delete, every stored message from one email address (case-insensitive)."""
    if g.db is None:
        return _error("The database is unavailable.", 503)
    validate_csrf()
    data = _body()
    email = str(data.get("email", "")).strip().lower()[:200]
    if not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
        return _error("Enter the full email address.")

    query = {"$or": [
        # encrypted messages can only be found by their keyed email code; older ones by the readable address
        *([{"email_hash": vault.blind("email", email)}] if vault.ready() else []),
        {"sender_email_lc": email},
        {"sender_email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}},
    ]}
    if not data.get("confirm"):
        return jsonify(ok=True, count=g.db.inquiries.count_documents(query))

    deleted = g.db.inquiries.delete_many(query).deleted_count
    audit("messages_delete", f"deleted={deleted} from {_mask(email)}", level="warn")
    return jsonify(ok=True, deleted=deleted)


# ── Site message ───────────────────────────────────────────
@app.route("/admin/api/site-message", methods=["POST"])
@login_required
def api_site_message():
    if g.settings_col is None:
        return _error("The database is unavailable.", 503)
    validate_csrf()
    data = _body()

    active = bool(data.get("active"))
    text = str(data.get("text", "")).strip()[:200]
    if active and not text:
        return _error("Write the message before switching it on.")

    style = str(data.get("style", "info"))
    if style not in SITE_MESSAGE_STYLES:
        return _error("Pick one of the message styles.")

    link_url = str(data.get("link_url", "")).strip()
    link_label = str(data.get("link_label", "")).strip()[:30]
    if link_url:
        link_url = sanitise_nav_url(link_url)
        if not link_url:
            return _error("The link address should start with / or https://.")
        link_label = link_label or "Read more"
    else:
        link_label = ""

    until = str(data.get("until", "")).strip()
    if until:
        try:
            datetime.strptime(until, "%Y-%m-%d")
        except ValueError:
            return _error("The last day should be a date.")

    doc = {
        "active": active, "text": text, "style": style, "link_url": link_url, "link_label": link_label,
        "dismissible": bool(data.get("dismissible", True)), "until": until, "updated_at": utc_now(),
    }
    g.settings_col.update_one({"name": "site_message"}, {"$set": doc}, upsert=True)
    bust_site_message_cache()
    audit("site_message_update", f"active={active} style={style} until={until or 'none'}: {text}")
    return jsonify(ok=True)
