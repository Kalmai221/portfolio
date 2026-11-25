"""Admin-only settings: the contact form controls and the site message banner."""
import os
import re
from datetime import datetime

import requests
from flask import g, jsonify, request

from .admin import sanitise_nav_url
from .app import app, logger, utc_now
from .security import login_required, validate_csrf
from .services import (
    CONTACT_DEFAULTS,
    CONTACT_LIMITS,
    SITE_MESSAGE_STYLES,
    audit,
    bust_site_message_cache,
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

    g.settings_col.update_one({"name": "contact_settings"}, {"$set": {**clean, "updated_at": utc_now()}}, upsert=True)
    audit("contact_settings", ", ".join(f"{k}={v}" for k, v in clean.items()))
    return jsonify(ok=True)


@app.route("/admin/api/contact-test-alert", methods=["POST"])
@login_required
def api_contact_test_alert():
    validate_csrf()
    url = os.environ.get("DISCORD_WEBHOOK_URL", "")
    if not url:
        return _error("DISCORD_WEBHOOK_URL isn't set where this site is running, so there's nowhere to send the alert.")
    payload = {
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": "Test alert from the admin settings",
            "description": "If you can read this, contact form alerts reach this channel.",
            "color": 0xD4C5A9,
            "timestamp": utc_now().isoformat() + "Z",
        }],
    }
    try:
        requests.post(url, json=payload, timeout=5).raise_for_status()
    except Exception as e:
        logger.warning(f"Test alert failed: {e}")
        audit("contact_test_alert", "failed", level="warn")
        return _error("Discord didn't accept the alert. Check that the webhook still exists.", 502)
    audit("contact_test_alert", "sent")
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
