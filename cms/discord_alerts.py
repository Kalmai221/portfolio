"""Discord alerts about the contact form. One place decides whether, when and how an alert is posted.

Three kinds of alert:

* new_message: a message arrived. By default Discord is only told the sender's name and how many messages are
  unread, because Discord is a third party and the email address and message belong in the encrypted database.
  A setting adds the email and message text.
* spam_flood: the contact form hit its hourly limit and is turning people away. Sent at most once an hour.
* form_paused: you paused or resumed the form from the admin settings.

Settings live in the "discord_settings" document and are edited in Admin > Settings > Discord. They are: an
overall switch, a switch per kind, the include-message switch, and quiet hours (UK time) during which alerts are
still posted but without a notification. The webhook address itself is only ever read from DISCORD_WEBHOOK_URL.

notify() never raises. It returns True (sent), False (tried and failed, or no webhook) or None (switched off or
throttled), so callers can tell "didn't send" from "wasn't meant to send".
"""
import os
import time
from datetime import datetime

import pytz
import requests
from flask import g

from .app import SITE_URL, logger, utc_now

UK = pytz.timezone("Europe/London")

DEFAULTS = {
    "enabled": True,           # overall switch
    "new_message": True,       # tell me when a message arrives
    "spam_flood": True,        # warn me when the form is flooded
    "form_paused": True,       # tell me when the form is paused or resumed
    "include_message": False,  # put the sender's email and message text in new message alerts
    "quiet_enabled": False,    # post silently during quiet hours
    "quiet_start": 22,         # hour of the day (UK time) quiet hours begin
    "quiet_end": 7,            # hour of the day (UK time) they end
}
HOUR_FIELDS = ("quiet_start", "quiet_end")

# label, colour, minimum seconds between two alerts of this kind
KINDS = {
    "new_message": ("New message", 0xD4C5A9, 0),
    "spam_flood": ("Contact form flooded", 0xF87171, 3600),
    "form_paused": ("Contact form paused", 0xFBBF24, 0),
}
SILENT = 1 << 12  # Discord's "suppress notifications" message flag


def webhook_configured() -> bool:
    return bool(os.environ.get("DISCORD_WEBHOOK_URL", "").strip())


def clean_settings(data: dict) -> dict:
    """Validate settings from the admin page. Raises ValueError with a message that can be shown."""
    out = {}
    for key, default in DEFAULTS.items():
        if isinstance(default, bool):
            out[key] = bool(data.get(key, default))
            continue
        try:
            value = int(data.get(key, default))
        except (TypeError, ValueError):
            raise ValueError("Quiet hours must be whole hours, from 0 to 23.") from None
        if not 0 <= value <= 23:
            raise ValueError("Quiet hours must be whole hours, from 0 to 23.")
        out[key] = value
    return out


def get_settings() -> dict:
    """Saved settings merged over the defaults. Never raises."""
    out = dict(DEFAULTS)
    try:
        if g.settings_col is not None:
            doc = g.settings_col.find_one({"name": "discord_settings"}) or {}
            for key, default in DEFAULTS.items():
                value = doc.get(key)
                if isinstance(default, bool):
                    if isinstance(value, bool):
                        out[key] = value
                elif isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 23:
                    out[key] = value
    except Exception:
        pass
    return out


def get_state() -> dict:
    """When each kind was last sent, and how the most recent alert went."""
    try:
        if g.settings_col is not None:
            return g.settings_col.find_one({"name": "discord_state"}) or {}
    except Exception:
        pass
    return {}


def status_summary() -> dict:
    """What the admin tab shows: is a webhook set, and how did the last alert go."""
    last = get_state().get("last_result") or {}
    shown = None
    if last.get("at") and last.get("kind") in KINDS:
        when = pytz.utc.localize(last["at"]).astimezone(UK).strftime("%d/%m/%Y %H:%M")
        shown = {"label": KINDS[last["kind"]][0], "ok": bool(last.get("ok")), "when": when}
    return {"configured": webhook_configured(), "last": shown}


def in_quiet_hours(settings: dict, now=None) -> bool:
    if not settings["quiet_enabled"]:
        return False
    now = now or utc_now()  # a naive time here means UTC, like every timestamp this site stores
    if now.tzinfo is None:
        now = pytz.utc.localize(now)
    hour = now.astimezone(UK).hour
    start, end = settings["quiet_start"], settings["quiet_end"]
    if start == end:
        return False
    return start <= hour < end if start < end else (hour >= start or hour < end)


def _post(payload: dict) -> bool:
    """Send to Discord. Waits a moment and tries once more if Discord says to slow down."""
    url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not url:
        return False
    for attempt in range(2):
        try:
            response = requests.post(url, json=payload, timeout=5)
            if response.status_code == 429 and attempt == 0:
                try:
                    wait = float(response.headers.get("Retry-After", 1))
                except (TypeError, ValueError):
                    wait = 1.0
                time.sleep(min(max(wait, 0.2), 2.0))
                continue
            response.raise_for_status()
            return True
        except Exception as e:
            logger.warning(f"Discord alert failed: {e}")
            return False
    return False


def _remember(kind: str, ok: bool):
    try:
        if g.settings_col is not None:
            now = utc_now()
            g.settings_col.update_one({"name": "discord_state"}, {"$set": {
                f"last.{kind}": now, "last_result": {"kind": kind, "ok": ok, "at": now}}}, upsert=True)
    except Exception:
        pass


def _throttled(kind: str) -> bool:
    gap = KINDS[kind][2]
    if not gap:
        return False
    last = (get_state().get("last") or {}).get(kind)
    return bool(isinstance(last, datetime) and (utc_now() - last).total_seconds() < gap)


def _clip(text, limit):
    text = (text or "").strip() or "-"
    return text if len(text) <= limit else text[: limit - 3] + "..."


def notify(kind: str, description: str = "", fields=None, url: str = "", *, title: str = "", force: bool = False):
    """Post an alert. `force` skips the switches and the throttle, for test alerts."""
    try:
        settings = get_settings()
        if not force and (not settings["enabled"] or not settings.get(kind) or _throttled(kind)):
            return None
        label, colour, _gap = KINDS[kind]
        embed = {"title": title or label, "color": colour, "timestamp": utc_now().isoformat() + "Z"}
        if description:
            embed["description"] = description
        if fields:
            embed["fields"] = fields
        if url:
            embed["url"] = url
        payload = {"allowed_mentions": {"parse": []}, "embeds": [embed]}  # a visitor's text can never ping anyone
        if in_quiet_hours(settings):
            payload["flags"] = SILENT
        ok = _post(payload)
        _remember(kind, ok)
        return ok
    except Exception as e:
        logger.warning(f"Discord alert error: {e}")
        return False


def _unread_count() -> int:
    try:
        return g.db.inquiries.count_documents({"status": {"$nin": ["READ", "SPAM"]}})
    except Exception:
        return 0


def notify_new_message(name: str, email: str, text: str, *, force: bool = False, title: str = ""):
    site = SITE_URL.rstrip("/")
    include = get_settings()["include_message"]
    fields = [{"name": "Unread", "value": str(_unread_count()), "inline": True}]
    if include:
        fields = [{"name": "Name", "value": _clip(name, 200), "inline": True}, {"name": "Email", "value": _clip(email, 200), "inline": True},
                  {"name": "Message", "value": _clip(text, 1000)}] + fields
        description = ""
    else:
        description = f"{_clip(name, 100)} sent you a message."
    return notify("new_message", description, fields, f"{site}/admin/messages", force=force, title=title)


def notify_flood(count: int, limit: int, *, force: bool = False):
    site = SITE_URL.rstrip("/")
    return notify("spam_flood", f"{count} messages in the last hour, over the limit of {limit}. The form is turning visitors away until the "
                  "hour is up. Check the Spam tab in Messages.", None, f"{site}/admin/messages?filter=spam", force=force)


def notify_form_paused(paused: bool):
    if paused:
        return notify("form_paused", "You paused the contact form. Visitors see your email address instead of the form.",
                      title="Contact form paused")
    return notify("form_paused", "The contact form is accepting messages again.", title="Contact form back on")


def send_test(kind: str):
    """A clearly labelled sample of one kind of alert. Ignores the switches so you can check the webhook."""
    if kind == "new_message":
        return notify_new_message("Sample Sender", "sample@example.com", "This is a test. A real alert looks like this.", force=True, title="Test: new message")
    if kind == "spam_flood":
        return notify("spam_flood", "This is a test of the flood warning.", None, f"{SITE_URL.rstrip('/')}/admin/messages?filter=spam", force=True, title="Test: contact form flooded")
    if kind == "form_paused":
        return notify("form_paused", "This is a test of the pause notice.", force=True, title="Test: contact form paused")
    raise ValueError("Unknown alert kind")
