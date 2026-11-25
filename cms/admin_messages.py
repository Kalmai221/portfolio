"""The admin Messages page: reads, filters and manages the contact form messages.

New messages are stored encrypted (see vault.py). This page decrypts them for display. It never reads, decrypts or
shows IP addresses or browser text, so there is nothing on screen to leak, and no way to browse them from here.
"""
from urllib.parse import quote

import pytz
from bson.errors import InvalidId
from bson.objectid import ObjectId
from flask import abort, g, redirect, render_template, request, url_for

from . import vault
from .app import app
from .security import login_required, validate_csrf
from .services import audit, is_maintenance_mode

PAGE_SIZE = 25
UK = pytz.timezone("Europe/London")

# Unread means NEW, or no status at all on very old messages.
FILTERS = {
    "inbox": {"status": {"$ne": "SPAM"}},
    "unread": {"status": {"$nin": ["READ", "SPAM"]}},
    "spam": {"status": "SPAM"},
    "all": {},
}
NOTICES = {
    "deleted": "Message deleted.",
    "read": "Marked as read.",
    "unread": "Marked as unread.",
    "spam": "Moved to spam.",
    "notspam": "Moved back to your inbox.",
    "spam-cleared": "Spam deleted.",
    "bad-id": "That message no longer exists.",
}


def _uk_time(value):
    if not value:
        return "Unknown date"
    return pytz.utc.localize(value).astimezone(UK).strftime("%d/%m/%Y %H:%M")


def open_message(doc: dict) -> dict:
    """What the page needs from one stored message. Deliberately leaves out IPs, browser text and hashes."""
    enc = doc.get("enc")
    if enc:
        name = vault.decrypt(enc.get("sender_name"))
        email = vault.decrypt(enc.get("sender_email"))
        text = vault.decrypt(enc.get("message_content"))
        locked = None in (name, email, text)
    else:  # an older message, from before encryption
        name, email, text = doc.get("sender_name"), doc.get("sender_email"), doc.get("message_content")
        locked = False
    email = email or ""
    status = doc.get("status") or "NEW"
    return {
        "id": str(doc["_id"]),
        "name": name or "Unknown sender",
        "email": email,
        "text": text or "",
        "locked": locked,
        "legacy": not enc,
        "received": _uk_time(doc.get("received_at")),
        "status": status,
        "spam_score": doc.get("spam_score"),
        "reasons": [str(r) for r in (doc.get("spam_reasons") or [])],
        "discord_failed": "discord_sent" in doc and not doc["discord_sent"],
        # quote() so an odd address can't add extra mail headers such as bcc
        "mailto": f"mailto:{quote(email, safe='@+.-_')}?subject={quote('Re: your message')}" if email else "",
    }


@app.route("/admin/messages", methods=["GET", "POST"])
@login_required
def admin_messages():
    if g.db is None:
        return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
    col = g.db.inquiries

    flt = request.values.get("filter", "inbox")
    if flt not in FILTERS:
        flt = "inbox"
    try:
        page = max(int(request.values.get("page", 1)), 1)
    except ValueError:
        page = 1

    if request.method == "POST":
        validate_csrf()
        action = request.form.get("action", "")
        done = None
        if action == "clear-spam":
            deleted = col.delete_many({"status": "SPAM"}).deleted_count
            audit("messages_spam_cleared", f"deleted={deleted}", level="warn")
            done = "spam-cleared"
        elif action in ("delete", "read", "unread", "spam", "notspam"):
            try:
                oid = ObjectId(request.form.get("id", ""))
            except (InvalidId, TypeError):
                oid = None
            if oid is None or col.count_documents({"_id": oid}) == 0:
                done = "bad-id"
            elif action == "delete":
                col.delete_one({"_id": oid})
                audit("message_delete", f"id={oid}", level="warn")
                done = "deleted"
            else:
                col.update_one({"_id": oid}, {"$set": {"status": {"read": "READ", "unread": "NEW", "spam": "SPAM", "notspam": "NEW"}[action]}})
                done = action
        else:
            abort(400)
        return redirect(url_for("admin_messages", filter=flt, page=page, done=done))

    docs = list(col.find(FILTERS[flt]).sort("received_at", -1).skip((page - 1) * PAGE_SIZE).limit(PAGE_SIZE + 1))
    has_next = len(docs) > PAGE_SIZE
    messages = [open_message(d) for d in docs[:PAGE_SIZE]]

    return render_template(
        "messages.html",
        messages=messages,
        flt=flt,
        page=page,
        has_next=has_next,
        counts={name: col.count_documents(q) for name, q in FILTERS.items()},
        notice=NOTICES.get(request.args.get("done", "")),
        legacy_count=col.count_documents({"enc": {"$exists": False}}),
        locked_count=sum(1 for m in messages if m["locked"]),
        vault_ready=vault.ready(),
    )
