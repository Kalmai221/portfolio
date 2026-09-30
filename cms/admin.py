"""Login, admin dashboard, settings, navigation and the page editor."""
import re

from flask import g, jsonify, redirect, render_template, request, session, url_for
from pymongo import DESCENDING

from .app import admin_login_enabled, app, utc_now
from .security import (
    check_admin_credentials,
    client_ip,
    login_locked_out,
    login_required,
    rate_clear,
    rate_limit,
    rate_record,
    safe_next_url,
    validate_csrf,
)
from .services import (
    audit,
    bust_maintenance_cache,
    bust_settings_cache,
    is_maintenance_mode,
)


def _db_down():
    return render_template("503.html", maintenance_active=is_maintenance_mode()), 503


# ── Auth ───────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
@rate_limit(10, 60)
def login():
    if "user" in session:
        return redirect(url_for("admin_dashboard"))

    error = None
    if not admin_login_enabled():
        error = "Admin login is disabled until ADMIN_PASSWORD (or ADMIN_PASSWORD_HASH) is configured."
    elif request.method == "POST":
        validate_csrf()
        ip = client_ip()
        if login_locked_out(ip):
            return render_template("login.html", error="Too many failed attempts. Try again in 15 minutes."), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if check_admin_credentials(username, password):
            rate_clear(f"loginfail:{ip}")
            session.clear()  # prevent session fixation
            session.permanent = True
            session["user"] = username
            session["login_at"] = utc_now().isoformat()
            audit("login", f"Successful login from {ip}")
            return redirect(safe_next_url(request.args.get("next")) or url_for("admin_dashboard"))

        rate_record(f"loginfail:{ip}")
        audit("login_fail", f"Failed login for '{username}' from {ip}", level="warn")
        error = "Invalid credentials"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))


# ── Dashboard ──────────────────────────────────────────────
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


@app.route("/admin/update-settings", methods=["POST"])
@login_required
def update_settings():
    if g.settings_col is None:
        return _db_down()
    validate_csrf()
    data = {
        "site_name_first": request.form.get("site_name_first", "").strip()[:40] or "Kurtis-Lee",
        "site_name_last": request.form.get("site_name_last", "").strip()[:40] or "Hopewell",
        "show_navbar": request.form.get("show_navbar") == "true",
        "updated_at": utc_now(),
    }
    if "site_description" in request.form:
        data["site_description"] = request.form.get("site_description", "").strip()[:200]
    g.settings_col.update_one({"name": "global_config"}, {"$set": data}, upsert=True)
    bust_settings_cache()
    audit("settings_update", str(data))
    return redirect(url_for("admin_dashboard"))


# ── Navigation ─────────────────────────────────────────────
_ALLOWED_SCHEMES = ("http://", "https://", "/")


def sanitise_nav_url(url: str):
    """Return a safe URL, or None for anything suspicious (javascript:, data:, //host...)."""
    url = url.strip()
    if not url or url.startswith("//"):
        return None
    if not any(url.startswith(s) for s in _ALLOWED_SCHEMES):
        if "." in url and ":" not in url.split("/")[0]:
            url = f"https://{url}"
        else:
            return None
    return url


@app.route("/admin/add-nav", methods=["POST"])
@login_required
def add_nav_link():
    if g.settings_col is None:
        return _db_down()
    validate_csrf()
    label = request.form.get("label", "").strip()[:30]
    url = sanitise_nav_url(request.form.get("url", ""))
    if not label or not url:
        return redirect(url_for("admin_dashboard"))

    links = (g.settings_col.find_one({"name": "global_config"}) or {}).get("nav_links", [])
    if len(links) >= 8 or any(link.get("url", "").lower() == url.lower() for link in links):
        return redirect(url_for("admin_dashboard"))

    g.settings_col.update_one(
        {"name": "global_config"},
        {"$push": {"nav_links": {"label": label, "url": url}}},
        upsert=True,
    )
    bust_settings_cache()
    audit("nav_add", f"label={label} url={url}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-nav/<int:index>", methods=["POST"])
@login_required
def delete_nav_link(index):
    if g.settings_col is None:
        return _db_down()
    validate_csrf()
    config = g.settings_col.find_one({"name": "global_config"}) or {}
    links = config.get("nav_links", [])
    if 0 <= index < len(links):
        removed = links.pop(index)
        g.settings_col.update_one({"name": "global_config"}, {"$set": {"nav_links": links}})
        bust_settings_cache()
        audit("nav_delete", f"index={index} label={removed.get('label')}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/api/reorder-nav", methods=["POST"])
@login_required
def api_reorder_nav():
    if g.settings_col is None:
        return jsonify(error="DB unavailable"), 503
    validate_csrf()
    data = request.get_json(silent=True)
    if not data or "nav_links" not in data:
        return jsonify(error="Invalid payload"), 400

    clean = []
    for item in data["nav_links"][:8]:
        label = str(item.get("label", "")).strip()[:30]
        url = sanitise_nav_url(str(item.get("url", "")))
        if label and url:
            clean.append({"label": label, "url": url})

    g.settings_col.update_one({"name": "global_config"}, {"$set": {"nav_links": clean}}, upsert=True)
    bust_settings_cache()
    audit("nav_reorder")
    return jsonify(status="ok"), 200


# ── Maintenance ────────────────────────────────────────────
@app.route("/admin/toggle-maintenance", methods=["POST"])
@login_required
def toggle_maintenance():
    if g.settings_col is None:
        return _db_down()
    validate_csrf()
    bust_maintenance_cache()
    new_state = not is_maintenance_mode()
    g.settings_col.update_one(
        {"name": "maintenance_mode"},
        {"$set": {"active": new_state, "updated_at": utc_now()}},
        upsert=True,
    )
    bust_maintenance_cache()
    audit("maintenance_toggle", f"new_state={new_state}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bypass-maintenance")
@login_required
def bypass_maintenance():
    # Only sets a flag on the admin's own session, so a GET is harmless here.
    session["maintenance_bypass"] = True
    return redirect(safe_next_url(request.args.get("next")) or url_for("cms_router"))


# ── Page editor ────────────────────────────────────────────
RESERVED_SLUGS = {
    "admin", "login", "logout", "static", "_preview", "trial",
    "sitemap.xml", "robots.txt", "og-image.png",
}


def normalise_slug(raw: str) -> str:
    """Lowercase, turn spaces into hyphens and drop characters that can't live in a URL."""
    slug = re.sub(r"\s+", "-", (raw or "").strip().lower())
    slug = re.sub(r"[^a-z0-9/._-]", "", slug)
    slug = re.sub(r"-{2,}", "-", slug)
    slug = re.sub(r"/{2,}", "/", slug)
    return slug.strip("/-_.")


@app.route("/admin/edit/<path:slug>", methods=["GET", "POST"])
@login_required
def edit_page(slug):
    if g.pages is None:
        return _db_down()
    slug = slug.strip("/").lower()

    if request.method == "POST":
        validate_csrf()
        new_slug = normalise_slug(request.form.get("slug", slug))
        if not new_slug or new_slug in RESERVED_SLUGS:
            return redirect(url_for("edit_page", slug=slug))

        # The URL can be stale after a rename, so `slug` may no longer exist. In that case
        # the editor is really working on `new_slug`, and saving must not create a duplicate.
        current = g.pages.find_one({"slug": slug})
        if new_slug != slug and current and g.pages.find_one({"slug": new_slug}):
            return redirect(url_for("edit_page", slug=slug))
        target = slug if current else new_slug

        data = {
            "slug": new_slug,
            "title": (request.form.get("title") or "Untitled")[:100],
            "content": request.form.get("content", ""),
            "css": request.form.get("css_content", ""),
            "js": request.form.get("js_content", ""),
            "python_logic": request.form.get("python_logic", ""),
            "updated_at": utc_now(),
            "updated_by": session.get("user"),
        }
        if "description" in request.form:
            data["description"] = request.form.get("description", "").strip()[:200]
        g.pages.update_one({"slug": target}, {"$set": data}, upsert=True)
        audit("page_save", f"slug={new_slug}")
        return redirect(url_for("admin_dashboard"))

    page = g.pages.find_one({"slug": slug})
    return render_template("edit_page.html", page=page, slug=slug)


@app.route("/admin/delete/<path:slug>", methods=["POST"])
@login_required
def delete_page(slug):
    if g.pages is None:
        return _db_down()
    validate_csrf()
    slug = slug.strip("/").lower()
    g.pages.delete_one({"slug": slug})
    audit("page_delete", f"slug={slug}", level="warn")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/audit")
@login_required
def admin_audit():
    entries = list(
        g.audit_col.find().sort("timestamp", DESCENDING).limit(200)
    ) if g.audit_col is not None else []
    return render_template("audit.html", entries=entries)
