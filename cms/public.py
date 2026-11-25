"""Public site: CMS router, admin preview, robots, sitemap, OG image and error pages."""
import html
import io
import sys
import traceback
from datetime import datetime, timedelta
from urllib.parse import quote

import requests
from flask import (
    Response,
    abort,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from werkzeug.datastructures import ImmutableMultiDict

from . import vault
from .app import SITE_URL, app, logger, utc_now
from .db import get_mongo_client, note_db_failure
from .security import login_required
from .services import get_site_settings, is_maintenance_mode, log_visit


# ── Admin preview ──────────────────────────────────────────
def _preview_error_page(exc: Exception, tb_text: str, line_no) -> str:
    return f"""<!DOCTYPE html><html style="background:#111"><head><meta charset="UTF-8">
<style>
body{{font-family:monospace;margin:0;background:#111;color:#ddd;padding:24px}}
h1{{font-size:16px;color:#f87171;margin:0 0 4px}}
p{{margin:0 0 16px;color:#999}}
pre{{background:#000;border:1px solid #333;padding:14px;font-size:12px;white-space:pre-wrap;overflow-x:auto;color:#888}}
</style></head><body>
<h1>{html.escape(type(exc).__name__)} (line {html.escape(str(line_no))})</h1>
<p>{html.escape(str(exc))}</p>
<pre>{html.escape(tb_text)}</pre>
</body></html>"""


def render_preview(content, css, js, logic, base_context=None):
    context = dict(base_context or {})

    if logic:
        try:
            exec(logic, {"__builtins__": __builtins__}, context)
        except Exception as e:
            frames = traceback.extract_tb(sys.exc_info()[2])
            line_no = frames[-1].lineno if frames else "?"
            return _preview_error_page(e, traceback.format_exc(), line_no)

    full_html = f"""<!DOCTYPE html>
<html class="dark" style="background:#000;margin:0;padding:0">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        html,body{{background:#000;color:#a1a1aa;min-height:100vh;margin:0;padding:0}}
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
        return f"<pre style='background:#111;color:orange;padding:20px'>Template error: {html.escape(str(e))}</pre>"


class _PreviewRequest:
    """Stand-in for `request` while previewing.

    The editor sends its own fields with a POST, which would look like a real form
    submission to page code (contact form, message deletion). Previews therefore see a
    GET with no form data, so they can read the database but never act on it.
    """

    method = "GET"

    def __init__(self, real):
        self._real = real
        self.form = ImmutableMultiDict()

    def __getattr__(self, name):
        return getattr(self._real, name)


@app.route("/_preview", methods=["GET", "POST"])
@login_required
def preview_node():
    """Admin-only. Executes the editor's Python and Jinja, so it must never be public."""
    base_ctx = {
        "db": g.db,
        "session": session,
        "request": _PreviewRequest(request),
        "datetime": datetime,
        "timedelta": timedelta,
        "now": utc_now(),
        "page": {},
        "maintenance_active": False,
    }

    if request.method == "GET":
        slug = request.args.get("target_slug", "home")
        page = g.pages.find_one({"slug": slug}) if g.pages is not None else None
        if not page:
            return "Node not found", 404
        base_ctx["page"] = page
        return render_preview(
            page.get("content", ""), page.get("css", ""), page.get("js", ""),
            page.get("python_logic", ""), base_ctx,
        )

    return render_preview(
        request.form.get("content", ""), request.form.get("css", ""), request.form.get("js", ""),
        request.form.get("python_logic", ""), base_ctx,
    )


# ── Trial sandbox (static shell; all state lives in the visitor's localStorage) ──

@app.route("/trial")
def trial():
    return render_template("trial.html")


@app.route("/trial/<path:_rest>")
def trial_legacy(_rest):
    # Old server-side trial URLs (/trial/edit/home, /trial/view/about, ...).
    return redirect(url_for("trial"), code=301)


# ── Database outages ───────────────────────────────────────
# Last copy of each page this process served. It is only read when the database can't be
# reached, and it is replaced by the database's version every time that works, so it can be
# out of date during an outage but never afterwards. Serverless instances each keep their own.
_page_cache: dict = {}
_PAGE_CACHE_MAX = 64


def _unavailable(maintenance=False):
    return render_template("503.html", maintenance_active=maintenance), 503, {"Retry-After": "15"}


def _load_page(path):
    """Return (page, from_cache). On an outage this falls back to the last copy of the page."""
    if g.pages is not None:
        try:
            page = g.pages.find_one({"slug": path})
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            note_db_failure()
            logger.warning(f"Database unreachable, trying cached copy of /{path}: {e}")
        else:
            if page:
                if len(_page_cache) >= _PAGE_CACHE_MAX and path not in _page_cache:
                    _page_cache.pop(next(iter(_page_cache)))
                _page_cache[path] = page
            else:
                _page_cache.pop(path, None)
            return page, False
    return _page_cache.get(path), True


@app.errorhandler(ConnectionFailure)
def database_unreachable(e):
    """Any route (admin included) that loses the database gets the friendly page, not a 500."""
    note_db_failure()
    logger.error(f"Database unreachable: {e}")
    return _unavailable()


@app.route("/healthz")
def healthz():
    """Uptime check: 200 when the database answers, 503 when it doesn't."""
    ok = False
    client = get_mongo_client()
    if client is not None:
        try:
            client.admin.command("ping")
            ok = True
        except ConnectionFailure:
            note_db_failure()
    status = {"status": "ok" if ok else "degraded", "database": ok, "vault": vault.ready()}
    return jsonify(status), (200 if ok else 503), {"Cache-Control": "no-store"}


# ── CMS router ─────────────────────────────────────────────
@app.route("/", defaults={"path": "home"}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def cms_router(path):
    if path == "admin":
        return redirect(url_for("admin_dashboard"))

    is_admin = "user" in session
    has_bypass = session.get("maintenance_bypass", False)
    global_maint = is_maintenance_mode()

    if global_maint and not (is_admin and has_bypass):
        return render_template("503.html", maintenance_active=True), 503

    try:
        page, from_cache = _load_page(path)
        if page is None and from_cache:
            # The database is down and this process has never served this page.
            return _unavailable()
        if page:
            maint_val = page.get("maintenance", False)
            page_maint = maint_val.lower() == "true" if isinstance(maint_val, str) else bool(maint_val)
            if page_maint and not (is_admin and has_bypass):
                return render_template("page_maintenance.html", page=page, maintenance_active=True), 503

            log_visit(path, 200)

            ctx = {
                "db": g.db,
                "session": session,
                "request": request,
                "datetime": datetime,
                "timedelta": timedelta,
                "page": page,
                "maintenance_active": global_maint or page_maint,
            }

            if page.get("python_logic"):
                try:
                    exec(page["python_logic"], {"__builtins__": __builtins__}, ctx)
                except Exception as e:
                    log_visit(path, 500)
                    ctx["logic_error"] = str(e)
                    ctx["error_traceback"] = traceback.format_exc()
                    logger.error(f"Logic exec error on /{path}: {e}")

            rendered = render_template_string(page.get("content", ""), **ctx)
            response = make_response(render_template("page.html", rendered_node_content=rendered, **ctx))
            if from_cache:
                response.headers["X-Content-Source"] = "cache"
            return response

    except (ConnectionFailure, ServerSelectionTimeoutError) as db_err:
        note_db_failure()
        logger.critical(f"DB error serving /{path}: {db_err}")
        return _unavailable()

    except Exception as e:
        logger.error(f"CMS router failure on /{path}: {e}")
        traceback.print_exc()
        return render_template("503.html", maintenance_active=global_maint), 503

    log_visit(path, 404)
    abort(404)


# ── robots / sitemap / OG image ────────────────────────────
@app.route("/robots.txt")
def robots_txt():
    body = (
        "User-agent: *\nAllow: /\n"
        "Disallow: /admin\nDisallow: /login\nDisallow: /trial\n\n"
        f"Sitemap: {SITE_URL}/sitemap.xml\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    today = utc_now().strftime("%Y-%m-%d")
    pages = [{"url": f"{SITE_URL}/", "lastmod": today, "priority": "1.0"}]
    try:
        for p in g.pages.find() if g.pages is not None else []:
            slug = (p.get("slug") or "").strip("/")
            if not slug or slug == "home" or p.get("maintenance") in (True, "true"):
                continue
            pages.append({
                "url": f"{SITE_URL}/{slug}",
                "lastmod": (p.get("updated_at") or utc_now()).strftime("%Y-%m-%d"),
                "priority": "0.8",
            })
    except Exception as e:
        logger.warning(f"Sitemap CMS error: {e}")
    return render_template("sitemap_template.xml", pages=pages), 200, {"Content-Type": "application/xml"}


_og_cache: dict = {"png": None, "fetched": None}
_OG_TTL = timedelta(hours=12)


@app.route("/og-image.png")
def og_image():
    """Screenshot of the home page, cached in-process and at the CDN."""
    headers = {"Cache-Control": "public, max-age=86400, s-maxage=86400"}
    fresh = _og_cache["png"] and _og_cache["fetched"] and utc_now() - _og_cache["fetched"] < _OG_TTL
    if not fresh:
        api_url = f"https://image.thum.io/get/width/1200/crop/630/delay/3/{SITE_URL}?isBot=true"
        try:
            r = requests.get(api_url, timeout=15, headers={"User-Agent": "Mozilla/5.0 (compatible; OGImageBot/1.0)"})
            if r.status_code == 200:
                _og_cache.update(png=r.content, fetched=utc_now())
        except Exception as e:
            logger.warning(f"OG image fetch failed: {e}")

    if _og_cache["png"]:
        resp = send_file(io.BytesIO(_og_cache["png"]), mimetype="image/png")
        resp.headers.update(headers)
        return resp

    s = get_site_settings()
    title = f"{s.get('site_name_first', '')} {s.get('site_name_last', '')}".strip()
    return redirect(f"https://placehold.co/1200x630/18181b/f4f4f5/png?text={quote(title)}")


# ── Error handlers ─────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(503)
def service_unavailable(e):
    return render_template("503.html", maintenance_active=is_maintenance_mode()), 503
