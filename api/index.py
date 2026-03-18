import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, abort, session, send_file, send_from_directory, render_template_string
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import certifi
from dotenv import load_dotenv
from functools import wraps
import json
from user_agents import parse
import requests
import io
import traceback
import hmac
import random
import sys

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-123")

# --- DATABASE CONNECTION ---
MONGO_URI = os.environ.get("MONGODB_URI")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client.my_portfolio
pages_collection = db.pages
settings_collection = db.settings
analytics_collection = db.analytics

og_cache = {"image": None, "expiry": datetime.now()}


# --- AUTH DECORATOR ---
def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# --- SETTINGS HELPERS ---
def get_site_settings():
    """Fetches global configuration from MongoDB or returns defaults."""
    try:
        settings = settings_collection.find_one({"name": "global_config"})
        if not settings:
            return {
                "site_name_first": "Kurtis-Lee",
                "site_name_last": "Hopewell",
                "show_navbar": True,
                "nav_links": []
            }
        # Ensure fallback for missing fields in existing documents
        if 'site_name_first' not in settings:
            settings['site_name_first'] = "Kurtis-Lee"
        if 'site_name_last' not in settings:
            settings['site_name_last'] = "Hopewell"
        return settings
    except:
        return {
            "site_name_first": "Kurtis-Lee",
            "site_name_last": "Hopewell",
            "show_navbar": True,
            "nav_links": []
        }


def is_maintenance_mode():
    """Strict boolean check for global maintenance."""
    try:
        config = settings_collection.find_one({"name": "maintenance_mode"})
        if not config:
            return False
        
        active = config.get("active")
        # Ensure we only return True if it is explicitly the boolean True 
        # or the lowercase string "true"
        if isinstance(active, str):
            return active.lower() == "true"
        return bool(active) is True
    except:
        return False


def log_visit(path, status_code=200):
    if path.startswith('admin') or path.startswith(
            'static') or path == 'favicon.ico':
        return

    # 1. Detect Source
    custom_ref = request.args.get('redirectfrom')
    raw_referrer = request.referrer or ""
    current_host = request.host  # e.g., klhportfolio.vercel.app

    # 2. Filter out internal redirects
    if current_host in raw_referrer and not custom_ref:
        final_source = "Direct / Internal"
        full_url = raw_referrer
    else:
        # 3. Clean Naming Logic
        ref_low = raw_referrer.lower()
        if custom_ref:
            final_source = f"Campaign: {custom_ref}"
        elif "google" in ref_low:
            final_source = "Google Search"
        elif "linkedin" in ref_low:
            final_source = "LinkedIn"
        elif "github" in ref_low:
            final_source = "GitHub"
        elif not raw_referrer:
            final_source = "Direct Entry"
        else:
            final_source = raw_referrer.split('//')[-1].split('/')[
                0]  # Get domain only

        full_url = raw_referrer

    analytics_collection.insert_one({
        "path": path,
        "status_code": status_code,
        "timestamp": datetime.now(),
        "ip": request.remote_addr,
        "agent": request.headers.get('User-Agent'),
        "referrer": final_source,
        "full_referrer_url": full_url
    })


# --- CONTEXT PROCESSOR ---
@app.context_processor
def inject_global_data():
    """Makes 'settings' available in all templates automatically."""
    from datetime import datetime
    return dict(settings=get_site_settings(), now=datetime.now())


# --- AUTH ROUTES ---


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Load admin credentials from environment (fallback to old defaults)
        admin_user = os.environ.get("ADMIN_USERNAME", "admin")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "password")

        # Use constant-time comparison to mitigate timing attacks
        if (username is not None and password is not None and
                hmac.compare_digest(str(username), admin_user) and
                hmac.compare_digest(str(password), admin_pass)):
            session['user'] = username
            return redirect(url_for('admin_dashboard'))

        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('cms_router'))


# --- ADMIN DASHBOARD ---


@app.route('/admin')
@login_required
def admin_dashboard():
    all_pages = list(pages_collection.find())
    maintenance_active = is_maintenance_mode()
    total_hits = analytics_collection.count_documents({"status_code": 200})
    return render_template('admin.html',
                           pages=all_pages,
                           maintenance_active=maintenance_active,
                           total_hits=total_hits)


@app.route('/admin/update-settings', methods=['POST'])
@login_required
def update_settings():
    """Handles Brand names and Navbar visibility."""
    data = {
        "site_name_first": request.form.get("site_name_first", "Kurtis-Lee"),
        "site_name_last": request.form.get("site_name_last", "Hopewell"),
        "show_navbar": request.form.get("show_navbar") == "true"
    }
    settings_collection.update_one({"name": "global_config"}, {"$set": data},
                                   upsert=True)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add-nav', methods=['POST'])
@login_required
def add_nav_link():
    """Injects a dynamic link into the navbar manager."""
    new_link = {
        "label": request.form.get("label", ""),
        "url": request.form.get("url", "")
    }
    if new_link["label"] and new_link["url"]:
        settings_collection.update_one({"name": "global_config"},
                                       {"$push": {
                                           "nav_links": new_link
                                       }},
                                       upsert=True)
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete-nav/<int:index>')
@login_required
def delete_nav_link(index):
    """Removes a nav link by its position in the array."""
    settings = get_site_settings()
    if "nav_links" in settings:
        links = settings["nav_links"]
        if 0 <= index < len(links):
            del links[index]
            settings_collection.update_one({"name": "global_config"},
                                           {"$set": {
                                               "nav_links": links
                                           }})
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/toggle-maintenance')
@login_required
def toggle_maintenance():
    current_status = is_maintenance_mode()
    settings_collection.update_one({"name": "maintenance_mode"},
                                   {"$set": {"active": not current_status}},
                                   upsert=True)
    return redirect(url_for('admin_dashboard'))

# --------------------
# Trial CMS (session-backed, no DB writes)
# --------------------


def _ensure_trial_state():
    """Initialize trial session state if missing."""
    now = datetime.now()
    if 'trial_pages' not in session:
        session['trial_pages'] = {}
    if 'trial_maintenance' not in session:
        session['trial_maintenance'] = False
    if 'trial_seed' not in session:
        session['trial_seed'] = random.randint(1, 10**9)
    # Set trial start/expiry once per session (10 minutes)
    if 'trial_started_at' not in session:
        session['trial_started_at'] = now.isoformat()
    if 'trial_expires' not in session:
        session['trial_expires'] = (now + timedelta(minutes=10)).isoformat()


def _get_trial_pages_list():
    _ensure_trial_state()
    pages = []
    for slug, p in session.get('trial_pages', {}).items():
        # convert updated_at to datetime for templates
        updated_at = None
        if p.get('updated_at'):
            try:
                updated_at = datetime.fromisoformat(p.get('updated_at'))
            except Exception:
                updated_at = None
        pages.append({
            'slug': slug,
            'title': p.get('title', '(untitled)'),
            'content': p.get('content', ''),
            'css': p.get('css', ''),
            'js': p.get('js', ''),
            'python_logic': p.get('python_logic', ''),
            'updated_at': updated_at
        })
    return pages


def _generate_fake_analytics():
    """Return deterministic fake analytics based on session trial_seed."""
    _ensure_trial_state()
    seed = session.get('trial_seed')
    rng = random.Random(seed)

    now = datetime.now()
    # 8 days labels/values
    chart_labels = []
    chart_values = []
    for i in range(7, -1, -1):
        d = now - timedelta(days=i)
        chart_labels.append(d.strftime('%b %d'))
        # small traffic influenced by number of trial pages
        base = max(1, len(session.get('trial_pages', {})))
        chart_values.append(base * rng.randint(1, 8))

    browsers = {'Chrome': rng.randint(5, 30), 'Firefox': rng.randint(0, 10), 'Safari': rng.randint(0, 6)}
    os = {'Windows': rng.randint(5, 20), 'macOS': rng.randint(1, 10), 'Linux': rng.randint(1, 8)}
    devices = {'Desktop': rng.randint(5, 20), 'Mobile': rng.randint(1, 12), 'Tablet': rng.randint(0, 4)}

    top_pages = []
    for slug, p in session.get('trial_pages', {}).items():
        top_pages.append({'_id': f"/trial/{slug}", 'count': rng.randint(1, 30)})

    error_logs = []
    # small chance of an error
    if rng.random() < 0.2:
        error_logs.append({'timestamp': now.isoformat(), 'path': '/trial/sample', 'status_code': 500, 'message': 'Sample error'})

    stats = {
        'browsers': browsers,
        'os': os,
        'devices': devices,
        'referrers': {'Direct Entry': rng.randint(5, 20), 'Google Search': rng.randint(0, 8)}
    }

    return {
        'chart_labels': chart_labels,
        'chart_values': chart_values,
        'stats': stats,
        'top_pages': top_pages,
        'error_logs': error_logs,
        'total_hits': sum(chart_values)
    }



@app.before_request
def _clear_expired_trial():
    """Clear trial session data when the expiry timestamp passes."""
    try:
        if 'trial_expires' in session:
            expires = datetime.fromisoformat(session.get('trial_expires'))
            if datetime.now() > expires:
                # clear trial keys
                keys = ['trial_pages', 'trial_maintenance', 'trial_seed', 'trial_expires', 'trial_started_at']
                for k in keys:
                    session.pop(k, None)
                from flask import flash
                flash('Your trial session has expired and was cleared.', 'info')
    except Exception:
        pass


@app.route('/trial')
def trial_dashboard():
    _ensure_trial_state()
    pages = _get_trial_pages_list()
    maintenance_active = session.get('trial_maintenance', False)
    fake = _generate_fake_analytics()
    return render_template('trial_admin.html', pages=pages, maintenance_active=maintenance_active, total_hits=fake['total_hits'])


@app.route('/trial/edit/<path:slug>', methods=['GET', 'POST'])
def trial_edit(slug):
    _ensure_trial_state()
    slug = slug.strip('/')
    if request.method == 'POST':
        data = {
            'title': request.form.get('title') or '(untitled)',
            'content': request.form.get('content') or '',
            'css': request.form.get('css_content') or '',
            'js': request.form.get('js_content') or '',
            # NOTE: Python backend logic is not allowed in trial pages for security
            # 'python_logic' intentionally omitted
            'updated_at': datetime.now().isoformat()
        }
        trial_pages = session.get('trial_pages', {})
        trial_pages[slug] = data
        session['trial_pages'] = trial_pages
        from flask import flash
        flash('Saved changes to trial session', 'success')
        return redirect(url_for('trial_dashboard'))

    page = session.get('trial_pages', {}).get(slug)
    snippets = {}
    snippet_path = os.path.join(app.root_path, 'static', 'data', 'snippets.json')
    try:
        if os.path.exists(snippet_path):
            with open(snippet_path, 'r') as f:
                snippets = json.load(f)
    except Exception:
        snippets = {}

    return render_template('trial_edit_page.html', page=page, slug=slug, snippets=snippets)


@app.route('/trial/delete/<path:slug>')
def trial_delete(slug):
    _ensure_trial_state()
    trial_pages = session.get('trial_pages', {})
    if slug in trial_pages:
        del trial_pages[slug]
        session['trial_pages'] = trial_pages
        from flask import flash
        flash('Deleted trial page', 'success')
    return redirect(url_for('trial_dashboard'))


@app.route('/trial/toggle-maintenance')
def trial_toggle_maintenance():
    _ensure_trial_state()
    session['trial_maintenance'] = not session.get('trial_maintenance', False)
    from flask import flash
    flash('Toggled trial site status', 'info')
    return redirect(url_for('trial_dashboard'))


@app.route('/trial/analytics')
def trial_analytics():
    fake = _generate_fake_analytics()
    return render_template('trial_analytics.html',
                           chart_labels=fake['chart_labels'],
                           chart_values=fake['chart_values'],
                           stats=fake['stats'],
                           top_pages=fake['top_pages'],
                           error_logs=fake['error_logs'],
                           total_hits=fake['total_hits'])


@app.route('/trial/view/<path:slug>', methods=['GET', 'POST'])
def trial_view(slug):
    """Render a trial page from session without touching DB or analytics."""
    _ensure_trial_state()
    slug = slug.strip('/')
    page = session.get('trial_pages', {}).get(slug)
    if not page:
        abort(404)

    template_context = {
        'db': None,
        'session': session,
        'request': request,
        'datetime': datetime,
        'timedelta': timedelta,
        'page': page
    }

    # For security: trial pages do NOT execute stored python logic

    rendered_node_content = render_template_string(page.get('content', ''), **template_context)
    return render_template('page.html', rendered_node_content=rendered_node_content, **template_context)

def render_preview_helper(content, css, js, logic, base_context=None):
    context = base_context if base_context else {}
    
    if logic:
        try:
            exec(logic, {"__builtins__": __builtins__}, context)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            tb = traceback.extract_tb(exc_traceback)
            line_no = tb[-1].lineno if tb else "Unknown"
            full_trace = traceback.format_exc()
            
            # Error UI with improved Dev Info and Styling
            return f"""
            <style>
                html, body {{ background: #09090b; margin: 0; padding: 0; height: 100vh; overflow: hidden; font-family: 'JetBrains Mono', monospace; }}
                .error-wrapper {{ display: flex; align-items: center; justify-content: center; height: 100%; padding: 20px; box-sizing: border-box; }}
                .error-card {{ width: 100%; max-width: 700px; background: #111111; border: 1px solid #450a0a; border-radius: 12px; overflow: hidden; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }}
                .error-header {{ background: #450a0a; padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #991b1b; }}
                .error-title {{ color: #ffffff; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.1em; display: flex; align-items: center; gap: 8px; }}
                .error-body {{ padding: 24px; }}
                .error-type {{ color: #f87171; font-size: 16px; font-weight: bold; margin-bottom: 4px; }}
                .error-msg {{ color: #a1a1aa; font-size: 13px; line-height: 1.5; margin-bottom: 20px; }}
                .dev-info {{ background: #000000; border: 1px solid #27272a; border-radius: 6px; padding: 16px; }}
                .info-row {{ display: flex; gap: 20px; margin-bottom: 12px; font-size: 11px; }}
                .info-label {{ color: #71717a; text-transform: uppercase; width: 80px; }}
                .info-value {{ color: #e4e4e7; }}
                .trace-block {{ margin-top: 12px; padding-top: 12px; border-top: 1px solid #18181b; color: #71717a; font-size: 10px; line-height: 1.6; white-space: pre-wrap; }}
            </style>
            <div class="error-wrapper">
                <div class="error-card">
                    <div class="error-header">
                        <div class="error-title">
                            <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                            Runtime Exception
                        </div>
                        <div style="color: #f87171; font-size: 10px; font-weight: bold;">NODE_ERR_01</div>
                    </div>
                    <div class="error-body">
                        <div class="error-type">{type(e).__name__}</div>
                        <div class="error-msg">{str(e)}</div>
                        
                        <div class="dev-info">
                            <div class="info-row">
                                <div><span class="info-label">Line:</span><span class="info-value">{line_no}</span></div>
                                <div><span class="info-label">Scope:</span><span class="info-value">Logic Tab</span></div>
                            </div>
                            <div class="trace-block">{full_trace.split('File "<string>", line', 1)[-1]}</div>
                        </div>
                    </div>
                </div>
            </div>
            """

    # Normal rendering logic (with fixed white bars)
    full_html = f"""
    <!DOCTYPE html>
    <html class="dark" style="background: #000; margin: 0; padding: 0;">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            html, body {{ background-color: #000; color: #a1a1aa; min-height: 100vh; margin: 0; padding: 0; }}
            ::-webkit-scrollbar {{ width: 10px; height: 10px; }}
            ::-webkit-scrollbar-track {{ background: #000; }}
            ::-webkit-scrollbar-thumb {{ background: rgba(121, 121, 121, 0.2); border: 2px solid #000; border-radius: 10px; }}
            ::-webkit-scrollbar-thumb:hover {{ background: rgba(121, 121, 121, 0.4); }}
            {css}
        </style>
    </head>
    <body style="margin: 0; padding: 0;">
        {content}
        <script>{js}</script>
    </body>
    </html>
    """
    
    try:
        from flask import render_template_string
        return render_template_string(full_html, **context)
    except Exception as e:
        return f"<div style='background:#111; color:orange; padding:20px; font-family:monospace;'>Template Error: {str(e)}</div>"
    
@app.route('/_preview', methods=['GET', 'POST'])
def preview_node():
    # Security Check
    if 'user' not in session and 'trial_pages' not in session:
        abort(403)

    # Base context available to all previews
    base_context = {
        'session': session,
        'request': request,
        'datetime': datetime,
        'now': datetime.now()
    }

    if request.method == 'GET':
        # Handling "Open in Preview" (Database-backed)
        slug = request.args.get('target_slug', 'home')
        page_data = pages_collection.find_one({"slug": slug})
        if not page_data:
            return "Node not found", 404
        
        return render_preview_helper(
            content=page_data.get('content', ''),
            css=page_data.get('css', ''),
            js=page_data.get('js', ''),
            logic=page_data.get('python_logic', ''),
            base_context=base_context
        )

    else:
        # Handling "Live Preview" (Editor-backed)
        return render_preview_helper(
            content=request.form.get('content', ''),
            css=request.form.get('css', ''),
            js=request.form.get('js', ''),
            logic=request.form.get('python_logic', ''),
            base_context=base_context
        )


# --- VERCEL-STYLE ANALYTICS ---
@app.route('/admin/analytics')
@login_required
def admin_analytics():
    now = datetime.now()
    seven_days_ago = now - timedelta(days=7)

    # Get filter params from URL: ?type=browser&val=Chrome
    f_type = request.args.get('type')
    f_val = request.args.get('val')

    # --- 1. BUILD THE DYNAMIC QUERY ---
    base_filter = {"status_code": 200, "timestamp": {"$gt": seven_days_ago}}

    if f_type == 'path':
        base_filter['path'] = f_val
    elif f_type == 'referrer':
        base_filter['referrer'] = f_val

    # --- 2. HIGH-LEVEL METRICS ---
    total_hits = analytics_collection.count_documents(base_filter)
    unique_visitors = len(analytics_collection.distinct("ip", base_filter))
    online_count = len(
        analytics_collection.distinct(
            "ip", {"timestamp": {
                "$gt": now - timedelta(minutes=5)
            }}))

    # --- 3. THE GRAPH (Filtered) ---
    graph_pipeline = [{
        "$match": base_filter
    }, {
        "$group": {
            "_id": {
                "$dateToString": {
                    "format": "%Y-%m-%d",
                    "date": "$timestamp"
                }
            },
            "count": {
                "$sum": 1
            }
        }
    }, {
        "$sort": {
            "_id": 1
        }
    }]
    raw_graph_data = {
        d['_id']: d['count']
        for d in analytics_collection.aggregate(graph_pipeline)
    }

    chart_labels = []
    chart_values = []
    for i in range(7, -1, -1):
        date_obj = now - timedelta(days=i)
        date_str = date_obj.strftime('%Y-%m-%d')
        chart_labels.append(date_obj.strftime('%b %d'))
        chart_values.append(raw_graph_data.get(date_str, 0))

    # --- 4. CLIENT SPECS & REFERRERS ---
    # Initialize correctly: 'referrers' is for simple counts, 'referrers_detailed' for URLs
    stats = {
        "browsers": {},
        "os": {},
        "devices": {},
        "referrers": {},
        "referrers_detailed": {}
    }

    logs = list(analytics_collection.find(base_filter))

    filtered_logs_count = 0
    for log in logs:
        ua = parse(log.get('agent') or '')
        browser = ua.browser.family
        os_family = ua.os.family
        device = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"

        # Apply Python-side filtering for UA-parsed fields
        if f_type == 'browser' and f_val != browser: continue
        if f_type == 'os' and f_val != os_family: continue
        if f_type == 'device' and f_val != device: continue

        # If we passed filters, increment counts
        filtered_logs_count += 1

        # Basic Stats
        stats["browsers"][browser] = stats["browsers"].get(browser, 0) + 1
        stats["os"][os_family] = stats["os"].get(os_family, 0) + 1
        stats["devices"][device] = stats["devices"].get(device, 0) + 1

        # Referrer Logic
        ref_name = log.get('referrer', 'Direct Entry')
        ref_url = log.get('full_referrer_url', '')

        # Simple count for progress bars
        stats["referrers"][ref_name] = stats["referrers"].get(ref_name, 0) + 1

        # Detailed entry for "View Exact Link"
        if ref_name not in stats["referrers_detailed"]:
            stats["referrers_detailed"][ref_name] = {
                "count": 0,
                "url": ref_url
            }
        stats["referrers_detailed"][ref_name]["count"] += 1

    # --- 5. TOP PAGES & ERRORS ---
    top_pages = list(
        analytics_collection.aggregate([{
            "$match": base_filter
        }, {
            "$group": {
                "_id": "$path",
                "count": {
                    "$sum": 1
                }
            }
        }, {
            "$sort": {
                "count": -1
            }
        }, {
            "$limit": 8
        }]))

    error_logs = list(
        analytics_collection.find({
            "status_code": {
                "$gte": 400
            },
            "timestamp": {
                "$gt": seven_days_ago
            }
        }).sort("timestamp", -1).limit(15))

    return render_template(
        'analytics.html',
        total_hits=filtered_logs_count if f_type else total_hits,
        unique_visitors=unique_visitors,
        online_count=online_count,
        chart_labels=chart_labels,
        chart_values=chart_values,
        stats=stats,
        top_pages=top_pages,
        error_logs=error_logs,
        filter_active={
            'type': f_type,
            'val': f_val
        })


# --- PAGE EDITOR ---
@app.route('/admin/edit/<path:slug>', methods=['GET', 'POST'])
@login_required
def edit_page(slug):
    if request.method == 'POST':
        data = {
            "slug": request.form.get("slug").strip("/"),
            "title": request.form.get("title"),
            "content": request.form.get("content"),
            "css": request.form.get("css_content"),
            "js": request.form.get("js_content"),
            "python_logic": request.form.get("python_logic"),
            "maintenance": request.form.get("maintenance") == "true", # New field
            "updated_at": datetime.now()
        }
        pages_collection.update_one({"slug": slug}, {"$set": data}, upsert=True)
        return redirect(url_for('admin_dashboard'))

    page = pages_collection.find_one({"slug": slug})

    snippet_data = {}
    snippet_path = os.path.join(app.root_path, 'static', 'data',
                                'snippets.json')
    try:
        if os.path.exists(snippet_path):
            with open(snippet_path, 'r') as f:
                snippet_data = json.load(f)
    except Exception as e:
        print(f"Error loading snippets: {e}")

    return render_template('edit_page.html',
                           page=page,
                           slug=slug,
                           snippets=snippet_data)


@app.route('/admin/delete/<path:slug>')
@login_required
def delete_page(slug):
    pages_collection.delete_one({"slug": slug})
    return redirect(url_for('admin_dashboard'))


# --- DYNAMIC CMS ROUTER ---
@app.route('/', defaults={'path': 'home'}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def cms_router(path):
    if path == "admin":
        return redirect(url_for('admin_dashboard'))

    # 1. Global Check (Admins bypass)
    if is_maintenance_mode() and 'user' not in session:
        return render_template('503.html'), 503

    try:
        page = pages_collection.find_one({"slug": path})
        if page:
            # 2. Per-Page Check (Strict boolean conversion)
            maint_val = page.get('maintenance', False)
            
            # Type guard for per-page maintenance
            if isinstance(maint_val, str):
                is_under_maint = maint_val.lower() == "true"
            else:
                is_under_maint = bool(maint_val)

            # 3. Apply Bypass
            if is_under_maint and 'user' not in session:
                return render_template('page_maintenance.html', page=page), 503

            # --- Normal rendering follows ---
            log_visit(path, 200)
            template_context = {"db": db, "session": session, "request": request, "datetime": datetime, "timedelta": timedelta, "page": page}
            
            if page.get('python_logic'):
                try:
                    exec(page['python_logic'], {"template_context": template_context}, template_context)
                except Exception as e:
                    log_visit(path, 500)
                    template_context['logic_error'] = str(e)
                    template_context['error_traceback'] = traceback.format_exc()

            rendered_node_content = render_template_string(page.get('content', ''), **template_context)
            return render_template('page.html', rendered_node_content=rendered_node_content, **template_context)
            
    except Exception as e:
        # If we hit an error here, check if it's a DB timeout
        return render_template('503.html'), 503

    log_visit(path, 404)
    abort(404)

@app.route('/og-image.png')
def dynamic_og_image():
    # 1. Target your live homepage
    target_url = "https://klhportfolio.vercel.app"
    settings = get_site_settings()
    first_name = settings.get('site_name_first', 'Kurtis-Lee')
    last_name = settings.get('site_name_last', 'Hopewell')

    # 2. Construct a professional branding string
    site_title = f"{first_name} {last_name}"

    # 2. Thum.io Keyless URL (Width 1200, Crop to 630 for OG standard)
    # This service allows a certain amount of free keyless requests per IP
    api_url = f"https://image.thum.io/get/width/1200/crop/630/noanimate/{target_url}"
    from urllib.parse import quote
    clean_title = quote(f"{site_title} | Portfolio")

    try:
        # 3. Fetch the image from the provider
        response = requests.get(api_url, timeout=15)

        if response.status_code == 200:
            # 4. Serve the actual image bytes to the crawler
            return send_file(io.BytesIO(response.content),
                             mimetype='image/png',
                             download_name='og-image.png')
    except Exception as e:
        print(f"Screenshot Error: {e}")

    # Fallback to a solid color placeholder if the service is down
    return redirect(
        f"https://placehold.co/1200x630/020617/ffffff/png?text={clean_title}&font=playfair-display"
    )

@app.route('/sitemap.xml')
def sitemap():
    """Self-inspects the Flask app and MongoDB to build a full sitemap."""
    pages = []
    base_url = "https://klhportfolio.vercel.app"

    # Manually ensure the root is added first
    pages.append({
        "url": f"{base_url}/",
        "lastmod": datetime.now().strftime('%Y-%m-%d'),
        "priority": "1.0"
    })

    excluded_endpoints = [
        'static', 'login', 'logout', 'admin_dashboard', 'update_settings',
        'add_nav_link', 'delete_nav_link', 'toggle_maintenance',
        'admin_analytics', 'edit_page', 'delete_page', 'sitemap',
        'dynamic_og_image', 'robots_dot_txt'
    ]

    # 1. Static Routes (Python logic)
    for rule in app.url_map.iter_rules():
        if "GET" in rule.methods and len(rule.arguments) == 0:
            route_path = str(rule.rule)
            # Skip root, admin paths, and test nodes
            if route_path == "/" or any(
                    x in route_path.lower() or x in rule.endpoint.lower()
                    for x in ["test", "admin"]):
                continue
            if rule.endpoint not in excluded_endpoints:
                pages.append({
                    "url": f"{base_url}{route_path}",
                    "lastmod": datetime.now().strftime('%Y-%m-%d'),
                    "priority": "0.7"
                })

    # 2. CMS Routes (MongoDB)
    try:
        cms_pages = pages_collection.find()
        for p in cms_pages:
            slug = p.get('slug', '').strip("/")

            # --- NEW FILTER LOGIC ---
            # Skip if slug is empty, 'home', contains 'test', or contains 'admin'
            if not slug or slug == 'home' or "test" in slug.lower() or "admin" in slug.lower():
                continue
            # ------------------------

            lastmod = p.get('updated_at', datetime.now()).strftime('%Y-%m-%d')
            pages.append({
                "url": f"{base_url}/{slug}",
                "lastmod": lastmod,
                "priority": "0.8"
            })
    except Exception as e:
        print(f"Sitemap Error: {e}")

    return render_template('sitemap_template.xml', pages=pages), 200, {
        'Content-Type': 'application/xml'
    }

@app.route('/admin/update-settings', methods=['POST'])
@login_required
def update_settings_thing():
    """Centralized handler for all global site configuration."""
    from flask import flash
    
    # 1. Capture Identity Data
    first_name = request.form.get("site_name_first", "Kurtis-Lee")
    last_name = request.form.get("site_name_last", "Hopewell")
    
    # 2. Capture Feature Toggles
    # In HTML, checkboxes only send a value if they are checked.
    show_navbar = True if request.form.get("show_navbar") == "true" else False

    # 3. Build Update Payload
    data = {
        "site_name_first": first_name,
        "site_name_last": last_name,
        "show_navbar": show_navbar,
        "updated_at": datetime.now()
    }

    try:
        # 4. Commit to MongoDB
        settings_collection.update_one(
            {"name": "global_config"}, 
            {"$set": data},
            upsert=True
        )
        flash('Configuration updated successfully', 'success')
    except Exception as e:
        flash(f'System Error: {str(e)}', 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/robots.txt')
def robots_dot_txt():
    """Serves the robots.txt from the static folder at the root level."""
    return send_from_directory(app.static_folder, 'robots.txt')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    log_visit(request.path, 500)
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True)
