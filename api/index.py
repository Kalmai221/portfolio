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
    try:
        config = settings_collection.find_one({"name": "maintenance_mode"})
        return config.get("active", False) if config else False
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
        if username == "admin" and password == "password":
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
        "label": request.form.get("label", "").upper(),
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
                                   {"$set": {
                                       "active": not current_status
                                   }},
                                   upsert=True)
    return redirect(url_for('admin_dashboard'))


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
            "updated_at": datetime.now()
        }
        pages_collection.update_one({"slug": slug}, {"$set": data},
                                    upsert=True)
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
@app.route('/', defaults={'path': 'home'}, methods=['GET', 'POST']) # Added methods here
@app.route('/<path:path>', methods=['GET', 'POST'])
def cms_router(path):
    if path == "admin":
        return redirect(url_for('admin_dashboard'))

    if is_maintenance_mode():
        return render_template('503.html'), 503

    try:
        page = pages_collection.find_one({"slug": path})
        if page:
            log_visit(path, 200)

            template_context = {
                "db": db,
                "session": session,
                "request": request,
                "datetime": datetime,
                "timedelta": timedelta,
                "page": page
            }

            if page.get('python_logic'):
                try:
                    exec(page['python_logic'],
                         {"template_context": template_context},
                         template_context)
                except Exception as e:
                    # 1. Log the error to analytics for later review
                    log_visit(path, 500)
                    # 2. Capture the detailed technical breakdown
                    template_context['logic_error'] = str(e)
                    template_context['error_traceback'] = traceback.format_exc(
                    )

            # ... (rendering logic remains the same)
            from flask import render_template_string
            rendered_node_content = render_template_string(
                page.get('content', ''), **template_context)

            return render_template('page.html',
                                   rendered_node_content=rendered_node_content,
                                   **template_context)
    except Exception as e:
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

    # Manually ensure the root is added first to guarantee its presence
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
            # Skip root (already added), admin paths, and test nodes
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
            slug = p.get('slug', '')
            # Skip empty slugs, the 'home' alias (root), and test pages
            if not slug or slug == 'home' or "test" in slug.lower():
                continue

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
