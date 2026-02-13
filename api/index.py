import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, abort, session, send_file
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import certifi
from dotenv import load_dotenv
from functools import wraps
import json
from user_agents import parse
import requests
import io

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

og_cache = {
    "image": None,
    "expiry": datetime.now()
}

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


# --- IMPROVED ANALYTICS ENGINE ---
def log_visit(path, status_code=200):
    """Logs project traffic and system faults."""
    if path.startswith('admin') or path.startswith(
            'static') or path == 'favicon.ico':
        return

    analytics_collection.insert_one({
        "path": path,
        "status_code": status_code,
        "timestamp": datetime.now(),
        "ip": request.remote_addr,
        "agent": request.headers.get('User-Agent'),
        "referrer": request.referrer or "Direct"
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

    # 1. High-Level Metrics
    total_hits = analytics_collection.count_documents({"status_code": 200})
    unique_visitors = len(
        analytics_collection.distinct("ip", {"status_code": 200}))

    # Real-time: Active unique IPs in last 5 minutes
    online_count = len(
        analytics_collection.distinct(
            "ip", {"timestamp": {
                "$gt": now - timedelta(minutes=5)
            }}))

    # 2. Fix the Graph: Continuous 7-day timeline
    graph_pipeline = [{
        "$match": {
            "timestamp": {
                "$gt": seven_days_ago
            },
            "status_code": 200
        }
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

    # 3. Client Distribution & System Faults
    stats = {"browsers": {}, "os": {}, "devices": {}}
    for log in analytics_collection.find({"status_code": 200}):
        agent_string = log.get('agent') or ''
        ua = parse(agent_string)
        stats["browsers"][ua.browser.family] = stats["browsers"].get(
            ua.browser.family, 0) + 1
        stats["os"][ua.os.family] = stats["os"].get(ua.os.family, 0) + 1
        d = "Mobile" if ua.is_mobile else "Tablet" if ua.is_tablet else "Desktop"
        stats["devices"][d] = stats["devices"].get(d, 0) + 1

    top_pages = list(
        analytics_collection.aggregate([{
            "$match": {
                "status_code": 200
            }
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
            }
        }).sort("timestamp", -1).limit(15))

    return render_template('analytics.html',
                           total_hits=total_hits,
                           unique_visitors=unique_visitors,
                           online_count=online_count,
                           chart_labels=chart_labels,
                           chart_values=chart_values,
                           stats=stats,
                           top_pages=top_pages,
                           error_logs=error_logs)


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
            "updated_at": datetime.now()
        }
        pages_collection.update_one({"slug": slug}, {"$set": data},
                                    upsert=True)
        return redirect(url_for('admin_dashboard'))

    # Load page data
    page = pages_collection.find_one({"slug": slug})

    # Load snippet data to fix the "snippets not defined" error
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


@app.route('/', defaults={'path': 'home'})
@app.route('/<path:path>')
def cms_router(path):
    if path == "admin":
        return redirect(url_for('admin_dashboard'))

    if is_maintenance_mode():
        return render_template('503.html'), 503

    try:
        page = pages_collection.find_one({"slug": path})
        if page:
            log_visit(path, 200)
            return render_template('page.html', page=page)
    except (ConnectionFailure, ServerSelectionTimeoutError):
        return render_template('503.html'), 503

    # Log 404s for the analytics dashboard
    log_visit(path, 404)
    abort(404)

@app.route('/og-image.png')
def dynamic_og_image():
    global og_cache

    # Check if we have a valid cached image
    if og_cache["image"] and datetime.now() < og_cache["expiry"]:
        return send_file(io.BytesIO(og_cache["image"]), mimetype='image/png')

    API_KEY = os.environ.get("SCREENSHOT_API_KEY")
    TARGET_URL = "https://klhportfolio.vercel.app"

    # Options: added 'delay' to ensure fonts load before the snap
    api_url = f"https://api.screenshotone.com/take?access_key={API_KEY}&url={TARGET_URL}&viewport_width=1200&viewport_height=630&format=png&delay=1"

    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code == 200:
            # Update Cache
            og_cache["image"] = response.content
            og_cache["expiry"] = datetime.now() + timedelta(hours=24)

            return send_file(io.BytesIO(response.content), mimetype='image/png')
    except Exception as e:
        print(f"OG Image Error: {e}")

    # Fallback to a local file in /static/img/default-og.png
    return redirect(url_for('static', filename='img/default-og.png'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    log_visit(request.path, 500)
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True)
