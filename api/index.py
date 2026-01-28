import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, abort, session
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
import certifi
from dotenv import load_dotenv
from functools import wraps
import json
from user_agents import parse

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-123")

# --- DATABASE CONNECTION ---
MONGO_URI = os.environ.get("MONGODB_URI")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client.my_portfolio
pages_collection = db.pages
settings_collection = db.settings
analytics_collection = db.analytics  # New collection for hits

# --- AUTH DECORATOR ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def is_maintenance_mode():
    try:
        config = settings_collection.find_one({"name": "maintenance_mode"})
        return config.get("active", False) if config else False
    except:
        return False

# --- ANALYTICS HELPER ---
def log_visit(path):
    # Ignore admin routes and static files
    if path.startswith('admin') or path.startswith('static'):
        return

    analytics_collection.insert_one({
        "path": path,
        "timestamp": datetime.now(),
        "ip": request.remote_addr,
        "agent": request.headers.get('User-Agent'),
        "referrer": request.referrer
    })

# --- ROUTES ---

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

@app.route('/admin/toggle-maintenance')
@login_required
def toggle_maintenance():
    current_status = is_maintenance_mode()
    settings_collection.update_one(
        {"name": "maintenance_mode"},
        {"$set": {"active": not current_status}},
        upsert=True
    )
    return redirect(url_for('admin_dashboard'))

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
            log_visit(path) # Log the hit
    except (ConnectionFailure, ServerSelectionTimeoutError):
        return render_template('503.html'), 503

    if not page:
        abort(404)
    return render_template('page.html', page=page)

@app.route('/admin')
@login_required
def admin_dashboard():
    all_pages = list(pages_collection.find())
    maintenance_active = is_maintenance_mode()

    # Fetch total hit count for the dashboard card
    total_hits = analytics_collection.count_documents({})

    return render_template('admin.html', 
                           pages=all_pages, 
                           maintenance_active=maintenance_active, 
                           total_hits=total_hits)

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    # 1. Basic Counts
    total_hits = analytics_collection.count_documents({})
    yesterday = datetime.now() - timedelta(hours=24)
    recent_hits = analytics_collection.count_documents({"timestamp": {"$gt": yesterday}})

    # 2. Advanced Parsing (OS, Browser, Device)
    all_logs = analytics_collection.find()
    stats = {
        "browsers": {},
        "os": {},
        "devices": {}
    }

    for log in all_logs:
        ua_string = log.get('agent', '')
        ua = parse(ua_string)

        # Categorize Browser
        b = ua.browser.family
        stats["browsers"][b] = stats["browsers"].get(b, 0) + 1

        # Categorize OS
        o = ua.os.family
        stats["os"][o] = stats["os"].get(o, 0) + 1

        # Categorize Device
        if ua.is_mobile: d = "Mobile"
        elif ua.is_tablet: d = "Tablet"
        elif ua.is_pc: d = "Desktop"
        else: d = "Bot/Other"
        stats["devices"][d] = stats["devices"].get(d, 0) + 1

    # 3. Time Graph Aggregation (Last 7 Days)
    seven_days_ago = datetime.now() - timedelta(days=7)
    graph_pipeline = [
        {"$match": {"timestamp": {"$gt": seven_days_ago}}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}}
    ]
    graph_data = list(analytics_collection.aggregate(graph_pipeline))

    # Prepare Labels and Values for Chart.js
    chart_labels = [d['_id'] for d in graph_data]
    chart_values = [d['count'] for d in graph_data]

    # 4. Top Pages & Recent Logs
    top_pages = list(analytics_collection.aggregate([
        {"$group": {"_id": "$path", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]))
    recent_log = list(analytics_collection.find().sort("timestamp", -1).limit(10))

    return render_template('analytics.html', 
                           total_hits=total_hits, 
                           recent_hits=recent_hits, 
                           top_pages=top_pages, 
                           recent_log=recent_log,
                           stats=stats,
                           chart_labels=chart_labels,
                           chart_values=chart_values)

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
        pages_collection.update_one({"slug": slug}, {"$set": data}, upsert=True)
        return redirect(url_for('admin_dashboard'))

    page = pages_collection.find_one({"slug": slug})
    snippet_data = {}
    snippet_path = os.path.join(app.root_path, 'static', 'data', 'snippets.json')

    try:
        if os.path.exists(snippet_path):
            with open(snippet_path, 'r') as f:
                snippet_data = json.load(f)
    except Exception as e:
        print(f"Error loading snippets: {e}")
        snippet_data = {}

    return render_template('edit_page.html', page=page, slug=slug, snippets=snippet_data)

@app.route('/admin/delete/<path:slug>')
@login_required
def delete_page(slug):
    pages_collection.delete_one({"slug": slug})
    return redirect(url_for('admin_dashboard'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)