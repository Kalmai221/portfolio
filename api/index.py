import os
from flask import Flask, render_template, request, redirect, url_for, abort
from pymongo import MongoClient
import certifi
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# --- DATABASE CONNECTION ---
MONGO_URI = os.environ.get("MONGODB_URI")
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client.my_portfolio
pages_collection = db.pages

@app.route('/', defaults={'path': 'home'})
@app.route('/<path:path>')
def cms_router(path):
    if path == "admin":
        return redirect(url_for('admin_dashboard'))

    page = pages_collection.find_one({"slug": path})
    if not page:
        abort(404)

    return render_template('page.html', page=page)

@app.route('/admin')
def admin_dashboard():
    all_pages = list(pages_collection.find())
    return render_template('admin.html', pages=all_pages)

@app.route('/admin/edit/<path:slug>', methods=['GET', 'POST'])
def edit_page(slug):
    if request.method == 'POST':
        data = {
            "slug": request.form.get("slug").strip("/"),
            "title": request.form.get("title"),
            "content": request.form.get("content"),    # HTML Tab
            "css": request.form.get("css_content"),    # CSS Tab
            "js": request.form.get("js_content")       # JS Tab
        }
        pages_collection.update_one({"slug": slug}, {"$set": data}, upsert=True)
        return redirect(url_for('admin_dashboard'))

    page = pages_collection.find_one({"slug": slug})
    return render_template('edit_page.html', page=page, slug=slug)

@app.route('/admin/delete/<path:slug>')
def delete_page(slug):
    pages_collection.delete_one({"slug": slug})
    return redirect(url_for('admin_dashboard'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)