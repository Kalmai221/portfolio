import os
from flask import Flask, render_template, request, redirect, url_for
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

MONGODB_URI = os.environ.get("MONGODB_URI", "")

_client = None
_db = None
_projects_collection = None

def get_projects_collection():
    global _client, _db, _projects_collection
    if _projects_collection is None and MONGODB_URI:
        try:
            from pymongo import MongoClient
            _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
            _db = _client.my_portfolio
            _projects_collection = _db.projects
        except Exception as e:
            print(f"MongoDB connection error: {e}")
            return None
    return _projects_collection

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index():
    collection = get_projects_collection()
    if collection is not None:
        all_projects = list(collection.find())
    else:
        all_projects = []
    return render_template('index.html', projects=all_projects)

@app.route('/admin/add', methods=['GET', 'POST'])
def add_project():
    if request.method == 'POST':
        collection = get_projects_collection()
        if collection is not None:
            project_data = {
                "title": request.form.get("title"),
                "description": request.form.get("description"),
                "tech_stack": request.form.get("tech").split(','),
                "link": request.form.get("link")
            }
            collection.insert_one(project_data)
        return redirect(url_for('index'))
    return render_template('add_project.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)