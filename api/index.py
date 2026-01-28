from flask import Flask, render_template, request, redirect, url_for
from pymongo import MongoClient
from bson.objectid import ObjectId

app = Flask(__name__)

# Setup MongoDB Connection
client = MongoClient("mongodb+srv://kalmai221:kalamai221@cluster0.zscuj9x.mongodb.net/?retryWrites=true&w=majority")
db = client.my_portfolio
projects_collection = db.projects

@app.route('/')
def index():
    # Fetch all projects to display on the home page
    all_projects = projects_collection.find()
    return render_template('index.html', projects=all_projects)

@app.route('/admin/add', methods=['GET', 'POST'])
def add_project():
    if request.method == 'POST':
        project_data = {
            "title": request.form.get("title"),
            "description": request.form.get("description"),
            "tech_stack": request.form.get("tech").split(','),
            "link": request.form.get("link")
        }
        projects_collection.insert_one(project_data)
        return redirect(url_for('index'))
    return render_template('add_project.html')

if __name__ == '__main__':
    app.run(debug=True)