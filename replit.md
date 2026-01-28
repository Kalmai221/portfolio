# Portfolio CMS

A Flask-based portfolio content management system with MongoDB backend.

## Overview

This is a portfolio CMS that allows users to:
- View all portfolio projects on the home page
- Add new projects via an admin interface

## Project Structure

```
api/
  index.py          - Main Flask application
  templates/
    layout.html     - Base template with navigation
    index.html      - Portfolio display page
    add_project.html - Admin form for adding projects
requirements.txt    - Python dependencies
```

## Environment Variables

- `MONGODB_URI` - MongoDB connection string (required for database features)

## Running the Application

The Flask app runs on port 5000. Start with:
```
python api/index.py
```

## Dependencies

- Flask - Web framework
- pymongo[srv] - MongoDB driver
- python-dotenv - Environment variable management

## Notes

- The app will work without MongoDB configured, but projects won't be persisted
- To enable database functionality, set the MONGODB_URI environment variable
