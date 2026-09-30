# Portfolio CMS

The source for my portfolio site, [klhportfolio.vercel.app](https://klhportfolio.vercel.app). It is a small Flask + MongoDB content management system I wrote so I can change pages, navigation and settings from the browser instead of redeploying.

**[Try the editor in a sandbox](https://klhportfolio.vercel.app/trial)**. No account needed. Your edits stay in your own browser and are deleted after 24 hours.

## What I built, and why

- **Pages live in the database.** Each page is HTML, CSS, JS and an optional Python snippet stored in MongoDB and routed by slug, so publishing is a save button, not a deploy.
- **An in-browser editor.** Tabs for each language, a live preview, and an audit log of every change.
- **Privacy-first analytics.** Page views are counted server-side. Visitor IPs are hashed with the user agent and the date, so they can't be linked across days. There are no cookies for visitors and no third-party scripts. Data expires after a year by default.
- **A safe public demo.** The `/trial` sandbox runs entirely client-side. Visitor code executes in a sandboxed iframe with no access to the site's origin, and the server never stores or runs it. The real editor's Python and Jinja execution is admin-only.
- **Maintenance mode** for the whole site or a single page, with an admin bypass.

## Stack

Python 3.12, Flask, MongoDB Atlas (PyMongo), Tailwind (Play CDN), deployed on Vercel.

Tailwind runs in the browser on purpose. Page content is written in the CMS and can use any utility class, so a build step that scans the repo would miss classes that only exist in the database.

## Layout

```text
api/
  index.py          Vercel entrypoint (imports the cms package)
  (see cms/ at the repo root)
    app.py          Flask app, config, Vercel path shim
    db.py           Mongo client, indexes, per-request handles
    security.py     CSRF, rate limiting, auth helpers, headers
    services.py     Settings, maintenance flag, audit log, visit tracking
    admin.py        Login, dashboard, navigation, editor
    analytics.py    Admin analytics
    trial.py        Serves the client-side sandbox
    public.py       Page router, preview, robots, sitemap, OG image
  templates/        Jinja templates (trial.html is the whole sandbox app)
  static/
```

## Running locally

```bash
python -m venv .venv
.venv\Scripts\activate        # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then fill in MONGODB_URI and credentials
python api/index.py
```

The site is at <http://localhost:5000>. Without `MONGODB_URI` it starts, but pages return 503 and `/trial` still works.

## Configuration

| Variable | Purpose |
| --- | --- |
| `MONGODB_URI` | MongoDB connection string (database `my_portfolio`) |
| `SECRET_KEY` | Signs sessions. **Required in production.** |
| `ADMIN_USERNAME` | Admin login name |
| `ADMIN_PASSWORD_HASH` | Werkzeug password hash (preferred) |
| `ADMIN_PASSWORD` | Plain-text fallback for local development |
| `SITE_URL` | Public URL for canonical links, sitemap and robots.txt |
| `ANALYTICS_RETENTION_DAYS` | How long analytics are kept (default 365) |

On Vercel the admin panel stays locked until a real `SECRET_KEY` and admin password are configured. Generate a hash with:

```bash
python -c "from werkzeug.security import generate_password_hash as g; print(g('your-password'))"
```

## AI acknowledgment

I used AI tools for parts of this project, including query drafting, CSS and reviews. I chose the architecture, wrote the data model and decided the security trade-offs myself, and I review and test everything before it ships.

## License

MIT. See [LICENSE](LICENSE).
