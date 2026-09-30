"""MongoDB connection, per-request handles and one-time index setup."""
import os
import time

import certifi
from flask import abort, g
from pymongo import MongoClient
from pymongo.read_preferences import ReadPreference
from pymongo.write_concern import WriteConcern

from .app import app, logger

ANALYTICS_RETENTION_DAYS = int(os.environ.get("ANALYTICS_RETENTION_DAYS", "365"))

_client = None
_last_failure = 0.0
_indexes_ready = False
_RETRY_AFTER = 10  # seconds to wait before retrying a failed connection


def get_mongo_client():
    """Return a cached client. PyMongo reconnects on its own, so no per-request ping."""
    global _client, _last_failure
    if _client is not None:
        return _client

    uri = os.environ.get("MONGODB_URI")
    if not uri:
        return None
    if _last_failure and time.monotonic() - _last_failure < _RETRY_AFTER:
        return None

    try:
        c = MongoClient(
            uri,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=5000,
            read_preference=ReadPreference.PRIMARY_PREFERRED,
            retryWrites=True,
        )
        c.admin.command("ping")  # once per cold start
    except Exception as e:
        _last_failure = time.monotonic()
        logger.warning(f"MongoDB connection failed: {e}")
        return None

    _client = c
    _ensure_indexes(c.my_portfolio)
    return _client


def _ensure_indexes(db):
    """Create indexes once per process. Failures are logged, never fatal."""
    global _indexes_ready
    if _indexes_ready:
        return
    _indexes_ready = True
    specs = [
        (db.pages, "slug", {}),
        (db.analytics, "timestamp", {"expireAfterSeconds": ANALYTICS_RETENTION_DAYS * 86400}),
        (db.audit_log, "timestamp", {}),
        (db.rate_limits, "ts", {"expireAfterSeconds": 86400}),
    ]
    for col, field, opts in specs:
        try:
            col.create_index(field, **opts)
        except Exception as e:
            logger.warning(f"Index on {col.name}.{field} skipped: {e}")


def get_db():
    """Return the db handle or abort with 503."""
    c = get_mongo_client()
    if c is None:
        abort(503)
    return c.my_portfolio


@app.before_request
def attach_db():
    c = get_mongo_client()
    if c is not None:
        db = c.my_portfolio
        g.db = db
        g.pages = db.pages
        g.settings_col = db.settings
        g.audit_col = db.audit_log
        g.rate_col = db.rate_limits
        g.analytics_col = db.analytics
        # Analytics writes are fire-and-forget so a page view never waits on them.
        g.analytics_write_col = db.analytics.with_options(write_concern=WriteConcern(w=0))
        return
    g.db = g.pages = g.settings_col = g.audit_col = g.rate_col = None
    g.analytics_col = g.analytics_write_col = None
