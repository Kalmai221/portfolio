"""Portfolio CMS. Importing this package registers every route on `app`."""
from . import admin, admin_messages, admin_tools, analytics, db, public, security, services  # noqa: F401
from .app import app

__all__ = ["app"]
