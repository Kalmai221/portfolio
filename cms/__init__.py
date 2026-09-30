"""Portfolio CMS. Importing this package registers every route on `app`."""
from . import admin, analytics, db, public, security, services  # noqa: F401
from .app import app

__all__ = ["app"]
