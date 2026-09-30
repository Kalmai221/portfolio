"""Vercel entrypoint. The application lives in the top-level `cms` package."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cms import app  # noqa: E402

if __name__ == "__main__":
    app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
