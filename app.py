"""One Vercel deployment for the API and built dashboard."""
from pathlib import Path

from fastapi.staticfiles import StaticFiles
from sentinel.main import app

web_dist = Path(__file__).resolve().parent / "apps" / "web" / "dist"
if web_dist.is_dir():
    app.mount("/", StaticFiles(directory=web_dist, html=True), name="dashboard")

__all__ = ["app"]
