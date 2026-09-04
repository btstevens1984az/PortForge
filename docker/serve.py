"""Serve PortForge API + built frontend from a single process."""
from pathlib import Path

import uvicorn
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.main import app

DIST = Path(__file__).parent / "frontend" / "dist"


@app.get("/")
async def index():
    return FileResponse(DIST / "index.html")


if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        candidate = DIST / full_path
        if candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(DIST / "index.html")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8788)
