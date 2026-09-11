"""Loopback-only monitor UI. Read-only API, no arbitrary file-read endpoint."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .core import Monitor

STATIC = Path(__file__).parent / 'static'


def create_app(monitor: Monitor):
    @asynccontextmanager
    async def lifespan(app):
        monitor.start()
        try:
            yield
        finally:
            monitor.stop()

    app = FastAPI(title='ThreatSight Monitor', lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', '[::1]', 'testserver'])

    @app.middleware('http')
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        return response

    @app.get('/')
    def dashboard():
        return FileResponse(STATIC / 'index.html')

    @app.get('/monitor.js')
    def script():
        return FileResponse(STATIC / 'monitor.js', media_type='text/javascript')

    @app.get('/monitor.css')
    def stylesheet():
        return FileResponse(STATIC / 'monitor.css', media_type='text/css')

    @app.get('/api/monitor')
    def snapshot():
        return monitor.snapshot()

    @app.get('/api/incidents/{incident_id}/export')
    def export(incident_id: str):
        with monitor.lock, monitor.connect() as con:
            row = con.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'Incident not found')
        return JSONResponse(dict(row), headers={'Content-Disposition': f'attachment; filename="incident-{row["id"]}.json"'})

    return app
