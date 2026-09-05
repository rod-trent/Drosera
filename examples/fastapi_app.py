"""Drosera in front of a FastAPI app.

    pip install fastapi uvicorn
    uvicorn examples.fastapi_app:app --port 8000

The middleware buffers a response only when it is HTML *and* there is bait to
inject; JSON endpoints stream through untouched, so streaming semantics survive.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from drosera.config import Config
from drosera.middleware.asgi import DroseraMiddleware

api = FastAPI()


@api.get("/", response_class=HTMLResponse)
def index() -> str:
    return """<!doctype html><html><head><title>Acme Analytics</title></head>
    <body><h1>Acme Analytics</h1>
    <p>Reporting for finance teams. <a href="/docs-public">Docs</a></p>
    </body></html>"""


@api.get("/docs-public", response_class=HTMLResponse)
def docs() -> str:
    return "<!doctype html><html><body><h1>Docs</h1><p>Coming soon.</p></body></html>"


@api.get("/api/v1/metrics")
def metrics() -> dict:
    # JSON: passes through with no injection and no buffering.
    return {"requests": 1024, "errors": 3}


@api.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


config = Config()
config.lure.site_name = "Acme Analytics"
config.lure.contact = "security@acme.example"
config.telemetry.jsonl = "drosera-events.jsonl"
config.telemetry.stderr = True

# Cap what a single trapped client can cost you in egress.
config.trap.session_byte_budget = 5_000_000

app = DroseraMiddleware(api, config)
