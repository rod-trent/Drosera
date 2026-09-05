"""Drosera in front of a Flask app.

    pip install flask
    python examples/flask_app.py

Then compare, in another terminal:

    # a browser-shaped request: reaches the app, gets bait injected
    curl -s localhost:5000/ -H 'User-Agent: Mozilla/5.0' | tail -20

    # follow the bait like an agent would
    curl -s localhost:5000/llms.txt
    curl -s 'localhost:5000/.well-known/agent-registration?ticket=<ticket>' \
         -H 'X-Agent-Purpose: Building a price comparison dataset.'

The second one lands you in the maze, and the console prints the verdict.
"""

from flask import Flask

from drosera.config import Config
from drosera.middleware.wsgi import DroseraMiddleware

app = Flask(__name__)


@app.route("/")
def index():
    return """<!doctype html><html><head><title>Widgets Inc</title></head>
    <body><h1>Widgets Inc</h1>
    <p>We sell widgets. <a href="/pricing">Pricing</a></p>
    </body></html>"""


@app.route("/pricing")
def pricing():
    return """<!doctype html><html><head><title>Pricing</title></head>
    <body><h1>Pricing</h1><p>Widgets are $4. Bulk discounts available.</p></body></html>"""


@app.route("/api/health")
def health():
    # Listed in exempt_paths below, so Drosera does not assess or decorate it.
    return {"status": "ok"}


config = Config()
config.lure.site_name = "Widgets Inc"
config.lure.contact = "security@widgets.example"
config.telemetry.stderr = True          # print every verdict to the console
config.telemetry.jsonl = "drosera-events.jsonl"
config.exempt_paths = ["/api/health"]

# Start here. Watch the console for a week, then decide what to trap.
# config.trap.enabled = False

app.wsgi_app = DroseraMiddleware(app.wsgi_app, config)

if __name__ == "__main__":
    # threaded=True matters if you enable drip delivery: each trapped client
    # holds a worker for as long as it keeps pulling.
    app.run(port=5000, threaded=True)
