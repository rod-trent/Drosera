"""Drosera -- a carnivorous honeypot for autonomous AI agents.

    Sweet-looking bait. Sticky ending.

Named for the sundew, which catches gnats not with force but with droplets
that look exactly like something worth landing on.

Quick start::

    from drosera import Snare, Observation

    snare = Snare()
    decision = snare.decide(Observation(session_id="", path="/", headers={...}))
    print(decision.assessment.summary())

Or wrap an existing app::

    from drosera.middleware.asgi import DroseraMiddleware
    app = DroseraMiddleware(app)
"""

from .config import Config
from .models import Action, Assessment, Category, Observation, Signal, Verdict
from .snare import Decision, Response, Snare

__version__ = "0.1.0"

__all__ = [
    "Action",
    "Assessment",
    "Category",
    "Config",
    "Decision",
    "Observation",
    "Response",
    "Signal",
    "Snare",
    "Verdict",
    "__version__",
]
