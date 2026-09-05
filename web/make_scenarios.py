"""Precompute the four demo scenarios into a static file.

    python web/make_scenarios.py

The scenarios are fully deterministic -- fixed headers, fixed offsets, a fixed
demo secret -- so the answer never changes between runs. That means the common
path through the playground (clicking the four tabs) does not need a serverless
function at all: the CDN can serve the answer.

This matters under load. Every tab click was previously a function invocation,
so a popular link could exhaust the platform's quota and take the demo down at
exactly the moment the most people were looking at it. Now only "score my
browser" and custom traces reach Python.

The committed file is checked against a fresh computation by
tests/test_playground.py, so it cannot quietly go stale when a weight changes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "api"))
sys.path.insert(0, str(HERE.parent / "src"))

import assess  # noqa: E402

OUT = HERE / "scenarios.json"


def build() -> dict:
    return {
        "drosera": assess.__version__,
        "scenarios": {key: assess.run_scenario(key) for key in assess.SCENARIOS},
    }


def main() -> None:
    payload = build()
    OUT.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8", newline="\n")
    size = OUT.stat().st_size
    print(f"  {OUT.name}: {len(payload['scenarios'])} scenarios, {size // 1024} KB")


if __name__ == "__main__":
    main()
