"""Regenerate docs/detection-signals.md from the live catalogue.

Run from the repo root:  python docs/_gen_signals.py
CI checks that the committed file matches, so the table cannot drift from code.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from drosera.detect.rules import catalogue  # noqa: E402
from drosera.models import Category  # noqa: E402

HEADER = """\
# Detection signals

Generated from the signal catalogue by `python docs/_gen_signals.py` --
edit `src/drosera/detect/rules.py`, not this file. `drosera signals` prints
the same table, and `drosera signals --json` emits it as data.

Each signal carries two independent 0..1 weights:

* **agency** -- evidence strength that no human is driving. Only signals in the
  *comprehension* category (plus `id.declared_agent`) also count toward the
  separate LLM-agency score that produces an `agent` verdict.
* **hostility** -- evidence strength that the client means harm.

Weights are evidence strengths for a noisy-OR combiner, not points in a running
total, so they never need to sum to anything.

## Strength tiers

| Range | Meaning |
| --- | --- |
| 0.90-0.98 | Decisive. Only an LLM-driven client produces this. |
| 0.60-0.85 | Strong. Bait engagement no human and few crawlers reach. |
| 0.30-0.55 | Corroborating. Has benign explanations on its own. |
| 0.10-0.25 | Whisper. Only meaningful stacked with something else. |
"""

BLURB = {
    Category.COMPREHENSION: (
        "**The discriminators.** These are the only signals that separate *an "
        "LLM is driving* from *a script is running*. Each requires the client "
        "to have understood natural language embedded in the page and taken an "
        "action described only in prose. A regex-driven scraper cannot fake "
        "these; it has no notion of instructions."
    ),
    Category.BAIT: (
        "Engagement with material humans cannot see or would never touch. "
        "Strong, but shared with classic crawlers -- these drive an "
        "`automation` verdict on their own, never `agent`."
    ),
    Category.IDENTITY: (
        "What the client says it is, and whether that story is internally "
        "coherent. Appearing here is not an accusation: most declared agents "
        "are well-behaved and documented."
    ),
    Category.BEHAVIOR: (
        "The shape of traffic over a session. Every one of these has a benign "
        "explanation, so all sit in the corroborating tier and none feed the "
        "LLM-agency score."
    ),
    Category.INTENT: (
        "Hostility, largely orthogonal to agency -- a scanner and an agent "
        "probe for the same things."
    ),
}

ORDER = [
    Category.COMPREHENSION,
    Category.BAIT,
    Category.IDENTITY,
    Category.BEHAVIOR,
    Category.INTENT,
]


def main() -> None:
    defs = catalogue()
    out = [HEADER]
    for cat in ORDER:
        rows = [d for d in defs if d.category is cat]
        if not rows:
            continue
        out.append(f"\n## {cat.value.title()}\n")
        out.append(BLURB[cat] + "\n")
        out.append("\n| Signal | Agency | Hostility | Fires when |")
        out.append("\n| --- | --- | --- | --- |")
        for d in rows:
            desc = d.description.replace("|", "\|")
            out.append(f"\n| `{d.id}` | {d.agency:.2f} | {d.hostility:.2f} | {desc} |")
        out.append("\n")

    out.append(
        "\n## Adding a signal\n\n"
        "1. Add a `SignalDef` to the right category block in "
        "`src/drosera/detect/rules.py`.\n"
        "2. Add a detector in `src/drosera/detect/signals.py` that yields it.\n"
        "3. Regenerate this file: `python docs/_gen_signals.py`.\n\n"
        "Before choosing a weight, ask what else produces the same observation. "
        "If a person using a text browser, a screen reader, a corporate proxy or "
        "a privacy extension could trip it, it belongs in the corroborating tier "
        "or below. The comprehension tier is reserved for evidence that the "
        "client read prose and acted on its meaning -- nothing else earns it.\n"
    )
    path = pathlib.Path(__file__).resolve().parent / "detection-signals.md"
    path.write_text("".join(out), encoding="utf-8", newline="\n")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
