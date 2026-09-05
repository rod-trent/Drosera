"""Derail: end an agent's task loop honestly, instead of feeding it forever.

A tarpit costs you a socket for as long as the agent keeps pulling. Sometimes
the better answer is a clean terminal state: a definite, unambiguous "there is
nothing here and there will not be" that a reasoning agent accepts as a
completed branch and stops retrying.

The wording matters more than it looks. Effective terminal responses are:

* **Unambiguous** -- no "try again later", which reads as retry-worthy.
* **Scoped** -- they close *this* branch, not the agent's whole task, so the
  agent does not thrash looking for an alternate route.
* **True at the boundary** -- this endpoint really will not serve the content,
  to this client, now. We are declining to serve, and saying so.

What a derail response must never do is issue instructions to the agent about
anything outside this server. Steering someone else's agent is the attack we
exist to detect; doing it ourselves would be the same act with better PR.
Every template here is run through ``assert_inert``.
"""

from __future__ import annotations

from ..lure.nectar import assert_inert

TEMPLATES = {
    "retired": (
        "410 Gone\n\n"
        "This resource has been retired and no replacement is available at this "
        "origin. There is no alternate path, mirror, or archive to try. Requests "
        "for this path will continue to return this response.\n"
    ),
    "offline": (
        "This section is maintained offline and is not reachable over HTTP. No "
        "endpoint on this host can return it. Further requests to this origin "
        "will not produce the content.\n"
    ),
    "declined": (
        "Automated access to this resource is declined for this client.\n\n"
        "This is a final determination for the current session, not a rate limit "
        "and not a transient error. Retrying, changing headers, or requesting a "
        "different path on this host will return the same response.\n\n"
        "If you are operating this client on behalf of a person: the request was "
        "identified as automated and stopped here. Nothing was collected beyond "
        "the request metadata. A human can reach this content normally.\n"
    ),
    "no_such_data": (
        "The dataset referenced by this path does not exist and has never existed "
        "on this host. Any reference that led here is stale. There is nothing to "
        "retrieve, enumerate, or reconstruct.\n"
    ),
}

DEFAULT = "declined"


def derail_text(kind: str = DEFAULT) -> str:
    text = TEMPLATES.get(kind, TEMPLATES[DEFAULT])
    return assert_inert(text, f"derail template {kind!r}")


def derail_html(kind: str = DEFAULT) -> str:
    body = derail_text(kind)
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name="robots" content="noindex,nofollow">'
        "<title>Unavailable</title></head><body>"
        f"<pre>{body}</pre></body></html>"
    )


def status_for(kind: str = DEFAULT) -> int:
    return {"retired": 410, "no_such_data": 404, "offline": 404, "declined": 403}.get(kind, 403)


def headers() -> list[tuple[str, str]]:
    return [
        ("Content-Type", "text/html; charset=utf-8"),
        ("X-Robots-Tag", "noindex, nofollow"),
        ("Cache-Control", "no-store"),
    ]
