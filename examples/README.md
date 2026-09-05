# Examples

| File | What it shows |
| --- | --- |
| [`library_use.py`](library_use.py) | The engine on its own — no server, no network. The clearest way to see how a verdict is built. |
| [`flask_app.py`](flask_app.py) | WSGI middleware in front of a real app. |
| [`fastapi_app.py`](fastapi_app.py) | ASGI middleware, including how JSON endpoints are left alone. |

Start with `library_use.py`:

```bash
python examples/library_use.py
```

For the standalone honeypot with no code at all, see `drosera serve` in the
[deployment guide](../docs/deployment.md).
