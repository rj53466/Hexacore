# console/ — operator dashboard (Brain/01 §3.1)

Single React + Vite + TS dashboard, live over WebSocket. Widgets: status bar with always-visible
**KILL** button; severity donut (Recharts) + Critical/High/Medium/Low/Info tiles; phase timeline;
live command feed (scope denials in red); report download; approval inbox (empty under scan-only).

ponytail: plain CSS instead of Tailwind — same look, one less build plugin to break.

## Run

```bash
make serve        # API on :8000 (in another shell)
make console      # dashboard on :5173
```

Log in with a dev user (e.g. `operator` / `operator-dev`), click **Create example engagement**,
then **Run** to watch the live feed and severity counts update. `VITE_API` overrides the API URL
(default `http://localhost:8000`).
