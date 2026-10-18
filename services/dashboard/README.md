# services/dashboard — the local audit server and run console

**Status:** `TESTED` with browser tests (`tests/ui/`, Chromium; axe in light and dark). `UNVERIFIED`: any use other than one person on
one computer. **Requirements:** R-UI-01 (partly: plain HTML), R-UI-02, R-UI-04, R-UI-05, R-SVC-01.

| File | What it does |
|---|---|
| `server.py` | Serves the static pages in `ui/` and answers read-only questions about the receipts in one folder. Listens on `127.0.0.1` only. |
| `runner.py` | The run console. **Off unless started with `--enable-runs`.** A person types a task, sees the worst-case cost, confirms it, and it runs. |

Routes (full contract: `docs/DATABASE_AND_API_CONTRACTS.md`, Part E): `GET /api/receipts`, `/api/receipt`, `/api/verify`,
`/api/alerts`, `/api/graph` (all take `?name=<receipt>` except the list), and, with `--enable-runs`, `/api/run/info`, `/api/run/status`,
`POST /api/run/start`, `POST /api/run/approve`.

Rules: the verdict always comes from `abb verify --json`, passed through untouched; the server never computes validity. Receipt content is
sent as data and inserted as text. Every response carries a strict `Content-Security-Policy` (no inline script or style, no outside host).
A run needs a human to start it, repeats the worst-case cost, is limited to the policy's hosts, runs one at a time and is killed after a timeout.
The API key is never read by the server, only inherited by the child process.

**Known gap:** only the run-console routes check that the `Host` header is the loopback address (a DNS-rebinding guard). The read routes
above do not, so a web page that rebinds a hostname to `127.0.0.1` could read receipt summaries. Tracked in `docs/SECURITY.md` section 16.
