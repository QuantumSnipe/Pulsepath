# AGENTS.md

## Project
Pulsepath is a local-first visual network activity explorer for **macOS only** (alpha). It collects connection **metadata** on the Mac, never message contents, and serves a browser UI at `http://127.0.0.1:4173/`. Requires Python **3.11+**.

## Setup / run
- Start (background collector + open browser): `make start`
- Stop: `make stop`
- Restart after Python collector changes: `make restart`
- Foreground collector without opening a browser: `make run` or `python3 pulsepath.py --no-open --port 4173`; then `make start` opens the page with the session token (a plain `http://127.0.0.1:4173/` cannot call `/api/*`)
- UI-only / simulation: open `index.html` in a browser (no live collector)

If something is already listening on **4173**, do not start a second server. Prefer `make start` (reopens the existing instance) or `make restart`. Runtime PID/log: `~/Library/Caches/Pulsepath/` (or `$TMPDIR/Pulsepath` when `HOME` is unset).

## Verify
- Full local checks: `make check` (unittest + `py_compile` + `index.html` script parse)
- Tests only: `make test` → `python3 -m unittest discover -s tests -v`
- Definition of done for code changes: `make check` green; for UI bugs, verify in the browser when possible.

### Testing budget (do not overdo)
- Prefer **running** existing checks over inventing a large new suite.
- Add or extend tests only when they catch a real regression risk that `make check` would miss.
- Skip tests for small, reversible, low-impact edits that merely mirror the implementation.
- One focused test (or a small handful) is enough. Do **not** spend a long session writing tests, spawn a dedicated “write tests” agent, or keep broadening the suite after the relevant checks pass.
- If verification is blocked, say what remains unchecked and stop — do not fill the gap with speculative tests.

## Layout
- `pulsepath.py` — collector / local HTTP API
- `behavior.py` — security / history behavior
- `references.py` — provider range and app-network reference lookups; `install_references.py` refreshes the ranges (`make update-references`)
- `references/` — committed reference data (generated provider-range snapshot, curated `app-networks.json`)
- `index.html` — UI (inline JS; refresh the page for UI-only changes)
- `tests/` — unit tests
- `data/` — local SQLite history and optional GeoIP DBs (**not for commit**)
- `vendor/` — vendored deps; do not “clean up” casually
- `docs/` — architecture, privacy, roadmap (read when the task needs them)

## Conventions
- Prefer existing patterns in this repo over inventing new layers or frameworks.
- Keep the tool an **observer**, not a firewall, unless the user explicitly asks for privileged / blocking work with a threat model and consent design (see `CONTRIBUTING.md`).
- UI copy must separate **observed facts** from **inferred** location, ownership, or third-party reference matches.
- Tests must use documentation IPs only: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.

## Boundaries
- Never commit `data/pulsepath-history.sqlite3`, GeoIP databases, packet captures, real destination inventories, tokens, certificates, or signing keys.
- Treat app names, destination IPs, DNS names, and timing in screenshots/fixtures as sensitive metadata.
- Do not add payload inspection, external telemetry, or remote exfiltration.
- Bind/listen only on localhost unless the user explicitly expands that.
- Do not push, publish, or open remotes unless the user explicitly asks.
- Do not delete or clear the user’s live history DB without an explicit ask.

## Pointers
- `CONTRIBUTING.md`, `SECURITY.md`
- Deeper design: `docs/architecture.md`, `docs/privacy.md`, `docs/roadmap.md`
