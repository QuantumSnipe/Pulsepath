# Security policy

## Supported versions

Pulsepath is pre-release alpha software. Security fixes are applied to the latest revision on the default branch only.

## Reporting a vulnerability

Please do not open a public issue containing exploit details, private connection metadata, or instructions that could endanger users.

Report vulnerabilities privately by email to **dspyros@gmail.com** with `[Pulsepath security]` in the subject line. You will receive an acknowledgment within 7 days. GitHub private vulnerability reporting is available on this repository through **Security → Report a vulnerability**.

Useful reports include:

- the affected revision and macOS version;
- the trust boundary involved;
- a minimal reproduction using synthetic data;
- the realistic impact;
- whether payloads, credentials, history, or privileged actions are exposed.

## Project security boundaries

- The current HTTP service must remain bound to loopback.
- Mutating API requests must remain same-origin and host-validated.
- Every `/api/*` request must present the per-session token described below.
- Connection history is private local data and must stay excluded from version control.
- No feature may upload destinations, DNS names, route hops, or findings without explicit opt-in. Trace route is the exception: it reverse-resolves hop addresses through the Mac's configured DNS resolver.
- GeoIP, ASN, and reputation data are evidence sources, not verdicts.
- Downloaded dependencies and databases must be integrity-checked before installation: Python packages by pinned sha256 hashes, MMDB downloads by size cap and format validation.
- Future allow/block functionality must fail safely and include a recovery path that cannot permanently lock a user out of networking.

## Local API session token

At startup the collector generates a session token with `secrets.token_urlsafe(32)`. The token is never sent over HTTP: `GET /` and `GET /index.html` serve the page unchanged, with no token in the body or headers. Once the collector owns its port, it writes the token to `~/Library/Caches/Pulsepath/token` (or `$TMPDIR/Pulsepath/token` when `HOME` is unset). The file has mode `0600` inside a `0700` folder. The collector refuses to start if that folder is a symlink or belongs to another user, and it removes the file on a clean shutdown.

`start.command` (and `make start`) reads the file and opens `http://127.0.0.1:4173/#k=<token>`. Browsers do not send the URL fragment to the server or put it in `Referer` headers. On load, the page moves the token into `sessionStorage` for that tab and clears it from the address bar with `history.replaceState`. A tab opened from a bookmark of `/` alone, or one left over from an earlier collector run, has no valid token and tells the user to launch with `start.command` again.

The page sends the token on every `/api/*` request in the `X-Pulsepath-Token` header. The collector compares the bytes of that header with the session token using `hmac.compare_digest` and responds with 403 when the header is missing, wrong, or not ASCII. Loopback binding, the `Host` checks, and the same-origin checks on mutations stay in place.

What this protects against: blind requests from other local processes and other macOS accounts. They can reach the loopback port, but reading the page no longer gives them the token, so they cannot read flows or clear history by forging `Origin` and `Host`.

What it does not protect against: a process that runs as the same macOS user. It can read the token file, read the launch URL while it briefly appears in the `open` command line at launch, or read the browser's session data. Pulsepath is not a defense against malware already running in your account.

Opening `index.html` from disk does not include the token. That mode is the built-in simulation and does not talk to a collector.

## Responsible testing

Test only on systems and networks you own or are authorized to assess. Use reserved documentation addresses in automated tests and published examples.
