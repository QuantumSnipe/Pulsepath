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

At startup the collector generates a session token with `secrets.token_urlsafe(32)` and injects it into the HTML it serves as `<meta name="pulsepath-token">`. The tag sits outside the inline script, so the script-hash Content-Security-Policy still matches that script. If the inline script changes, the collector hashes the snapshot it is actually serving.

The page sends the token on every `/api/*` request in the `X-Pulsepath-Token` header. The collector compares the header with the session token using `hmac.compare_digest` and responds with 403 when the header is missing or wrong. Loopback binding and the same-origin checks on mutations stay in place. Another local process, or a browser that was not given this page, cannot read flows or clear history by forging `Origin` alone.

Opening `index.html` from disk does not include the token. That mode is the built-in simulation and does not talk to a collector.

## Responsible testing

Test only on systems and networks you own or are authorized to assess. Use reserved documentation addresses in automated tests and published examples.
