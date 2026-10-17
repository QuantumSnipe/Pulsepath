# Pulsepath

Pulsepath is a visual network activity explorer, currently developed only for macOS. Everything it collects stays on your Mac. It turns connection metadata into animated routes, remembers which destinations your apps normally talk to, and explains unfamiliar changes without capturing message contents.

> **Alpha software:** Pulsepath is an observability prototype, not yet a firewall. It cannot currently guarantee that every short-lived, privileged, inbound, or blocked connection is observed.

## Table of contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Using the interface](#using-the-interface)
- [Local security history](#local-security-history)
- [Current scope and limits](#current-scope-and-limits)
- [Offline connection intelligence](#offline-connection-intelligence)
- [Offline basemap](#offline-basemap)
- [Troubleshooting](#troubleshooting)
- [Uninstall and data removal](#uninstall-and-data-removal)
- [Native observer](#native-observer)
- [Development](#development)
- [Getting help](#getting-help)
- [License](#license)

## Requirements

- macOS.
- Python 3.11 or newer. Check with `python3 --version`.
- No administrator access is required for the current observer.

## Quick start

Open the Terminal app, change into the folder where you cloned or downloaded the repo and run:

```sh
make start
```

This starts the collector in the background and opens Pulsepath in your web browser at `http://127.0.0.1:4173/`. The collector records connection metadata only, never message contents. Stop it with:

```sh
make stop
```

If Pulsepath is already running, `make start` reopens that instance. After updating the Python collector, use `make restart` to stop and start it with the new code. Interface-only changes load when you refresh the page.

In VS Code, the same actions are available from **Terminal → Run Task…** as **Pulsepath: Start**, **Pulsepath: Stop**, and **Pulsepath: Run checks**.

To explore the interface without observing any real traffic, open `index.html` in a web browser. It then runs in simulation mode with generated example connections.

### Optional: offline city and network-owner lookup

Pulsepath can estimate the city behind an IP address and identify which network owns it, entirely offline. To enable this, double-click `install-geoip.command` in Finder (or run `python3 install_geoip.py` in Terminal) and accept the DB-IP Lite license prompt. You only need to do this one time. If macOS warns that `install-geoip.command` is from an unidentified developer, right-click it and choose **Open**. The large databases and your local history are deliberately excluded from Git. Restart Pulsepath afterward.

## Using the interface

- Select a recent activity to change the animated route. While the collector is running, the newest connection is listed first. The simulated example list keeps its original order.
- Scroll over the map or use `+` for protocol and endpoint detail. **Trace route** enables intermediate markers as probe results arrive; **Show hop details** opens the ordered list of traceroute steps.
- Drag to pan the map.
- **Luminous** adds cyan-to-magenta route bloom, short activity trails, and endpoint brackets. Switch to **Quiet** for the simpler presentation; the choice lasts for the page session. Both styles retain the same routes, evidence, and controls. Trails illustrate activity, not captured packets or measured transfer speed.
- **Constellation** shows other fresh streams as subdued endpoint connections behind the selected route. Click a background endpoint, or use Tab and Enter/Space, to select its stream. Shared map positions open a chooser; they do not establish a shared physical server. **Focus view** hides the overview while keeping the selected route. This control is separate from Luminous/Quiet.
- The constellation follows the activity filter and shows up to 24 active streams, including the selected stream when active. Its count explains when filtering can narrow a larger set; all streams remain accessible in the activity list. Background paths are illustrative source-to-endpoint connections, even if another stream has collected traceroute results. Labels appear on hover or keyboard focus, and location estimates and unlocated visual anchors retain their uncertainty. Historical investigations hide the overview to keep the historical context clear.
- **Pause animation** freezes motion while collection continues. The interface also respects the system's reduced-motion setting and stops its activity animation loop when the tab is hidden. Historical and stale connections remain static in either visual style.
- Zoom up to detail level (18×). Click any visible route node to center it and inspect its location evidence; labels automatically move apart when they would overlap.
- **Show hop details** starts collapsed and does not send probes when opened. **Hide hop details** collapses the text and detail card while collected hop markers stay visible for an enabled route. Selecting a different connection collapses the panel again without disabling the previous route's trace view.
- Published address lists from Cloudflare, Google, AWS, Fastly, Oracle Cloud, DigitalOcean, GitHub, and Apple are recognized locally. Each match says whether the address is the provider's own service, a customer hosted on its cloud, or a shared CDN edge, and is tagged **Reference**; ownership from the offline ASN database is tagged **Inferred**. GeoIP cities remain secondary estimates and are explicitly marked as physically unverified. See [Provider reference](docs/provider-reference.md).
- Related sockets are grouped into service streams by app, protocol, port, and inferred network owner. Stream thickness and packet density reflect the number of underlying sockets; expand the timeline to inspect every endpoint.
- The map is a connection visualization: curves and moving dots illustrate activity. They are not captured packet paths. Traceroute provides separate probe results; geographic placement remains an estimate, and service names are inferred from ports rather than proof of encryption.
- Use the home button to return to the global view.
- Pause or resume the simulated live stream from the control in the top right corner.
- If you started Pulsepath with the collector (via `make start` or `start.command`), switch between live local activity and simulation from the source control in the top right corner.
- The collector view distinguishes connecting, live, stale, and disconnected states and shows the last successful collection time. It reconnects automatically without switching to simulation. An empty feed clears the map; sockets seen within the last 10 seconds are active, while older observations remain static for up to two minutes. Each socket keeps its own last-seen time, including within grouped streams.
- Filter the live feed by application, protocol, service, or IP address. Type for example `WhatsApp` to isolate the Mac app and its helper processes.
- Select a live connection and press `Trace route` (or the `T` key) to actively probe its ordered network hops. Press it again to stop. The probe runs only after you request it; `T` is ignored while you type in a field.
- Without Location Services, Pulsepath places your Mac approximately using only its configured time zone; nothing leaves the machine. Press `Use Mac location` to switch to the Mac's current Location Services estimate. Approve the browser/macOS prompt when it appears; press `Location active` to stop sharing and return to the time zone estimate.
- Open `Security` to see the private connection baseline and explanations for unfamiliar destinations, estimated countries, ports, or switches between VPN and direct network connections.
- Security also highlights sustained outbound transfers that exceed a stream's recently learned traffic baseline, with measured byte counts and comparison evidence.
- For a few well-known apps, Security flags a connection to a network the app does not normally use, such as WhatsApp reaching something other than Meta. This check uses a small curated reference, so it works from the first launch, even during learning. It can only add findings, never hide them.
- Run `make update-references` to refresh the providers' published address lists, then `make restart`. It downloads the same public lists for everyone and sends nothing about your connections.
- When a new destination, an interface change, and an outbound transfer describe the same stream within 30 minutes, Security shows one card. Each observation keeps its own evidence chip. The card is a coincidence to review, not a malware verdict. The stored records stay separate.
- Open any Security finding on the map. If the socket is still active, Pulsepath selects the live route and you can trace it for more information; otherwise it shows a static historical preview clearly marked as an offline estimate and not currently live.
- Use `Pause history` when you do not want new metadata remembered. `Clear local history` permanently removes the local baseline and starts a new learning period.
- **Expected** on a Security card remembers that app, network, protocol, and port. The card leaves the list, the original row stays in the local database, and later repeats of that stream are not shown. Clearing history forgets those acceptances.

## Local security history

Pulsepath stores a small SQLite history at `data/pulsepath-history.sqlite3`. It records connection metadata only: app name, destination IP and port, protocol, interface type, timestamps, byte counters, RTT averages, and offline location estimates for IP addresses. Process IDs and changing local ports are deliberately excluded from the long-term identity so an app remains recognizable after it restarts.

The first launch begins with at least three minutes of learning. After that, Pulsepath explains destinations an app contacts for the first time and highlights stronger changes such as an unfamiliar port or an offline country estimate that has not appeared for that app. These findings are more like behavioral clues than malware verdicts; IP geolocation can be inaccurate and every card shows the evidence behind the explanation.

After learning, a known connection switching between a VPN-style (`utun`) interface and a direct (`en`) interface is recorded as its own change, with the previous and current interface classes. These transitions are recorded even between ordinary counter writes. Repeated observations on the same class do not create duplicate notices, and unknown or mixed interface evidence starts a fresh comparison baseline. Interface names alone do not establish VPN protection or encryption.

When findings from different detectors describe the same stream and the latest falls within 30 minutes of the earliest, Security presents them as one card with a chip for each observation. A repeated finding from only one detector stays on its own card. The overlap is called a coincidence, not a malware verdict, and the underlying rows remain stored separately.

Outbound transfer monitoring has its own learning period: six complete 60-second measurement windows per stream. It compares traffic, normalized to one minute, with the largest of up to 20 recent baseline windows. A finding requires two consecutive windows above both 10 MiB per minute and five times that baseline, with at least 30 minutes between findings for the same stream. Windows that exceed the threshold after learning do not enter the baseline. Backups, uploads, and sync can explain a finding; it is not a malware or data-theft verdict.

Each measurement requires fresh `nettop` counters for every observed socket in the stream and unchanged socket membership throughout the window. Missing counters or streams, counter resets, membership changes, and sampling gaps over 10 seconds break the window and consecutive-window streak. This conservative coverage check can miss short connections and traffic with frequent socket changes; it does not establish coverage of unobserved traffic. Streams use app-name and destination grouping, not verified code-signing identity. Outbound learning lives in memory and starts again after a collector restart, history pause/resume, or history clear. Findings and their measured evidence remain in the existing local SQLite history until cleared.

History never includes packet contents and is never uploaded. Route animation can continue while history recording is paused. There is no automatic retention limit for the connection history or findings yet; only per-address sightings older than 30 days are pruned. **Clear local history** and deleting the database are the ways to remove it.

## Current scope and limits

The local collector observes established TCP and connected UDP/QUIC metadata owned by your user account: process name, PID, local and remote IP address, ports, protocol, service hint, and timestamps. It ignores unconnected UDP listeners. It does not inspect packet contents, decrypt TLS, use external geolocation, or require administrator access.

On macOS, Pulsepath also uses `nettop` to attribute connections delegated through Apple networking services. This enables apps such as WhatsApp to appear with interface, byte totals, and average round-trip time even when their sockets are not visible through `lsof`.

| Visibility | Current Version | Planned |
| --- | --- | --- |
| Established outbound connections for the current Mac user | Yes, best effort | Yes |
| TCP plus connected UDP/QUIC metadata | Yes, best effort | Yes |
| Connections owned by other users or privileged system services | Partial | macOS Network Extension |
| Very short-lived, denied, or inbound connection attempts | Not guaranteed | macOS Network Extension |
| Allow/block decisions like a firewall | No | Per-app rules approved by the user |
| Connections made by other devices on the LAN | No | Optional router/gateway collector |

See [Architecture](docs/architecture.md), [Privacy model](docs/privacy.md), and [Roadmap](docs/roadmap.md) for the intended path from observer to visual firewall.

The optional Mac location control runs entirely in the browser and is never sent to the local collector or an external service. macOS may estimate your Mac's position from nearby Wi-Fi networks and other available Location Services signals. Pulsepath keeps the location only for the current page session.

## Offline connection intelligence

Run `install-geoip.command` (double-click it in Finder, or run `python3 install_geoip.py` in Terminal or inside your IDE) to install two offline databases: DB-IP City Lite (about 124 MB) and DB-IP ASN Lite (about 10 MB), together with the local reader they need. Restart Pulsepath afterward. Pulsepath then resolves the coordinates and network owners of endpoints, and of the hops that answer a traceroute, entirely on your Mac; IP addresses are never sent to a lookup service.

DB-IP City Lite provides approximate locations derived from IP addresses, with reduced coverage and accuracy. DB-IP ASN Lite provides autonomous system numbers and organization names that Pulsepath translates into conservative provider labels such as Meta, Google, or Amazon Web Services. Neither source proves the identity of an application service or physical server. It must not be interpreted as a device, household, or person location. The data is provided by [DB-IP](https://db-ip.com) under the Creative Commons Attribution 4.0 license.

Matches against known edge networks are also resolved locally from providers' published address ranges. A match identifies the serving network, such as Cloudflare, but does not reveal which physical edge facility handled the connection or where the protected service's origin server is located. Cloudflare range data is sourced from [Cloudflare's published IP ranges](https://www.cloudflare.com/ips/).

Remote locations are deliberately marked as pending and use a visual anchor. Traceroute reveals hop order and round-trip time, but an offline GeoIP database is still needed to place those hops geographically.

Some routers and VPNs intentionally ignore traceroute probes. Pulsepath shows unresponsive hops and partial results instead of treating them as failures.

Trace route asks the Mac's DNS resolver for a hostname for each hop address. The name is kept beside the address when the resolver has one. A missing name stays numeric. That name is a resolver answer, not proof of which router or service handled the connection. City and network-owner labels still come only from the offline databases.

Choosing **Trace route** enables that route's traced view for the current page session and starts one finite diagnostic probe. Collected hop markers appear automatically, even with hop details collapsed. While the probe runs, its connection in the **Recent activity list on the left** has a thin teal accent and a **Calculating route…** label. Once calculation finishes, the label becomes **Trace enabled** and the latest snapshot remains available. This does not start automatic repeated probes.

Selecting another connection or switching data sources does not disable an enabled route; multiple routes can remain enabled independently. Results belong to the destination that was probed: if a grouped stream changes destination, the new target does not inherit the previous target's hops. Select an enabled route and choose **Stop tracing route** in the flow timeline or hop details panel to cancel any running probe, disable its traced view and highlight, and return its map view to endpoints. This does not close the application's connection or pause metadata collection. **Trace route** enables it again with a fresh probe.

If the collector cannot confirm a running probe's status, the row says **Trace status unavailable** and keeps the stop action available. A connection that disappears from current socket observations remains in the list while its probe is pending so you can still stop it.

### Intermediate hops and missing replies

After a requested traceroute, **Show hop details** lists probe steps in their original order, including the destination reply when available:

- **Responding:** a router answered; its IP, round-trip time, and usable city estimate are shown. The city remains unverified.
- **Unlocated:** a router answered, but no usable city estimate is available, or the timing check withheld it. Its IP and timing remain visible.
- **No response:** the probe received no reply at that step. Router identity and location stay unknown; no router or city is invented.

Click a map marker or select a hop row to focus it and open its detail card. Map markers also support Tab followed by Enter or Space. The card shows:

- **IP and identity:** the replying IP, available network owner and ASN, and the source of the ownership evidence. Network ownership does not identify a person or a specific router. Silent hops retain unknown identities.
- **Geography and timing:** an available city/region/country estimate, its source and uncertainty, and that probe step's round-trip time from the Mac. Unanswered and unlocated markers use illustrative positions; these positions are never presented as observed coordinates.
- **Connections & protocols:** previous and next probe steps, the selected application's socket transport and destination port, available local process/PID/interface metadata, and reported bytes received/sent by the Mac for sockets matching the traced endpoint. Missing counters remain unavailable, and partial coverage is shown.

Previous/next steps describe **probe order**, not confirmed physical links, the application's exact route, or its return path. Pulsepath cannot observe a remote router's incoming/outgoing traffic, interfaces, or internal connections. Mac socket counters are not router traffic counters. The traceroute probe transport is not recorded and must not be inferred from the application's TCP/UDP transport; payload protocols and encryption are not inspected.

The details panel remains collapsed by default, with additional connection context inside the selected card. Opening or closing details affects only the text and card, not the enabled route's map markers, and sends no extra probes or external identity lookups. A new connection selection or a replaced/empty trace clears obsolete hop details. The probe-step badge counts the ordered rows, including destination replies. Opening the panel cannot recover hidden router identities or paths that traceroute never observed. Simulation hops are labeled as sample data.

### City evidence and verification limits

Pulsepath cannot currently verify which physical city served a connection. An offline GeoIP record is an estimate; an ASN identifies network ownership, and an anycast IP can represent multiple physical sites. Traceroute supplies probe order and round-trip times, not independent city confirmation. Zooming into a city does not increase the certainty of its location.

The **Location evidence** section inside **Show hop details** explains the selected endpoint or focused hop:

- **City unverified:** a GeoIP estimate may be available, but the serving city is unconfirmed. Anycast addresses receive an explicit explanation of the ambiguity.
- **Estimate withheld:** a hop's GeoIP estimate did not pass the existing timing plausibility heuristic. Pulsepath withholds that geographic position and uses an illustrative position between neighboring points instead. The same check applies to the destination. When its database city is too far for the extra round-trip time, the curve ends just beyond the last plausible hop instead of being drawn out to that city, and the label says the city was withheld. The check compares distance with additional round-trip time relative to an estimated anchor; passing it does not verify a city, and the heuristic can reject a correct estimate.
- **No usable city estimate:** the point is a visual anchor, not an observed location.
- **Origin estimate / Device estimate:** the Mac's position comes from its time zone or optional browser Location Services, separately from remote-city evidence.
- **Sample locations:** simulation positions are illustrative.

When available, the panel names the offline city database release. No additional external lookups are made to produce these explanations. A future verified-city label would require independent evidence tied to the specific serving endpoint or session; GeoIP, ASN, and timing agreement alone are insufficient.

## Offline basemap

Pulsepath ships local 1:50m Natural Earth country, state/province, lake, and major river geometry. The browser loads these files only from the local Pulsepath server; no route coordinates are sent to an external tile provider. If the detailed files are unavailable, the original simplified world silhouette remains as a fallback.

Natural Earth map data is public domain. Learn more at [naturalearthdata.com](https://www.naturalearthdata.com).

## Troubleshooting

Reach for the collector log first. `make start` runs the collector in the background and writes it to `~/Library/Caches/Pulsepath/server.log` (or `$TMPDIR/Pulsepath/server.log` when `HOME` is unset). To watch it live instead, run `make run`, which starts the collector in the foreground with `--no-open` and prints its output.

**The browser does not open, or the page is blank**

- Open `http://127.0.0.1:4173/` manually. `make start` waits for the local API before it opens the browser.
- If the page loads but stays empty, check the log and the collector status in the top right corner, then reload.

**`make stop` says "Pulsepath is not running"**

- This is expected when nothing was running. If you started the collector in another terminal with `make run` or `python3 pulsepath.py`, stop it there with Control-C.

**The port is already in use**

- Another process holds TCP port 4173. Check with `lsof -nP -iTCP:4173 -sTCP:LISTEN`, or start on another port: `python3 pulsepath.py --port 4174`. `make start` always uses 4173.

**The collector shows disconnected, or the feed stays empty**

- The interface reconnects automatically; if the status keeps reading disconnected, the collector process stopped. Check the log, then run `make restart`.
- An empty feed is normal on an idle Mac. A socket is active if it was seen in the last 10 seconds; older observations stay static for up to two minutes.

**Byte counters, interface, or RTT are missing for an app**

- Those fields come from `nettop`. If `nettop` is unavailable, Pulsepath falls back to `lsof` metadata alone. Sockets owned by other users or privileged system services may stay invisible. See [Current scope and limits](#current-scope-and-limits).

**City, region, or network-owner labels are missing**

- The offline DB-IP databases are not installed. Run `install-geoip.command` (double-click it in Finder) or `python3 install_geoip.py`, then `make restart`.
- If macOS refuses to open the `.command` file, right-click it and choose **Open**.
- These labels are still estimates and stay marked as unverified even when present.

**Traceroute shows only "No response", or partial hops**

- Many routers and VPNs drop probe packets. Pulsepath lists unresponsive steps instead of inventing routers. Try again, and remember an offline GeoIP database is still needed to place any hop that answers.

**The animation is not moving**

- Check **Pause animation**, the system reduced-motion setting under **System Settings → Accessibility → Display**, and whether the browser tab is in the background. Simulation can also be paused from the top-right control.

**"Trace status unavailable"**

- The collector could not confirm the running probe's status. The stop action stays available so you can cancel it.

**`make check` fails while parsing JavaScript**

- The JavaScript parse step needs Node.js (`node`). The Python tests run without it: `python3 -m unittest discover -s tests -v`.

**`python3` is too old**

- Pulsepath requires Python 3.11 or newer. Check `python3 --version` and point `python3` at a newer install.

## Uninstall and data removal

Pulsepath installs nothing system-wide, registers no login item, and adds no privileged helper. To remove it and the data it created:

1. Stop the collector: `make stop`.
2. Optionally reset history from the app first with `Security` → **Clear local history**.

Then delete the local data you no longer want:

- **Local history:** `data/pulsepath-history.sqlite3`, plus any `-wal` and `-shm` sidecars. Pulsepath recreates these on the next launch. The `data/` directory is set to `0700` and the database to `0600`.
- **Offline GeoIP data:** `data/dbip-*.mmdb` and any `data/*.part` files. Re-run `install-geoip.command` to restore them.
- **Vendored MMDB reader:** the `vendor/` directory installed by `install_geoip.py`.
- **Runtime files:** `~/Library/Caches/Pulsepath` (`server.pid`, `server.log`). When `HOME` is unset, the same files live under `$TMPDIR/Pulsepath`.
- **The application itself:** delete the cloned folder, or run `git clean -xfd` inside it to remove everything not tracked by Git.

If you enabled the native Network Extension observer, disable it from that app and remove it under **System Settings → Network → Filters** (wording varies by macOS) before deleting the build. See [macos/README.md](macos/README.md) for recovery steps.

## Native observer

The always-allow Network Extension lives in [`macos/`](macos/README.md). It is not on at launch. The Python collector remains the UI until that host takes over.

## Development

Run the standard checks before opening a pull request:

```sh
make check
```

`make check` runs the test suite, compiles the Python sources, and parses the browser JavaScript. The JavaScript parse step requires Node.js. Ruff and pyright are configured in `pyproject.toml` for editors that read it, but are not required to run the tests. Run a single test module directly, for example:

```sh
python3 -m unittest tests.test_collector -v
```

The test suite uses Python's standard library. The optional GeoIP reader is installed only when requested and is pinned by version and sha256 hash in `requirements-geoip.txt`, so a tampered package upload cannot be installed silently.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Please report security issues according to [SECURITY.md](SECURITY.md), not in a public issue.

## Getting help

- Questions and bug reports: open an issue in the project's tracker using the provided templates. Remove real connection metadata, app names, and destination IPs from screenshots and logs before posting.
- Security reports: follow [SECURITY.md](SECURITY.md) and report privately.

## License

Pulsepath is licensed under the [Apache License 2.0](LICENSE). Data and components from third parties retain their own terms; see [NOTICE.md](NOTICE.md).
