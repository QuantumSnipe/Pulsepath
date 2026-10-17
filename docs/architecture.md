# Architecture

Pulsepath deliberately separates observation, analysis, and presentation. That makes privacy boundaries visible and gives the project a path from today's unprivileged prototype to a signed macOS firewall.

## Current alpha

```text
macOS lsof + nettop
        │ metadata only
        ▼
Python collector ── offline DB-IP city + ASN lookup
        │
        ├── in-memory active flows
        ├── local SQLite history and findings
        └── loopback-only HTTP API
                     │
                     ▼
             local browser interface
```

- `pulsepath.py` polls `lsof` and `nettop`, groups related sockets into service streams, runs user-requested traceroutes, performs offline city and network-owner lookups, and serves the local API.
- `HistoryEngine` stores a stable app/service identity without using transient process IDs, local ports, or rotating edge IPs when a stronger provider identity is available.
- `behavior.py` provides `OutboundMonitor`, which compares fresh per-socket outbound counter differences before the history write throttle and returns evidence for findings stored by `HistoryEngine` in the same SQLite database.
- `index.html` renders the local UI and Natural Earth basemap. It loads no remote scripts.
- `data/pulsepath-history.sqlite3` contains private local history and is excluded from Git.

The HTTP server binds only to `127.0.0.1`. It validates the `Host` header, validates browser origins for mutating requests, sends a restrictive script policy, and never enables cross-origin API access.

## Outbound transfer evidence

The monitor tracks streams by normalized app name, protocol, remote port, and grouped destination identity. These are observed names and inferred destination groups, not authenticated application identities. It differences individual `nettop` socket counters rather than grouped lifetime totals, requiring fresh counters for every observed socket and stable socket membership over each measurement window. A missing stream or counter, stale sample, counter decrease, socket membership change, or sampling gap over 10 seconds discards the partial window and breaks the consecutive-window streak. Unobserved traffic remains unknown.

Windows cover at least 60 seconds and are normalized to a 60-second byte count. After six complete baseline windows, a window is unusual only when its normalized count is strictly greater than both 10 MiB and five times the largest baseline window. The baseline retains at most 20 recent accepted windows; unusual windows are excluded after learning. Two consecutive unusual windows produce a finding, subject to a 30-minute cooldown per stream. A finding contains measured bytes and duration, baseline and threshold values, socket count, and the counter source and coverage limitation. Its map anchor is one measured endpoint; the reported total covers the grouped stream.

Counter snapshots, learning windows, streaks, and cooldowns remain in memory, bounded to 1,024 streams. Collector restart, history pause/resume, and history clear reset that state; persisted findings survive restart and pause. Broken measurement continuity preserves the learned baseline but requires a fresh complete window. The detector uses existing collection only, adds no upload or payload inspection, and cannot determine whether a transfer is malicious. Ordinary uploads and backups can trigger it, while short connections and frequent socket changes can prevent a finding.

## Coinciding findings

Novelty, interface-change, and outbound-transfer rows stay independent in SQLite. The security summary groups them only at presentation time: same normalized app, protocol, port, and destination, and only when the latest observation is within 30 minutes of the earliest. A group becomes one card when it contains at least two detector kinds. Each kind keeps its own evidence chip, including every repeated observation inside the episode. Repeats of a single kind stay separate cards. The card is labeled a coincidence to review, not a verdict. One such card counts once toward the recent-change badge.

## Target: visual application firewall

The first shipped slice is observe-only and always returns allow. See [Network Extension observer](network-extension.md). Verdicts stay in a later 0.4b.

The correct macOS foundation for complete on-device flow visibility is a signed Network Extension content-filter system extension. Apple describes content filters as the supported way to inspect new flows and return allow or block verdicts. The extension requires an Xcode target, the Network Extensions capability, code signing, notarization, and explicit user approval.

```text
macOS Network Extension
   │ observed inbound/outbound flow metadata
   │ allow / block / ask verdict
   ▼
privileged flow broker  ◄──── signed local rules
   │ XPC, narrow typed messages
   ▼
unprivileged Pulsepath app
   ├── map and timeline
   ├── local behavior baseline
   └── human-readable decision prompt
```

The system extension should emit the least metadata required for a decision. Packet bodies should remain outside the main app. The UI process must never be trusted to issue arbitrary privileged commands; communication should use a narrow, versioned XPC schema.

Relevant platform references:

- [Apple Network Extension](https://developer.apple.com/documentation/networkextension)
- [Apple: Configuring network extensions](https://developer.apple.com/documentation/xcode/configuring-network-extensions)
- [Apple: NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)
- [Apple: System Extensions](https://developer.apple.com/system-extensions/)
- [LuLu source repository](https://github.com/objective-see/LuLu) as a product and UX reference only; Pulsepath does not copy LuLu code.

## Third-party attribution

"Third party" is not one fact. Pulsepath should keep three evidence levels separate:

1. **Observed identity** — signed process, bundle identifier, code-signing team, destination IP and port, interface, timing.
2. **Inferred owner** — local IP-to-ASN allocation, DNS correlation, and TLS hostname or certificate metadata when the platform safely provides it.
3. **Reference classification** — a versioned local dataset describing known service providers, trackers, CDNs, or threat indicators.

The interface should label each item as **Observed**, **Inferred**, or **Reference** and display its source and age. A match means “this destination appears in this reference,” not “this app is malicious.” Remote reputation lookups should be opt-in because they disclose the destination being checked.

## Seeing the whole network

A Mac normally cannot observe unicast traffic exchanged by other devices on a switched Wi-Fi or Ethernet network. Whole-LAN visibility therefore needs one of these explicit integrations:

- a Pulsepath collector running on the router or gateway;
- a supported router's flow logs or connection-tracking feed;
- a managed network sensor connected to a mirror port.

The laptop UI can merge those feeds later, but should never imply that its local observer covers devices it cannot see.
