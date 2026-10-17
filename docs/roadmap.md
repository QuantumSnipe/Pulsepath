# Roadmap

## 0.1 — Local visual observer

- Live macOS connection metadata from `lsof` and `nettop`
- Offline map and IP city estimates
- User-requested traceroute
- Local history, learning period, and explainable novelty findings
- Service-level stream grouping with inspectable raw sockets
- Offline IP-to-ASN network-owner inference
- Privacy controls and repository security baseline

## 0.2 — Better identity and evidence

- Normalize macOS bundle identifiers and signed application identity
- Correlate local DNS activity with destinations
- Add signed application identity to the current app-family normalization
- Add **Observed**, **Inferred**, and **Reference** confidence labels (provider ownership labels shipped: [Provider reference](provider-reference.md))
- Export and import redacted investigation sessions
- Add history retention limits and per-app exclusions

## 0.3 — Native macOS app shell

- Swift/SwiftUI host app
- Signed update and packaging pipeline
- Narrow local IPC instead of a browser-facing control API
- Accessibility, onboarding, and permission explanations

## 0.4 — Network Extension observer

Design for the first slice: [Network Extension observer](network-extension.md) (0.4a, observe-only).

- Content-filter system extension for complete on-device flow lifecycle events
- Inbound, outbound, short-lived, and denied-flow visibility
- Always-allow observer before any verdicts (0.4a)
- Per-app allow, block, ask, and temporary decisions (0.4b)
- Tamper-resistant, signed local rules (0.4b)
- Explicit protections against lockout and blocking the Pulsepath control plane (0.4b)

## Later — Optional LAN visibility

- Router/gateway collector protocol
- Authenticated device enrollment and encrypted transport
- Clear device/source attribution on the map
- No claim of whole-network coverage without a configured gateway source

## Non-goals

- TLS interception or silent certificate installation
- Reading message contents
- Uploading connection history by default
- Treating GeoIP or a reputation-list match as proof of malicious behavior
