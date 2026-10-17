# Network Extension observer (0.4a)

Sources for this slice are in [`macos/`](../macos/README.md). The filter always returns allow and is not enabled at launch. The Python UI is unchanged.

This is the first Network Extension slice. It observes flow lifecycle on this Mac and always returns allow. It does not make firewall decisions.

Roadmap 0.4 currently mixes observer and verdicts. Those must not ship together. Verdicts, prompts, and signed local rules are 0.4b and need lockout recovery that 0.4a does not have.

## Why this exists

The current collector polls `lsof` and `nettop`. It sees established TCP and connected UDP/QUIC owned by the logged-in user. It does not reliably see:

- inbound flows
- short-lived connections that close between polls
- flows owned by other users or privileged system services
- attempts the OS already denied

Apple's supported way to get that lifecycle is a content-filter system extension (`NEFilterDataProvider`). Pulsepath should use it as an observer first, then as a firewall.

## Prerequisite: 0.3

A Network Extension cannot live inside `pulsepath.py` and `index.html`. 0.4a needs the native shell from 0.3:

- a signed Swift/SwiftUI host app
- an Xcode Network Extension / System Extension target
- the Network Extensions capability
- notarization
- an explicit user approval prompt for the system extension

Until that host exists, this document is the contract. Do not add a `.swift` filter target to the Python prototype.

Unsigned local builds keep using `lsof` and `nettop`. The UI must say which observer is active.

## Placement

```text
macOS content filter (always allow)
        │ metadata only, no payloads
        ▼
privileged flow broker
        │ versioned XPC
        ▼
unprivileged Pulsepath app
        ├── FlowCollector / in-memory flows
        ├── HistoryEngine
        └── existing map, timeline, Security findings
```

The Python loopback HTTP API is a prototype control plane. 0.3 should replace it with the same XPC schema. 0.4a must not add a second browser-facing API.

## Verdict rule for 0.4a

`handleNewFlow` (and any equivalent) returns **allow** for every flow, including Pulsepath's own traffic.

There is no user prompt, no rule file, and no block path in this slice. If a future change can return deny, that change is 0.4b and needs its own threat model.

Pulsepath's signed flows and its loopback control channel must still be allowed even in 0.4b. 0.4a should already identify those flows so the later rule engine has a fail-open path.

## XPC contract

The UI process must not be able to ask the extension to run commands, read memory, or dump packets. The broker exposes a small, versioned schema. Unknown fields are ignored; unknown message types are rejected.

### `ObserverHello`

Sent by the app after the extension is loaded.

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer. Current: 1 |
| `app_code_signing_id` | Host app identity the extension should treat as Pulsepath |

The extension replies with `schema_version` it speaks and whether it is observing.

### `FlowEvent` (extension → app)

One message per lifecycle transition, not per packet.

| Field | Evidence level | Notes |
| --- | --- | --- |
| `schema_version` | — | Must match |
| `observer` | Observed | Always `network-extension` |
| `event` | Observed | `started`, `ended`, `denied-by-os` |
| `direction` | Observed | `inbound` or `outbound` |
| `protocol` | Observed | `TCP`, `UDP`, or the kernel's protocol id if neither |
| `local_ip`, `local_port` | Observed | Include only if the filter supplies them |
| `remote_ip`, `remote_port` | Observed | Documentation ranges in tests |
| `flow_token` | Observed | Extension-assigned id. Not a PID. Stable for the life of the flow |
| `bundle_id` | Observed | When macOS provides it |
| `code_signing_id` | Observed | When macOS provides it |
| `team_id` | Observed | When macOS provides it |
| `app_family` | Inferred | Host-side normalization, same as today's helper collapse |
| `bytes_in`, `bytes_out` | Observed | Only from filter counters, never by buffering bodies |
| `started_at`, `ended_at` | Observed | |
| `interface_type` | Observed | e.g. Wi-Fi, Ethernet, VPN, if the API exposes it |

Do not send:

- packet payloads or truncated payloads
- TLS plaintext, certificates, or SNI unless a later 0.2 design adds them with a separate consent surface
- DNS question names in this slice (that is 0.2 correlation, not the filter dump)
- full command lines, environment, or arguments
- other devices' traffic (this observer is on-device only)

The host maps `FlowEvent` onto the existing `Flow` identity. Prefer `code_signing_id` + `team_id` + remote service identity over PID and local port, which is already HistoryEngine policy.

Denied-by-OS events are first-class. The UI should label them as observed denials, not as Pulsepath blocks.

## What stays on the existing path

Offline GeoIP, ASN, Cloudflare range matching, traceroute, history learning, and Security findings stay in the unprivileged app. The extension does not look up cities or providers.

Loopback and link-local flows stay out of long-term history, same as today.

## Activation and failure

1. The host explains, before the system prompt, that Pulsepath will see connection metadata for all apps on this Mac, not message contents.
2. If the user declines, Pulsepath keeps the `lsof`/`nettop` observer and states the limitation.
3. If the extension crashes or is unloaded, fail open: all flows stay allowed, the UI switches to the unprivileged observer, and no rules are applied (there are none).
4. Uninstall must remove the system extension. Leaving a silent filter after deleting the app is a defect.

CI on GitHub cannot load a real system extension. Tests for 0.4a should feed synthetic `FlowEvent` messages using documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) into HistoryEngine and the UI. Manual checks on a signed Mac are a release gate, not a unit-test substitute.

## 0.4b (explicitly out of scope here)

- allow / block / ask
- signed local rules
- decision prompts in the UI
- lockout recovery if Pulsepath rules break networking
- protecting the Pulsepath control plane from being blocked by those rules

Architecture already states the shape: privileged broker, narrow XPC, packet bodies outside the main app. 0.4b may begin only after 0.4a is observing real flows on signed builds without dropping traffic.

## Non-goals

- TLS interception or custom certificates
- reading message contents
- uploading flows
- treating a filter event as proof of malware
- claiming LAN-wide visibility (that needs a gateway collector)

## Platform references

- [NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)
- [Configuring network extensions](https://developer.apple.com/documentation/xcode/configuring-network-extensions)
- [System Extensions](https://developer.apple.com/system-extensions/)

LuLu remains a product and UX reference only. Pulsepath must not copy LuLu code.

## Related docs

- [Architecture](architecture.md)
- [Privacy model](privacy.md)
- [Roadmap](roadmap.md)
- [Security policy](../SECURITY.md)
