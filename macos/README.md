# Pulsepath native observer (0.4a)

This is the signed-macOS shell and content-filter system extension. It is observe-only: the filter always returns allow and never peeks at packet bytes.

The Python collector in the repo root is still the UI. This app does not replace it yet, and it does not turn the filter on at launch.

## What you need

- Apple Developer Program membership (system extensions will not load with only a personal team)
- Set your own Team ID on both targets in Xcode. `DEVELOPMENT_TEAM` is empty in the project file
- The Network Extensions capability: Content Filter
- System Extension entitlement on the host
- To run locally: `systemextensionsctl developer on` (SIP considerations are Apple's, not something to disable casually)

Bundle IDs (change the prefix if you already own a different one):

- Host: `app.pulsepath.Pulsepath`
- Filter: `app.pulsepath.Pulsepath.Filter`

## Build

Open `macos/Pulsepath.xcodeproj` in Xcode. Select the Pulsepath scheme, set your own Team, then Run. In the app, read the explanation and press **Enable observer** only when you are willing to approve a system extension on this Mac.

Disable from the same screen before deleting the app. A leftover filter in System Settings can stall networking.

## Recovery if networking stalls

1. In this app, press **Disable observer**.
2. System Settings → Network → Filters (wording varies by macOS) and remove Pulsepath.
3. Reboot if `handleNewFlow` has stopped being called. That is a known kernel-path issue, not a fried NIC.

## Non-goals for this slice

- allow / block / ask
- replacing `lsof` in `pulsepath.py`
- App Group event pipe into HistoryEngine (next)
- notarization
