# Privacy model

Pulsepath is local-first. Network metadata is sensitive even when payloads are not captured, so the project treats collection scope and retention as security boundaries.

## Data stored locally

- app/process name;
- remote IP, remote port, protocol, and service hint;
- interface category, timestamps, byte counters, and RTT averages;
- offline IP-location estimates;
- the network owner and class (provider service, cloud customer, or CDN edge) derived from local reference data;
- locally generated novelty, interface-change, outbound-transfer, and unexpected-network findings and their evidence.

The long-term identity excludes PID and local ephemeral port. Browser-provided Mac location remains in the page session and is not sent to the Python collector.

A coincidence card only groups findings already stored for the same stream. It adds no collection or uploads. Outbound-transfer findings use byte counters already collected through `nettop`; they add no collection or uploads. The existing SQLite history stores each finding's app name, destination context, measured byte count and duration, baseline and threshold values, socket count, and coverage explanation. Per-socket comparison state and the rolling outbound baseline remain in memory and reset on collector restart, history pause/resume, or history clear. App names and destination groups are not verified signed application identities, and a finding does not establish malware or data theft.

## Data not collected

- message, file, or packet contents;
- decrypted TLS content;
- browser cookies, passwords, or authentication tokens;
- contacts, message recipients, or chat text;
- remote analytics or telemetry.

## User controls

- **Pause history** stops new records and outbound analysis while leaving the live visualization available. Pausing and resuming reset outbound learning; existing findings remain.
- **Clear local history** deletes the SQLite baseline, findings, and remembered expected streams, clears in-memory outbound learning, and starts learning again.
- **Expected** records the app, network, protocol, and port locally and hides later findings for that stream. It does not delete the original finding.
- **Use Mac location** is off by default and can be stopped at any time.
- **Trace route** runs only after the user requests it.

## Reference data

Provider address lists and the expected-networks list for apps are local files (see [Provider reference](provider-reference.md)). Matching a connection against them happens on the Mac.

`make update-references` runs only when you invoke it. It downloads each provider's own public list over HTTPS from that provider's domain; the request is identical for every user and carries no connection data. TLS authenticates the publisher, so this slice needs no Pulsepath-hosted mirror or signing key.

## Future integrations

Other third-party reference data should be downloaded as a signed, versioned dataset without uploading a user's connection history. If remote reputation checks are ever offered, they must be disabled by default and explain exactly what destination data will leave the Mac.

Network Extension builds should keep packet bodies inside the extension sandbox and pass only minimal flow metadata and verdict state to the UI.
