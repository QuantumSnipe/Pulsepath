# Contributing to Pulsepath

Thank you for helping build a transparent, privacy-respecting network tool.

## Before you start

- Open an issue before a large architectural change.
- Keep payload inspection, external telemetry, blocking, or privileged collection out of a pull request unless the change has an explicit threat model and user-consent design.
- Never commit real connection history, packet captures, private IP inventories, tokens, certificates, provisioning profiles, or signing keys.
- Treat app names, destination IPs, DNS names, and network timing as sensitive metadata in screenshots and fixtures.

## Local checks

```sh
make check
```

Tests must use documentation ranges such as `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` instead of real user destinations.

## Pull requests

A focused pull request should explain:

1. what changes for the user;
2. what data is newly observed, retained, displayed, or transmitted;
3. how failure behaves;
4. how the change was tested;
5. any macOS permission, entitlement, signing, or compatibility impact.

UI language must distinguish observed facts from inferred location/ownership and third-party reference matches.

## Security-sensitive changes

Changes to the local API, system extension, IPC, update mechanism, rule engine, installer, or external data ingestion require tests for their trust boundary. Avoid string-built code or HTML, remote scripts, broad filesystem access, shell interpolation, and permissive network listeners.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
