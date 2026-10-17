# Third-party notices

Pulsepath itself is licensed under Apache-2.0. The following data and optional software retain their own terms.

## Natural Earth

The repository includes Natural Earth 1:50m country, state/province, lake, and river geometry in `data/`. Natural Earth data is public domain.

Source: https://www.naturalearthdata.com/

## DB-IP City Lite and ASN Lite

`install-geoip.command` optionally downloads DB-IP City Lite and ASN Lite. The databases are not committed to this repository. Both are licensed under Creative Commons Attribution 4.0.

Source: https://db-ip.com/db/download/ip-to-city-lite

ASN source: https://db-ip.com/db/download/ip-to-asn-lite

License: https://creativecommons.org/licenses/by/4.0/

## Provider published IP ranges

`install_references.py` downloads providers' published address ranges and keeps a local snapshot so a match can label the serving network. A match identifies that network, not a physical facility, an origin server, or a hosted customer. Curated networks for a few well-known apps are stored separately in `references/app-networks.json`.

- Cloudflare: https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
- Google (`goog.json` and `cloud.json`): https://www.gstatic.com/ipranges/goog.json and https://www.gstatic.com/ipranges/cloud.json
- AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
- Fastly: https://api.fastly.com/public-ip-list
- Oracle: https://docs.oracle.com/iaas/tools/public_ip_ranges.json
- DigitalOcean geofeed: https://digitalocean.com/geo/google.csv
- GitHub `/meta`: https://api.github.com/meta
- Apple: `17.0.0.0/8`, as registered with ARIN. No list is fetched.

## MaxMind DB reader for Python

The optional installer pins and installs `maxminddb` locally into `vendor/`. The installed copy is not committed to this repository. The package is distributed under the Apache License 2.0.

Source: https://github.com/maxmind/MaxMind-DB-Reader-python

No LuLu source code or assets are included. LuLu is referenced only as an independent open-source macOS firewall and product inspiration.
