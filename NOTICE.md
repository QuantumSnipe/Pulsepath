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

## Cloudflare published IP ranges

`pulsepath.py` hardcodes published Cloudflare edge prefixes so a local match can label anycast infrastructure. A match identifies the serving network, not a physical facility or an origin server.

Source: https://www.cloudflare.com/ips/

## MaxMind DB reader for Python

The optional installer pins and installs `maxminddb` locally into `vendor/`. The installed copy is not committed to this repository. The package is distributed under the Apache License 2.0.

Source: https://github.com/maxmind/MaxMind-DB-Reader-python

No LuLu source code or assets are included. LuLu is referenced only as an independent open-source macOS firewall and product inspiration.
