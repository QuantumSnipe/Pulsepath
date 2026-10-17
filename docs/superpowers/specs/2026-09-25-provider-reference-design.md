# Provider reference data: design

Date: 2026-09-25
Status: implemented on branch `provider-reference`
Roadmap: 0.2 — Better identity and evidence (Observed / Inferred / Reference labels)

## Goal

Make network ownership a sharper security signal without sending anything off the Mac.

1. **Provider ranges.** Use the address lists that providers publish to tell three kinds of address apart: the provider's own services, a customer's server hosted on the provider's cloud, and a shared CDN edge.
2. **App reference.** Keep a small, hand-curated list of the networks well-known apps are expected to use, and flag connections outside that list, including during the learning period.

Today Pulsepath infers the owner from the offline DB-IP ASN database, plus a hard-coded Cloudflare list. "Google network" can mean Google's own APIs or any stranger's server on Google Cloud, and a new app gets no novelty findings until the learning period ends.

## Non-goals

- Remote reputation lookups (VirusTotal and similar). They disclose destinations; see `docs/privacy.md`.
- Hostname or TLS correlation. It needs the Network Extension (roadmap 0.4).
- Signed application identity. App identity stays the process name until roadmap 0.2 delivers signing.
- Quieting findings. The app reference only ever adds attention.
- Azure, Meta and Akamai ranges. Azure's download link changes weekly; Meta and Akamai publish no list. They stay ASN-inferred.

## Decisions

| Question | Decision |
|---|---|
| What may the app reference do? | Raise flags only. It never lowers, merges away, or hides a finding, because a process name can be imitated. |
| How do range lists reach the Mac? | A generated snapshot is kept in the repo, and `make update-references` fetches fresh official lists into `data/`. The newer file wins. |
| How is the difference expressed? | Three network classes: `service`, `hosted`, `edge`. |
| UI wording | Short and plain. Caveats live in `docs/provider-reference.md`, and a one-word evidence tag stays in the UI. |

## Network classes

| Class | Meaning | Label examples |
|---|---|---|
| `service` | The provider's own services | Google services, Amazon services, Apple services, GitHub services |
| `hosted` | A customer's server on the provider's cloud; the customer is unknown | Google Cloud customer, AWS customer, Oracle Cloud customer, DigitalOcean customer |
| `edge` | A shared CDN or proxy edge in front of many customers | Cloudflare edge, CloudFront edge, Fastly edge |

Only addresses matched by a published list get a class. ASN-inferred owners (Meta, Anthropic, Akamai, ISPs) have no class.

## Data files

### `references/provider-ranges.json` (generated, committed)

`data/provider-ranges.json` has the same format. It is written by the update command and is not committed.

```json
{
  "format": 1,
  "generated_at": "2026-09-25T12:00:00Z",
  "sources": {
    "google": {
      "name": "Google",
      "urls": ["https://www.gstatic.com/ipranges/goog.json", "https://www.gstatic.com/ipranges/cloud.json"],
      "version": "<syncToken>",
      "published": "<creationTime>",
      "prefix_count": 1234
    }
  },
  "groups": [
    {
      "provider": "Google",
      "class": "hosted",
      "tag": "Google Cloud",
      "source": "google",
      "anycast": false,
      "v4": ["34.149.0.0/16"],
      "v6": []
    }
  ]
}
```

Rules:

- **Disjoint ranges:** no address may fall in two groups. The generator guarantees this and the loader verifies it.
- **Canonical names:** `provider` uses the same canonical name that `canonical_provider()` returns for the ASN path, such as "Amazon Web Services" or "Google". Novelty history compares these names.
- **Deterministic output:** groups and prefixes are sorted, so snapshot diffs are reviewable.
- **Size:** about 0.5 MB, one prefix per line so diffs stay reviewable. AWS customer ranges are three quarters of it. Adjacent prefixes within a group are merged.

### First-cut sources and class rules

| Source key | URL | Class rules |
|---|---|---|
| `cloudflare` | `https://www.cloudflare.com/ips-v4`, `https://www.cloudflare.com/ips-v6` | all `edge`, anycast |
| `google` | `https://www.gstatic.com/ipranges/goog.json`, `https://www.gstatic.com/ipranges/cloud.json` | in `cloud.json` → `hosted` (Google Cloud); in `goog.json` only → `service` |
| `aws` | `https://ip-ranges.amazonaws.com/ip-ranges.json` | `CLOUDFRONT` → `edge`; `EC2`, `S3`, `API_GATEWAY`, `GLOBALACCELERATOR` → `hosted` (S3 buckets hold customer content); everything else, including `AMAZON`-only prefixes → `service` |
| `fastly` | `https://api.fastly.com/public-ip-list` | all `edge`, anycast |
| `oracle` | `https://docs.oracle.com/iaas/tools/public_ip_ranges.json` | all `hosted` (Oracle Cloud) |
| `digitalocean` | `https://digitalocean.com/geo/google.csv` | all `hosted` |
| `github` | `https://api.github.com/meta` | all `service` |
| `apple` | constant `17.0.0.0/8` (registry allocation) | `service` |

When two sources overlap, the more specific prefix wins. On a tie, source order in this table decides.

### `references/app-networks.json` (hand-curated, committed)

```json
{
  "format": 1,
  "reviewed": "2026-09-25",
  "apps": [
    {
      "app": "WhatsApp",
      "processes": ["whatsapp"],
      "expected": [{ "provider": "Meta" }],
      "source": "observed 2026-09"
    },
    {
      "app": "Claude",
      "processes": ["claude"],
      "expected": [
        { "provider": "Anthropic, PBC" },
        { "provider": "Cloudflare", "class": "edge" },
        { "provider": "Google", "class": "hosted" }
      ],
      "source": "observed 2026-09"
    }
  ]
}
```

- **`processes`:** case-insensitive prefixes of the raw process name. The file does not change `application_name()`, because that function derives history `process_key`, and a new alias would re-key existing history.
- **`expected`:** each entry is a canonical `provider`, optionally narrowed by `class`. Without `class`, any class of that provider matches.
- **`source`:** required. It is a vendor documentation URL, or `observed <YYYY-MM>` when no vendor source exists. The evidence level shows in the finding.
- **Initial list:** WhatsApp, Claude and Apple push (`apsd`), each grounded in connections observed on the maintainer's Mac in September 2026. Zoom and Microsoft Teams wait until their entries can be verified against observed traffic or vendor pages.
- **Never listed:** browsers, `curl`, Python, Node, package managers, VPN clients, `nsurlsessiond`, and any other process that legitimately reaches arbitrary hosts.

## Components

### `references.py` (new, standard library only)

- **`ProviderRanges.load(snapshot, refreshed)`:** reads both files and uses the one with the newer `generated_at` as a whole. A file that fails validation (format, prefix syntax, overlap, size cap) is skipped. If both fail, lookups return `None`.
- **`ProviderRanges.lookup(ip)`:** binary search over sorted `(start, end, group)` intervals per IP version. Returns `provider`, `class`, `tag`, `anycast`, `source`, and the source `published` date, or `None`. About a microsecond per lookup, so no cache.
- **`ProviderRanges.status()`:** `state` is `ok`, `stale` or `unavailable`, plus `generated_at` and per-source age. A source is stale after 60 days; stale data is still used.
- **`AppNetworks.load(path)`** and **`AppNetworks.expectation(process)`:** return the matching app entry or `None`.
- **`AppNetworks.allows(entry, provider, cls)`:** whether this owner is expected.

### `install_references.py` (new) and `make update-references`

- **Fetching:** all sources over HTTPS only, following `install_geoip.py`: `User-Agent: Pulsepath/0.1`, 45 s timeout, and a 16 MB cap per response.
- **Normalizing:** parses each source, applies the class rules, resolves overlaps, merges adjacent prefixes, and writes `data/provider-ranges.json` atomically (temp file, then rename).
- **Per-source fallback:**
  - If a source fails to download or parse, its previous groups are kept from the current data file, or the snapshot.
  - If a source's prefix count drops below half of the previous count, the previous groups are kept, with a warning. To accept a genuine shrink, delete `data/provider-ranges.json` and run again.
- **Validation:** rejects loopback, link-local, multicast, unspecified, RFC 1918, CGNAT (`100.64.0.0/10`) and ULA prefixes. Documentation ranges stay valid, so tests can use them. There is a total cap of 200,000 prefixes.
- **`--snapshot`:** a maintainer flag that writes `references/provider-ranges.json` instead.
- **Makefile:** `check` also runs `py_compile` on `references.py` and `install_references.py`.

### Changes in `pulsepath.py`

- **`canonical_provider()`:** add Oracle and GitHub. Both lookup paths must produce the same names.
- **`network_reference(host, asn)`:**
  1. A range match returns `confidence: "reference"` with `service_class`, `tag`, `anycast` and source details. `name` is the canonical provider; `label` is the class label.
  2. Otherwise the ASN path runs as today, with `confidence: "inferred"` and no class.
  3. The hard-coded `CLOUDFLARE_NETWORKS` is removed, since Cloudflare comes from the dataset.
- **`flow_destination_key()`:** for flows with a class, the key becomes `provider:<name>:<class>`. ASN-only flows keep `provider:<name>`. A group therefore never mixes classes, and its label stays true for every socket in it.
- **History migration:**
  - Add a nullable `network_class TEXT` column to `connections` through the existing `migrations` map.
  - `enrich_network_ownership()` runs at every collector start and already recomputes `network_reference()` for every row. It now also:
    - writes `network_class` and the new `destination_key`;
    - rewrites `fingerprint` with `history_identity()` for that key, because the fingerprint hashes `destination_key`;
    - moves matching `findings` fingerprints with `UPDATE OR IGNORE`, following the lazy re-key that `observe` already does for the older raw-IP scheme.

    Old history is therefore classified and re-keyed in one pass, and history always reflects the current lists after a restart.
- **Familiarity:** `provider_seen` compares provider and class, using `IS` so an ASN-only class of `NULL` matches `NULL`. A known provider reached in a new class is a new network. Reason: "First connection to a Google Cloud customer."
  - Before declaring a class new, check the app's `ip_sightings` rows, which hold every address the app contacted, classified with the same lookup. A pre-upgrade stream that mixed classes under one key was classified by its last address only, so this check stops a one-time wave of findings for classes the app already used.
- **App reference findings:**
  - For a public destination whose process matches an app entry, and whose provider and class are not allowed, add the reason and set `event_type: "unexpected_network"`. A destination with no known owner is not allowed.
  - This check runs **even while `learning` is true and when `process_rows == 0`.** In those cases the finding carries only this reason. Otherwise it merges into the normal novelty finding.
  - Title: "Unexpected network for WhatsApp". Text: "WhatsApp usually uses Meta. This connection goes to Amazon Web Services."
  - Evidence adds `reference_expected`, `reference_source` and `reference_reviewed`. `_finding_kind()` recognizes `unexpected_network`.
  - One finding per app, provider and class. The finding fingerprint hashes `destination_key`, which now includes the class.
  - Excluded destinations: loopback, link-local, RFC 1918, CGNAT (`100.64.0.0/10`) and ULA. The collector's `scope` field is not used here, because it counts documentation ranges as private, and tests rely on those ranges.
- **Expected marks:** `_stream_is_expected()` also matches the legacy key without the class suffix, so streams marked Expected before the upgrade stay silenced for every class of that provider.
- **`/api/status`:** adds `provider_references` from `ProviderRanges.status()` and `app_references` from `AppNetworks.status()`.

### Changes in `index.html`

| Place | Wording |
|---|---|
| Endpoint and hop detail line | evidence tag `Reference · Google list · 5 days old`, `Reference · Google list · 74 days old (stale)`, or `Inferred · ownership lookup` |
| Hosted endpoint evidence | "Runs on Google Cloud. Owner unknown." |
| Stream title | unchanged: "claude via Google" |
| Subtitle and short detail | use `label` ("Google Cloud customer") instead of "Google network" |
| Security finding | the server supplies title and text; the UI adds the `Reference` tag when `event_type` is `unexpected_network` |

### Static serving

No change is needed. The server only serves `/`, `/index.html` and `data/*.geojson`, so neither `references/` nor `data/provider-ranges.json` can be fetched by the browser. A test asserts this for both paths.

## Failure handling

| Situation | Behavior |
|---|---|
| Refreshed file missing or invalid | The snapshot is used |
| Snapshot invalid too | ASN inference only. `/api/status` reports `unavailable`, and the UI shows `Inferred` tags |
| Source older than 60 days | Still used. The tag shows "(stale)" |
| `app-networks.json` invalid | No app-reference findings. `/api/status` reports it. Novelty findings are unaffected |
| Update fetch fails for one source | That source keeps its previous ranges. The command exits non-zero and names it |

## Privacy and security

- The update command downloads the same public lists for every user. It sends no connection data, and it runs only when invoked.
- Every source is fetched over HTTPS straight from the provider's own domain, so TLS authenticates the publisher. No Pulsepath-hosted mirror or signing key is needed for this slice.
- Response size caps, the prefix cap and the shrink guard limit the damage from a broken or hostile feed.
- The app reference can only add findings. A process that imitates an app name gains nothing.

## Testing

Keep to the AGENTS.md testing budget. Use documentation IPs only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in synthetic datasets.

1. `tests/test_references.py`:
   - lookup returns the right group for IPv4 and IPv6;
   - an overlapping or malformed file is rejected and the other file is used;
   - the newer `generated_at` wins.
2. Generator:
   - AWS-style input (a prefix in `AMAZON` and `EC2`, one in `AMAZON` and `CLOUDFRONT`, one only in `AMAZON`) yields `hosted`, `edge` and `service`;
   - Google-style input yields `goog` minus `cloud` as `service`;
   - the shrink guard keeps the previous groups.
3. History:
   - migration fills `network_class`, re-keys `destination_key` and `fingerprint`, and moves findings with them;
   - a pre-upgrade stream that used two classes raises nothing, thanks to the `ip_sightings` check;
   - a class change raises "New network";
   - an unexpected network is raised during learning;
   - a legacy Expected mark still silences the stream.
4. Frontend (`frontend_behavior.cjs`): one assertion that a hosted endpoint shows its label and the `Reference` tag.
5. Static serving: `references/…` and `data/provider-ranges.json` return 404.

## Documentation

- **New `docs/provider-reference.md`:** the classes, the sources and how to update them, and the caveats. A match is not proof. The app is identified by process name, which can be imitated. ISP-hosted caches cause false alarms. BYOIP addresses stay ASN-inferred.
- **`docs/privacy.md`:** what `make update-references` downloads and that it sends nothing.
- **`docs/roadmap.md`:** note the Reference labels under 0.2.
- **`README.md`:** the new command.
- **`AGENTS.md`:** the layout list gains `references/` and `install_references.py`.

## Known limitations

- **Process names can be imitated.** Accepted, because the reference only raises flags. Fixed by signed identity (roadmap 0.2).
- **ISP-embedded caches** (Meta, Google and Netflix servers inside the ISP) appear as the ISP's network and can raise one "Unexpected network" finding per app. The user marks it Expected.
- **BYOIP addresses**, such as Anthropic's addresses served through Cloudflare, are not in the edge provider's list. They stay ASN-inferred.
- **Ranges move between classes.** The backfill at collector start reclassifies history with the current lists. A range that moves from `service` to `hosted` between runs can raise one "New network" finding.
- **Coverage gaps:** Azure, Meta and Akamai remain ASN-inferred until a stable published source exists.
