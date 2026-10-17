# Provider reference

Pulsepath uses two small reference datasets to say more about who is at the other end of a connection. Both are local files. Nothing about your connections is sent anywhere to use them.

The design is in [the spec](superpowers/specs/2026-09-25-provider-reference-design.md).

## Evidence levels

The UI marks every ownership claim with one word:

- **Reference**: the address is in a list the provider itself publishes. The tag names the list and its age, for example `Reference · Google list · 5 days old`. After 60 days it shows `(stale)`; stale lists are still used.
- **Inferred**: the owner comes from the offline DB-IP ASN database, which records which network announces the address. It is usually right about the network, and says nothing about the service or the city.

## Network classes

A Reference match also says what kind of address it is:

| Class | Meaning | Example labels |
|---|---|---|
| Service | The provider's own services | Google services, Amazon services, Apple services, GitHub services |
| Hosted | A customer's server on the provider's cloud; *who* is unknown | Google Cloud customer, AWS customer, Oracle Cloud customer, DigitalOcean customer |
| Edge | A shared CDN or proxy edge in front of many customers | Cloudflare edge, CloudFront edge, Fastly edge |

"Hosted" matters for security. A big provider's name sounds reassuring, but anyone can rent a server, bucket or API on AWS or Google Cloud. "AWS customer" means *someone's* server at Amazon, and the UI says "Owner unknown."

An edge hides what is behind it. A Cloudflare edge address can front Anthropic, a bank, or a phishing site.

## Sources

| Provider | Published list | Classes |
|---|---|---|
| Cloudflare | `cloudflare.com/ips-v4`, `ips-v6` | edge |
| Google | `gstatic.com/ipranges/goog.json`, `cloud.json` | `cloud.json` → hosted; the rest of `goog.json` → service |
| AWS | `ip-ranges.amazonaws.com/ip-ranges.json` | `CLOUDFRONT` → edge; `EC2`, `S3`, `API_GATEWAY`, `GLOBALACCELERATOR` → hosted; other AWS services → service |
| Fastly | `api.fastly.com/public-ip-list` | edge |
| Oracle Cloud | `docs.oracle.com/iaas/tools/public_ip_ranges.json` | hosted |
| DigitalOcean | `digitalocean.com/geo/google.csv` | hosted |
| GitHub | `api.github.com/meta` (web, API, git, hooks, packages, pages, importer, copilot) | service |
| Apple | `17.0.0.0/8`, Apple's registry allocation | service |

S3 counts as hosted because a bucket holds customer content, and public buckets are a common place to host payloads.

GitHub's Actions and Codespaces lists are left out: they are Azure ranges that GitHub rents, not GitHub services.

Not covered yet: Azure (its download link changes weekly), plus Meta and Akamai, which publish no list. Those stay **Inferred**.

When one address appears in several lists, the most specific prefix wins. For an identical prefix, the stronger claim wins: edge over hosted, hosted over service. Between providers, the earlier row in the table wins.

## Updating the lists

```bash
make update-references
make restart
```

`install_references.py` downloads each list straight from the provider over HTTPS and writes `data/provider-ranges.json`. That file is not committed. The download is the same for every user.

Pulsepath uses whichever is newer: that file or the reviewed snapshot in `references/provider-ranges.json`.

Safeguards:

- Each response is capped at 16 MB and each request times out after 45 seconds.
- A source that fails, returns nothing, or suddenly lists fewer than half its previous prefixes keeps its previous ranges. The command then exits with an error that names it. To accept a genuine shrink, delete `data/provider-ranges.json` and run the command again.
- Local, private and carrier-NAT prefixes are dropped, and the result must pass the same checks the collector applies when it loads a file.

Maintainers regenerate the committed snapshot with `python3 install_references.py --snapshot`. Review the diff: it lists one prefix per line.

## Expected networks for apps

`references/app-networks.json` lists the networks a few well-known apps normally use:

| App | Processes | Expected |
|---|---|---|
| Apple Push | `apsd` | Apple |
| Claude | `claude…` | Anthropic, Cloudflare edge, Google Cloud customer |
| WhatsApp | `whatsapp…` | Meta |

When a listed app connects to anything else, Security shows **Unexpected network for WhatsApp**, with text such as "WhatsApp usually uses Meta. This connection goes to an AWS customer." The card carries a **Reference** tag. Hover it to see the entry's source and review date.

What this does and does not mean:

- **It can only add findings.** It never lowers, hides, or merges away another finding.
- **It works from the first launch.** It does not depend on your history, so it also runs during the learning period.
- **Unexpected is not malicious.** Apps add providers, move to new CDNs, or load third-party content.
- **The app is identified by its process name, which any program can imitate.** That is why the list only raises flags: a program calling itself "WhatsApp" gains nothing. Quieting findings waits for signed app identity (roadmap 0.2).
- **ISP caches cause false alarms.** Meta, Google and Netflix place cache servers inside ISPs. Content from such a cache belongs to your ISP's network, so it can raise one "Unexpected network" finding per app. Mark it **Expected**.
- **Some providers' own addresses stay Inferred.** Anthropic's addresses, for example, are served through Cloudflare but are not in Cloudflare's list, so they match the ASN owner instead.

### Adding an app

Add an entry with:

- `app`: a display name;
- `processes`: case-insensitive prefixes of the process name;
- `expected`: providers, optionally narrowed by `class`;
- `source`: a vendor documentation URL, or `observed YYYY-MM` when you have only watched the app yourself.

Provider names must match the canonical names Pulsepath shows, such as "Meta", "Google", "Amazon Web Services" or "Anthropic, PBC".

Never list browsers, `curl`, Python, Node, package managers, VPN or relay clients (such as `IPNExtension`), `nsurlsessiond`, or anything else that legitimately reaches arbitrary hosts.

## History and familiarity

Novelty findings compare a provider *and* its class. An app that only ever used Google's own services and now reaches a Google Cloud customer gets "New network", with "First connection to a Google Cloud customer." Before calling a class new, Pulsepath also checks every address the app contacted earlier. History recorded before classes existed therefore does not produce a wave of findings.

At each start, the collector reclassifies stored history with the current lists and moves findings to the new stream keys. Streams you marked **Expected** before classes existed stay accepted for every class of that provider.
