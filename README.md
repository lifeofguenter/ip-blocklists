# ip-blocklists

Public IP blocklists merged into deduplicated CIDR lists, rebuilt daily by GitHub Actions.

The lists are published as assets on the rolling [`latest`](../../releases/tag/latest)
release, not committed to the repository, so the download URLs below never change:

| File | Contents |
| --- | --- |
| [`ipv4.txt`](../../releases/latest/download/ipv4.txt) | Abuse and attack sources, IPv4 |
| [`ipv6.txt`](../../releases/latest/download/ipv6.txt) | Abuse and attack sources, IPv6 |
| [`tor_ipv4.txt`](../../releases/latest/download/tor_ipv4.txt) | Tor relays, IPv4 |
| [`tor_ipv6.txt`](../../releases/latest/download/tor_ipv6.txt) | Tor relays, IPv6 |

One CIDR per line. Single addresses are written as `1.2.3.4/32` and `2001:db8::1/128`.
Tor is kept separate because blocking it is a policy choice, not an abuse signal.

Entries are sorted by address, and each one names the feeds it came from in square
brackets. Where a feed annotated an entry, that note follows the brackets:

```
1.0.164.165/32  # [blocklist_de, ipsum_level3]
1.10.16.0/20  # [spamhaus_drop] SBL256894
1.15.227.58/32  # [blocklist_de, ipsum_level3]
62.60.130.0/23  # [spamhaus_drop] SBL683637; SBL688269
```

A CIDR is credited to every feed that supplied any part of it, so provenance survives
merging. Strip everything from `#` onward to get a plain CIDR list.

Repeating the feed names on every line roughly doubles the file, which buys two things:
you can grep a single address and see what flagged it, and an entry stays put when its
feeds change. Grouping entries under shared `# sources:` headers was cheaper on disk but
made ~6k otherwise-unchanged entries move between sections on every run, burying the real
additions and removals in the diff.

## Sources

| Name | Feed |
| --- | --- |
| `alienvault_reputation` | https://reputation.alienvault.com/reputation.generic |
| `bds_atif` | https://www.binarydefense.com/banlist.txt |
| `blocklist_de` | https://lists.blocklist.de/lists/all.txt |
| `blocklist_net_ua` | https://iplists.firehol.org/files/blocklist_net_ua.ipset |
| `bruteforceblocker` | https://iplists.firehol.org/files/bruteforceblocker.ipset |
| `ciarmy` | https://cinsscore.com/list/ci-badguys.txt |
| `cruzit_web_attacks` | https://iplists.firehol.org/files/cruzit_web_attacks.ipset |
| `dshield` | https://feeds.dshield.org/block.txt |
| `et_compromised` | https://rules.emergingthreats.net/blockrules/compromised-ips.txt |
| `feodo` | https://feodotracker.abuse.ch/downloads/ipblocklist.txt |
| `greensnow` | https://blocklist.greensnow.co/greensnow.txt |
| `ipsum_level3` | https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt |
| `nixspam` | https://iplists.firehol.org/files/nixspam.ipset |
| `spamhaus_drop` | https://www.spamhaus.org/drop/drop.txt |
| `yoyo_adservers` | https://pgl.yoyo.org/adservers/iplist.php |
| `dm_tor` (Tor) | https://www.dan.me.uk/torlist/ |

Each feed has its own licence and terms of use.

## Behaviour

Private, loopback, link-local, multicast and reserved ranges are removed, then the
remaining networks are merged with `ipaddress.collapse_addresses`, which only emits a
supernet the inputs fully cover.

The build aborts without writing anything if a feed cannot be fetched, yields no IPs,
parses on fewer than 90% of its lines, or contains an entry broader than `/8` (IPv4) or
`/19` (IPv6). A failed run leaves the previous lists in place and fails the workflow.

`dan.me.uk` rate-limits to one request per 30 minutes and supplies most of the IPv6
entries, so an occasional `403` will fail the run.

## Usage

Requires Python 3.14.

```sh
pip install -r requirements.txt
python -m builder.build          # writes blocklists/

pip install -r requirements-dev.txt
python -m pytest
```

`builder/` holds the code. `blocklists/` is build output: it is git-ignored, and CI
uploads it to the release rather than committing it. Add a feed by appending a `Source`
to `builder/sources.py` and its name to `tests/test_sources.py`.

## Licence

GPL-3.0, see [LICENSE](LICENSE). The aggregated data remains subject to each upstream's
terms.
