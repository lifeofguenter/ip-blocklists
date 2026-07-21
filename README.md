# ip-blocklists

Public IP blocklists merged into deduplicated CIDR lists, rebuilt daily by GitHub Actions.

| File | Contents |
| --- | --- |
| [`ipv4.txt`](ipv4.txt) | Abuse and attack sources, IPv4 |
| [`ipv6.txt`](ipv6.txt) | Abuse and attack sources, IPv6 |
| [`tor_ipv4.txt`](tor_ipv4.txt) | Tor relays, IPv4 |
| [`tor_ipv6.txt`](tor_ipv6.txt) | Tor relays, IPv6 |

One CIDR per line, nothing else — no headers, comments or timestamps. Single addresses
are written as `1.2.3.4/32` and `2001:db8::1/128`. Tor is kept separate because blocking
it is a policy choice, not an abuse signal.

```
1.10.16.0/20
5.188.86.0/24
185.220.101.0/24
```

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

`spamhaus_edrop`, `sslbl`, `malc0de` and `darklist_de` were dropped after their upstreams
went dead. All four were serving empty lists, so coverage was unaffected.

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
python -m blocklists.build

pip install -r requirements-dev.txt
python -m pytest
```

Add a feed by appending a `Source` to `blocklists/sources.py` and its name to
`tests/test_sources.py`.

## Licence

GPL-3.0, see [LICENSE](LICENSE). The aggregated data remains subject to each upstream's
terms.
