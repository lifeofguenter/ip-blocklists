"""Declarative registry of upstream blocklist feeds.

Feeds removed after their upstreams went dead, all of which had stopped
publishing any entries at all:

``spamhaus_edrop``
    Retired by Spamhaus and merged into ``spamhaus_drop``, which is still here.
``sslbl``
    Deprecated by abuse.ch on 2025-01-03 and now served empty.
``malc0de``
    Host no longer presents a valid certificate for its own domain.
``darklist_de``
    Still regenerates daily but publishes an empty list.

``greensnow``, ``ipsum_level3`` and ``blocklist_net_ua`` replace them.

Feeds removed because the FireHOL mirror stopped updating them, so they kept
serving a frozen snapshot that passed every check in :mod:`builder.sanitize`:

``cruzit_web_attacks``
    Frozen since 2023-09-22; ``cruzit.com`` is now a parked domain.
``nixspam``
    Frozen since 2021-09-10, although upstream drops each address after 12
    hours; the NiX Spam download host no longer resolves. Spam senders are
    also out of scope, see below.

Feeds removed because they list content rather than attackers:

``yoyo_adservers``
    Ad and tracking servers, mostly CDN edge addresses. These lists protect
    servers from hosts that attack them; ad, adult and gambling servers are
    out of scope however unwanted they are on a home network.
"""

from dataclasses import dataclass


#: Sources in this group build the plain ``ipv4.txt``/``ipv6.txt`` pair. Any
#: other group name is written to ``<group>_ipv4.txt``/``<group>_ipv6.txt``.
MAIN_GROUP = "main"
TOR_GROUP = "tor"


@dataclass(frozen=True)
class Source:
    """A single upstream feed.

    ``parser`` selects the line format handler in :mod:`blocklists.parse`.
    ``group`` selects which pair of output files the feed contributes to; Tor
    relays are kept apart because blocking them is a policy choice rather than
    an abuse signal.
    """

    name: str
    url: str
    parser: str = "plain"
    group: str = MAIN_GROUP


#: Trusted ranges subtracted from the main lists. These are first-party cloud
#: feeds: a host flagged for abuse while it sits in this space is not blackholed,
#: because the range belongs to a provider, not the attacker. Fetched, parsed and
#: sanitized exactly like a blocklist feed, so a failure aborts the build and the
#: broad-prefix guard in :mod:`builder.sanitize` rejects a poisoned allow feed.
#: The ``group`` field is unused here; allowlists are never routed by group.
ALLOWLISTS = (
    Source("aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", "aws"),
    Source("gcp", "https://www.gstatic.com/ipranges/cloud.json", "gcp"),
    Source("bunny_ipv4", "https://bunnycdn.com/api/system/edgeserverlist", "bunny"),
    Source("bunny_ipv6", "https://bunnycdn.com/api/system/edgeserverlist/ipv6", "bunny"),
)


SOURCES = (
    Source("alienvault_reputation", "https://reputation.alienvault.com/reputation.generic"),
    Source("bds_atif", "https://www.binarydefense.com/banlist.txt"),
    Source("blocklist_de", "https://lists.blocklist.de/lists/all.txt"),
    Source("blocklist_net_ua", "https://iplists.firehol.org/files/blocklist_net_ua.ipset"),
    Source("bruteforceblocker", "https://iplists.firehol.org/files/bruteforceblocker.ipset"),
    Source("ciarmy", "https://cinsscore.com/list/ci-badguys.txt"),
    Source("dm_tor", "https://www.dan.me.uk/torlist/", group=TOR_GROUP),
    Source("dshield", "https://feeds.dshield.org/block.txt", "dshield"),
    Source("et_compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    Source("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    Source("greensnow", "https://blocklist.greensnow.co/greensnow.txt"),
    Source("ipsum_level3", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"),
    Source("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt"),
)
