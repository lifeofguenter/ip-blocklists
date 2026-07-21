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


SOURCES = (
    Source("alienvault_reputation", "https://reputation.alienvault.com/reputation.generic"),
    Source("bds_atif", "https://www.binarydefense.com/banlist.txt"),
    Source("blocklist_de", "https://lists.blocklist.de/lists/all.txt"),
    Source("blocklist_net_ua", "https://iplists.firehol.org/files/blocklist_net_ua.ipset"),
    Source("bruteforceblocker", "https://iplists.firehol.org/files/bruteforceblocker.ipset"),
    Source("ciarmy", "https://cinsscore.com/list/ci-badguys.txt"),
    Source("cruzit_web_attacks", "https://iplists.firehol.org/files/cruzit_web_attacks.ipset"),
    Source("dm_tor", "https://www.dan.me.uk/torlist/", group=TOR_GROUP),
    Source("dshield", "https://feeds.dshield.org/block.txt", "dshield"),
    Source("et_compromised", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    Source("feodo", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    Source("greensnow", "https://blocklist.greensnow.co/greensnow.txt"),
    Source("ipsum_level3", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"),
    Source("nixspam", "https://iplists.firehol.org/files/nixspam.ipset"),
    Source("spamhaus_drop", "https://www.spamhaus.org/drop/drop.txt"),
    Source(
        "yoyo_adservers",
        "https://pgl.yoyo.org/adservers/iplist.php"
        "?ipformat=plain&showintro=0&mimetype=plaintext",
    ),
)
