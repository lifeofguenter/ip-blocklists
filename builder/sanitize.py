"""Reject dangerous entries and split networks by address family."""

#: Entries broader than these prefix lengths are treated as poisoned rather
#: than merely noisy: no honest feed asks us to blackhole that much of the
#: internet, so seeing one means the feed is wrong.
MIN_PREFIXLEN = {4: 8, 6: 19}


class SanitizeError(Exception):
    """A feed contained an entry too broad to be credible."""


def is_bogon(network):
    """True for anything that must never appear in a public blocklist.

    ``is_global`` is the broad catch: it excludes ranges that are not publicly
    routable yet are not flagged private either, such as the carrier-grade NAT
    block 100.64.0.0/10. The explicit checks then cover what ``is_global``
    still considers global, such as the NAT64 prefix 64:ff9b::/96.
    """
    return (
        not network.is_global
        or network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_multicast
        or network.is_reserved
        or network.is_unspecified
    )


def sanitize(entries, *, name="<source>"):
    """Split ``entries`` into ``(ipv4, ipv6)`` mappings, dropping bogons.

    ``entries`` is a ``{network: note}`` mapping, or any iterable of networks
    when no notes are involved. Raises :class:`SanitizeError` on an
    implausibly broad entry.
    """
    items = entries.items() if hasattr(entries, "items") else ((net, "") for net in entries)
    ipv4 = {}
    ipv6 = {}

    for network, note in items:
        # Bogons are checked first: a reserved or multicast supernet such as
        # 240.0.0.0/4 is junk to drop, not evidence of a poisoned feed.
        if is_bogon(network):
            continue
        minimum = MIN_PREFIXLEN[network.version]
        if network.prefixlen < minimum:
            raise SanitizeError(
                f"{name}: entry {network} is broader than /{minimum} - "
                f"refusing to build a list that blackholes this much address space"
            )
        if network.version == 4:
            ipv4[network] = note
        else:
            ipv6[network] = note

    return ipv4, ipv6
