"""Merge networks into the smallest equivalent set of CIDRs, keeping provenance.

Output is one flat list in ascending address order, each entry annotated with
the feeds it came from. Repeating the feed names per line roughly doubles the
file, but it keeps an entry on the same line when its feeds change: grouping by
feed combination instead made ~6k unchanged entries jump between sections on
every run, swamping the real additions and removals in the diff.
"""

import ipaddress
from bisect import bisect_right
from collections import defaultdict

UNKNOWN_SOURCE = "unknown"


def collapse(networks):
    """Return ``networks`` deduped, merged where adjacent, and sorted.

    ``collapse_addresses`` only ever replaces a group with a supernet the group
    completely covers, so this never widens what the lists block.
    """
    return list(ipaddress.collapse_addresses(networks))


def attribute(cidrs, provenance):
    """Map each collapsed CIDR to the ``{source: {notes}}`` it absorbed.

    ``provenance`` maps an original network to ``{source: note}``. Because
    collapsing can merge entries contributed by different feeds, a resulting
    CIDR is credited to every feed that supplied any part of it.
    """
    if not cidrs:
        return {}

    ordered = sorted(cidrs)
    starts = [int(cidr.network_address) for cidr in ordered]
    result = {cidr: defaultdict(set) for cidr in ordered}

    for network, sources in provenance.items():
        index = bisect_right(starts, int(network.network_address)) - 1
        if index < 0:
            continue
        cidr = ordered[index]
        if network.version != cidr.version or not network.subnet_of(cidr):
            continue
        for source, note in sources.items():
            if note:
                result[cidr][source].add(note)
            else:
                result[cidr].setdefault(source, set())

    return result


def render(cidrs, attribution=None):
    """Render ``cidrs`` as text, one CIDR per line, in ascending address order.

    Without ``attribution`` this is a plain CIDR list. With it, every line
    carries its own ``[feed, feed]`` bracket followed by whatever notes those
    feeds supplied, so grepping the file for a single address tells you which
    feed put it there.
    """
    ordered = sorted(cidrs)
    if not ordered:
        return ""

    if attribution is None:
        return "\n".join(str(cidr) for cidr in ordered) + "\n"

    lines = []
    for cidr in ordered:
        sources = attribution.get(cidr, {})
        line = f"{cidr}  # [{', '.join(sorted(sources)) if sources else UNKNOWN_SOURCE}]"
        notes = sorted(note for notes in sources.values() for note in notes)
        if notes:
            line += " " + "; ".join(notes)
        lines.append(line)

    return "\n".join(lines) + "\n"
