"""Merge networks into the smallest equivalent set of CIDRs, keeping provenance.

Output is grouped by which feeds an entry came from, so the source comment is
written once per group rather than once per line. With ~170k entries falling
into ~165 distinct feed combinations, that costs a few hundred lines instead of
doubling the file.
"""

import ipaddress
from bisect import bisect_right
from collections import defaultdict

SOURCE_PREFIX = "# sources: "


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
    """Render ``cidrs`` as text, one CIDR per line.

    Without ``attribution`` this is a plain CIDR list. With it, entries are
    grouped under a ``# sources:`` header naming the feeds they came from, and
    any notes those feeds supplied are appended inline.
    """
    ordered = sorted(cidrs)
    if not ordered:
        return ""

    if attribution is None:
        return "\n".join(str(cidr) for cidr in ordered) + "\n"

    groups = defaultdict(list)
    for cidr in ordered:
        groups[tuple(sorted(attribution.get(cidr, {})))].append(cidr)

    lines = []
    for sources in sorted(groups):
        if lines:
            lines.append("")
        lines.append(SOURCE_PREFIX + (", ".join(sources) if sources else "unknown"))
        for cidr in groups[sources]:
            notes = sorted(
                note for notes in attribution.get(cidr, {}).values() for note in notes
            )
            lines.append(f"{cidr}  # {'; '.join(notes)}" if notes else str(cidr))

    return "\n".join(lines) + "\n"
