"""Subtract trusted (allowlisted) ranges out of a blocklist.

Cloud providers publish the address space they hand to customers. A host that
turns up in an abuse feed while sitting inside that space should not be
blackholed, so those ranges are carved out of the main lists before rendering.

Subtraction happens on the per-network provenance map *before* collapsing, not
on the collapsed CIDR set. :func:`builder.aggregate.attribute` assumes a
collapsed CIDR is always a supernet of the originals it absorbed; carving space
out after collapse could produce a CIDR smaller than an original, which would
then misattribute to ``unknown``. Doing it here keeps every surviving piece a
subnet of its original and copies the original's sources onto each piece, so the
existing collapse/attribute path is left untouched.
"""

from bisect import bisect_left, bisect_right


def subtract(networks, allow):
    """Remove allowlisted space from one address family's provenance map.

    ``networks`` maps each blocklist network to its ``{source: note}``. ``allow``
    is the collapsed (disjoint) allow set for the same family. Returns a new map:
    a network wholly inside the allow set is dropped, a network that only partly
    overlaps is split into the sub-networks that survive (each inheriting the
    original's sources), and a network that misses the allow set is kept as is.
    """
    allow = sorted(allow)
    if not allow:
        return {network: dict(sources) for network, sources in networks.items()}

    starts = [int(a.network_address) for a in allow]
    ends = [int(a.broadcast_address) for a in allow]

    result = {}
    for network, sources in networks.items():
        for piece in _survivors(network, allow, starts, ends):
            # Distinct pieces of one original never collide, but two originally
            # overlapping networks can survive into the same piece; merge rather
            # than overwrite so no feed loses its credit.
            result.setdefault(piece, {}).update(sources)
    return result


def _survivors(network, allow, starts, ends):
    """Yield the sub-networks of ``network`` left after removing ``allow``."""
    lo = int(network.network_address)
    hi = int(network.broadcast_address)

    # Disjoint ranges sorted by start are also sorted by end, so the ones that
    # overlap ``network`` form the contiguous slice [left, right).
    left = bisect_left(ends, lo)
    right = bisect_right(starts, hi)
    overlaps = [a for a in allow[left:right] if a.version == network.version]
    if not overlaps:
        return [network]

    pieces = [network]
    for a in overlaps:
        remaining = []
        for piece in pieces:
            if piece.subnet_of(a):  # covers equal-to and inside -> removed
                continue
            if a.subnet_of(piece):
                remaining.extend(piece.address_exclude(a))
            else:
                remaining.append(piece)  # disjoint from this hole
        pieces = remaining
        if not pieces:
            break
    return pieces
