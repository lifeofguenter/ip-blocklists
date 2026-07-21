"""Merge networks into the smallest equivalent set of CIDRs."""

import ipaddress


def collapse(networks):
    """Return ``networks`` deduped, merged where adjacent, and sorted.

    ``collapse_addresses`` only ever replaces a group with a supernet the group
    completely covers, so this never widens what the lists block.
    """
    return list(ipaddress.collapse_addresses(networks))


def render(cidrs):
    """Render an iterable of networks as newline-terminated CIDRs, one per line."""
    lines = [str(cidr) for cidr in cidrs]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"
