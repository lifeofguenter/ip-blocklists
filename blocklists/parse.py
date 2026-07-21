"""Turn raw feed bodies into sets of IP networks.

Two line formats cover every source we consume:

``plain``
    Everything after a comment marker is discarded, then the first whitespace
    token on the line must be an IP or CIDR. This transparently handles bare
    IP lists, FireHOL ``.ipset`` files, Spamhaus' ``1.2.3.0/24 ; SBL123`` and
    AlienVault's ``IP#field#field`` records (its ``#`` reads as a comment).

``dshield``
    Whitespace-separated columns ``startIP endIP netmask ...`` which are
    recombined into ``startIP/netmask``.
"""

import ipaddress

COMMENT_MARKERS = ("#", ";", "//")

#: A feed must yield an IP from at least this share of its data lines. Below
#: it, assume the format changed or we were served an error page.
MIN_PARSE_RATIO = 0.9


class ParseError(Exception):
    """A feed was unreadable, empty, or no longer matches its format."""


def strip_comment(line):
    """Drop the comment tail and surrounding whitespace from ``line``."""
    for marker in COMMENT_MARKERS:
        index = line.find(marker)
        if index != -1:
            line = line[:index]
    return line.strip()


def _parse_plain(line):
    return ipaddress.ip_network(line.split()[0], strict=False)


def _parse_dshield(line):
    columns = line.split()
    return ipaddress.ip_network(f"{columns[0]}/{columns[2]}", strict=False)


PARSERS = {"plain": _parse_plain, "dshield": _parse_dshield}


def parse(text, parser="plain", *, name="<source>", min_ratio=MIN_PARSE_RATIO):
    """Return the set of networks in ``text``.

    Raises :class:`ParseError` if the feed has no data lines, yields no IPs, or
    too many of its lines fail to parse.
    """
    try:
        parse_line = PARSERS[parser]
    except KeyError:
        raise ParseError(f"{name}: unknown parser {parser!r}") from None

    networks = set()
    data_lines = 0
    parsed_lines = 0

    for raw_line in text.splitlines():
        line = strip_comment(raw_line)
        if not line:
            continue
        data_lines += 1
        try:
            networks.add(parse_line(line))
        except (ValueError, IndexError):
            continue
        parsed_lines += 1

    if data_lines == 0:
        raise ParseError(f"{name}: feed contained no data lines")

    ratio = parsed_lines / data_lines
    if ratio < min_ratio:
        raise ParseError(
            f"{name}: only {parsed_lines}/{data_lines} lines parsed as IPs "
            f"({ratio:.0%} < {min_ratio:.0%}) - feed format may have changed"
        )

    if not networks:
        raise ParseError(f"{name}: feed yielded zero IPs")

    return networks
