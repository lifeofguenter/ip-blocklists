"""Turn raw feed bodies into networks with the notes their feed supplied.

Two line formats cover every source we consume:

``plain``
    Everything after a comment marker is discarded, then the first whitespace
    token on the line must be an IP or CIDR. This transparently handles bare
    IP lists, FireHOL ``.ipset`` files, Spamhaus' ``1.2.3.0/24 ; SBL123`` and
    AlienVault's ``1.2.3.4 # Malicious Host KR,,lat,long``. Whatever followed
    the marker is kept as the entry's note.

``dshield``
    Whitespace-separated columns ``startIP endIP netmask nattacks name country``
    which are recombined into ``startIP/netmask``, with the name and country
    columns kept as the note.
"""

import ipaddress
import re

COMMENT_MARKERS = ("#", ";", "//")

#: Notes are descriptive only, so an unusually long one is truncated rather
#: than allowed to bloat a line.
MAX_NOTE_LENGTH = 120

#: A feed must yield an IP from at least this share of its data lines. Below
#: it, assume the format changed or we were served an error page.
MIN_PARSE_RATIO = 0.9

_SEPARATORS = re.compile(r"[#;]+")


class ParseError(Exception):
    """A feed was unreadable, empty, or no longer matches its format."""


def strip_comment(line):
    """Drop the comment tail and surrounding whitespace from ``line``."""
    for marker in COMMENT_MARKERS:
        index = line.find(marker)
        if index != -1:
            line = line[:index]
    return line.strip()


def extract_note(line):
    """Return the comment tail of ``line``, normalised for display.

    Any further ``#`` or ``;`` inside the tail is rewritten as a comma so a
    feed that packs several fields after the marker still reads as one note.
    """
    positions = [line.find(marker) for marker in COMMENT_MARKERS]
    positions = [index for index in positions if index != -1]
    if not positions:
        return ""
    tail = line[min(positions) :].lstrip("#;/ \t")
    tail = " ".join(_SEPARATORS.sub(", ", tail).split())
    return tail[:MAX_NOTE_LENGTH].strip().strip(",").strip()


def _parse_plain(line, raw_line):
    return ipaddress.ip_network(line.split()[0], strict=False), extract_note(raw_line)


def _parse_dshield(line, raw_line):
    columns = line.split()
    network = ipaddress.ip_network(f"{columns[0]}/{columns[2]}", strict=False)
    fields = [field.strip() for field in raw_line.split("\t")]
    note = ", ".join(field for field in fields[4:6] if field)
    return network, note[:MAX_NOTE_LENGTH]


PARSERS = {"plain": _parse_plain, "dshield": _parse_dshield}


def parse(text, parser="plain", *, name="<source>", min_ratio=MIN_PARSE_RATIO):
    """Return ``{network: note}`` for every entry in ``text``.

    ``note`` is the empty string when the feed said nothing about the entry.
    Raises :class:`ParseError` if the feed has no data lines, yields no IPs, or
    too many of its lines fail to parse.
    """
    try:
        parse_line = PARSERS[parser]
    except KeyError:
        raise ParseError(f"{name}: unknown parser {parser!r}") from None

    entries = {}
    data_lines = 0
    parsed_lines = 0

    for raw_line in text.splitlines():
        line = strip_comment(raw_line)
        if not line:
            continue
        data_lines += 1
        try:
            network, note = parse_line(line, raw_line)
        except (ValueError, IndexError):
            continue
        parsed_lines += 1
        # A repeated entry keeps the first note that actually said something.
        if not entries.get(network):
            entries[network] = note

    if data_lines == 0:
        raise ParseError(f"{name}: feed contained no data lines")

    ratio = parsed_lines / data_lines
    if ratio < min_ratio:
        raise ParseError(
            f"{name}: only {parsed_lines}/{data_lines} lines parsed as IPs "
            f"({ratio:.0%} < {min_ratio:.0%}) - feed format may have changed"
        )

    if not entries:
        raise ParseError(f"{name}: feed yielded zero IPs")

    return entries
