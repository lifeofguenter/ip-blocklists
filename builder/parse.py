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

The allowlist feeds are JSON rather than line-oriented, so they use their own
document parsers (``aws``, ``gcp``, ``bunny``). These carry no notes: an allow
range only needs its address, not a reason.
"""

import ipaddress
import json
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


#: Line parsers see one ``(stripped, raw)`` line at a time. JSON parsers see the
#: whole decoded document and yield address strings.
LINE_PARSERS = {"plain": _parse_plain, "dshield": _parse_dshield}


def _json_aws(doc):
    for prefix in doc["prefixes"]:
        yield prefix["ip_prefix"]
    for prefix in doc["ipv6_prefixes"]:
        yield prefix["ipv6_prefix"]


def _json_gcp(doc):
    for prefix in doc["prefixes"]:
        yield prefix["ipv4Prefix"] if "ipv4Prefix" in prefix else prefix["ipv6Prefix"]


def _json_bunny(doc):
    #: A bare JSON array of addresses. Anything else is treated as shape drift.
    if not isinstance(doc, list):
        raise TypeError("bunny feed is not a JSON array")
    yield from doc


JSON_PARSERS = {"aws": _json_aws, "gcp": _json_gcp, "bunny": _json_bunny}

#: Every known parser, so callers can validate a source's parser name up front.
PARSERS = {**LINE_PARSERS, **JSON_PARSERS}


def _parse_json(text, extract, *, name):
    """Decode a JSON feed and return ``{network: ""}`` for its addresses.

    Raises :class:`ParseError` on a body that is not JSON, a document whose
    shape no longer matches (a missing or renamed key), or one that yields no
    usable address at all.
    """
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as error:
        raise ParseError(f"{name}: body is not valid JSON ({error})") from None

    try:
        tokens = list(extract(doc))
    except (KeyError, TypeError, AttributeError) as error:
        raise ParseError(
            f"{name}: JSON shape not recognised ({error}) - feed format may have changed"
        ) from None

    entries = {}
    for token in tokens:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except (ValueError, TypeError):
            continue
        entries.setdefault(network, "")

    if not entries:
        raise ParseError(f"{name}: feed yielded zero IPs")

    return entries


def parse(text, parser="plain", *, name="<source>", min_ratio=MIN_PARSE_RATIO):
    """Return ``{network: note}`` for every entry in ``text``.

    ``note`` is the empty string when the feed said nothing about the entry.
    Raises :class:`ParseError` if the feed has no data lines, yields no IPs, or
    too many of its lines fail to parse.
    """
    if parser in JSON_PARSERS:
        return _parse_json(text, JSON_PARSERS[parser], name=name)

    try:
        parse_line = LINE_PARSERS[parser]
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
