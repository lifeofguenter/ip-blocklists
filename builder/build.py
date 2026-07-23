"""Build the aggregated blocklists.

Every source must succeed. If any feed cannot be fetched, cannot be parsed, or
looks poisoned, the whole run aborts before anything is written, so a broken
upstream can never replace good lists with corrupt ones.
"""

import argparse
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

from .aggregate import attribute, collapse, render
from .allowlist import subtract
from .fetch import FetchError, fetch
from .parse import ParseError, parse
from .sanitize import SanitizeError, sanitize
from .sources import ALLOWLISTS, MAIN_GROUP, SOURCES

REPO_ROOT = Path(__file__).resolve().parent.parent

#: The generated lists live in their own directory so the repository root
#: stays clean as more lists are added.
DEFAULT_OUTPUT_DIR = REPO_ROOT / "blocklists"

FATAL_ERRORS = (FetchError, ParseError, SanitizeError)


class BuildError(Exception):
    """The aggregate result failed its sanity checks."""


def output_names(group):
    """Return the ``(ipv4, ipv6)`` filenames for ``group``."""
    prefix = "" if group == MAIN_GROUP else f"{group}_"
    return f"{prefix}ipv4.txt", f"{prefix}ipv6.txt"


def group_sources(sources):
    """Group ``sources`` by their output group, preserving registry order."""
    grouped = OrderedDict()
    for source in sources:
        grouped.setdefault(source.group, []).append(source)
    return grouped


def collect(sources, fetcher=fetch, *, group=MAIN_GROUP, log=print):
    """Fetch and parse one group, returning ``(ipv4, ipv6)`` provenance maps.

    Each map is ``{network: {source: note}}``, recording every feed an entry
    was seen in along with whatever that feed said about it.
    """
    all_ipv4 = defaultdict(dict)
    all_ipv6 = defaultdict(dict)

    for source in sources:
        log(f"==> [{group}] {source.name}: {source.url}")
        body = fetcher(source.url)
        entries = parse(body, source.parser, name=source.name)
        ipv4, ipv6 = sanitize(entries, name=source.name)
        for network, note in ipv4.items():
            all_ipv4[network][source.name] = note
        for network, note in ipv6.items():
            all_ipv6[network][source.name] = note
        log(f"    {len(ipv4)} IPv4 + {len(ipv6)} IPv6 entries")

    if not all_ipv4:
        raise BuildError(f"{group}: combined IPv4 set is empty")
    if not all_ipv6:
        raise BuildError(f"{group}: combined IPv6 set is empty")

    return dict(all_ipv4), dict(all_ipv6)


def build(
    sources=SOURCES,
    fetcher=fetch,
    *,
    allowlists=ALLOWLISTS,
    output_dir=DEFAULT_OUTPUT_DIR,
    log=print,
):
    """Collect every group and write its list files.

    Trusted ranges from ``allowlists`` are subtracted from the main group before
    it is rendered, so a host flagged for abuse while it sits in a provider's
    address space is not blackholed. The Tor group is left untouched. Passing no
    allowlists disables subtraction.

    Nothing is written until every group and the allowlists have been collected
    successfully, so a failed run leaves all previous lists untouched.
    """
    grouped = group_sources(sources)

    # Collected up front so a broken or poisoned allow feed aborts before any
    # blocklist work, and collapsed into a disjoint set per family.
    allow = {4: [], 6: []}
    if allowlists:
        allow_v4, allow_v6 = collect(allowlists, fetcher, group="allowlist", log=log)
        allow = {4: collapse(allow_v4), 6: collapse(allow_v6)}

    results = OrderedDict()
    for group, group_sources_ in grouped.items():
        ipv4, ipv6 = collect(group_sources_, fetcher, group=group, log=log)
        if group == MAIN_GROUP:
            ipv4 = subtract(ipv4, allow[4])
            ipv6 = subtract(ipv6, allow[6])
        rendered = []
        for family in (ipv4, ipv6):
            cidrs = collapse(family)
            rendered.append((len(cidrs), render(cidrs, attribute(cidrs, family))))
        results[group] = rendered

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for group, rendered in results.items():
        names = output_names(group)
        for name, (count, text) in zip(names, rendered):
            path = output_dir / name
            path.write_text(text, encoding="utf-8")
            written.append(path)
        counts = ", ".join(f"{n} ({c})" for n, (c, _) in zip(names, rendered))
        log(f"==> wrote {counts}")

    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="directory to write the list files into (default: blocklists/)",
    )
    args = parser.parse_args(argv)

    try:
        build(output_dir=args.output_dir)
    except (*FATAL_ERRORS, BuildError) as error:
        print(f"FATAL: {error}", file=sys.stderr)
        print("Aborting: existing lists left unchanged.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
