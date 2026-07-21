"""Build the aggregated blocklists.

Every source must succeed. If any feed cannot be fetched, cannot be parsed, or
looks poisoned, the whole run aborts before anything is written, so a broken
upstream can never replace good lists with corrupt ones.
"""

import argparse
import sys
from collections import OrderedDict
from pathlib import Path

from .aggregate import collapse, render
from .fetch import FetchError, fetch
from .parse import ParseError, parse
from .sanitize import SanitizeError, sanitize
from .sources import MAIN_GROUP, SOURCES

REPO_ROOT = Path(__file__).resolve().parent.parent

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
    """Fetch and parse every source in one group, returning ``(ipv4, ipv6)``."""
    all_ipv4 = set()
    all_ipv6 = set()

    for source in sources:
        log(f"==> [{source.group}] {source.name}: {source.url}")
        body = fetcher(source.url)
        networks = parse(body, source.parser, name=source.name)
        ipv4, ipv6 = sanitize(networks, name=source.name)
        log(f"    {len(ipv4)} IPv4 + {len(ipv6)} IPv6 entries")
        all_ipv4 |= ipv4
        all_ipv6 |= ipv6

    if not all_ipv4:
        raise BuildError(f"{group}: combined IPv4 set is empty")
    if not all_ipv6:
        raise BuildError(f"{group}: combined IPv6 set is empty")

    return all_ipv4, all_ipv6


def build(sources=SOURCES, fetcher=fetch, *, output_dir=REPO_ROOT, log=print):
    """Collect every group and write its list files.

    Nothing is written until every group has been collected successfully, so a
    failed run leaves all previous lists untouched.
    """
    grouped = group_sources(sources)
    results = OrderedDict()

    for group, group_sources_ in grouped.items():
        ipv4, ipv6 = collect(group_sources_, fetcher, group=group, log=log)
        results[group] = (collapse(ipv4), collapse(ipv6))

    output_dir = Path(output_dir)
    written = []
    for group, (ipv4_cidrs, ipv6_cidrs) in results.items():
        ipv4_name, ipv6_name = output_names(group)
        for name, cidrs in ((ipv4_name, ipv4_cidrs), (ipv6_name, ipv6_cidrs)):
            path = output_dir / name
            path.write_text(render(cidrs), encoding="utf-8")
            written.append(path)
        log(f"==> wrote {ipv4_name} ({len(ipv4_cidrs)}) and {ipv6_name} ({len(ipv6_cidrs)})")

    return written


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output-dir",
        default=REPO_ROOT,
        help="directory to write the list files into (default: repo root)",
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
