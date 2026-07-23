"""Guards on the source registry itself."""

from builder.parse import PARSERS
from builder.sources import ALLOWLISTS, MAIN_GROUP, SOURCES, TOR_GROUP

EXPECTED_ALLOWLIST_NAMES = {"aws", "gcp", "bunny_ipv4", "bunny_ipv6"}

EXPECTED_NAMES = {
    "alienvault_reputation",
    "bds_atif",
    "blocklist_de",
    "blocklist_net_ua",
    "bruteforceblocker",
    "ciarmy",
    "cruzit_web_attacks",
    "dm_tor",
    "dshield",
    "et_compromised",
    "feodo",
    "greensnow",
    "ipsum_level3",
    "nixspam",
    "spamhaus_drop",
    "yoyo_adservers",
}

#: Upstreams that went dead and were deliberately dropped. Guarding against
#: their reintroduction keeps a well-meaning revert from breaking the build.
RETIRED_NAMES = {"spamhaus_edrop", "sslbl", "malc0de", "darklist_de"}


def test_registry_matches_the_configured_feeds():
    assert {source.name for source in SOURCES} == EXPECTED_NAMES


def test_retired_feeds_are_not_reintroduced():
    assert {source.name for source in SOURCES}.isdisjoint(RETIRED_NAMES)


def test_names_are_unique():
    names = [source.name for source in SOURCES]
    assert len(names) == len(set(names))


def test_urls_are_unique():
    urls = [source.url for source in SOURCES]
    assert len(urls) == len(set(urls))


def test_every_url_is_https():
    assert all(source.url.startswith("https://") for source in SOURCES)


def test_every_parser_is_implemented():
    assert all(source.parser in PARSERS for source in SOURCES)


def test_tor_is_the_only_source_outside_the_main_group():
    non_main = {source.name for source in SOURCES if source.group != MAIN_GROUP}
    assert non_main == {"dm_tor"}


def test_tor_feed_uses_the_tor_group():
    dm_tor = next(source for source in SOURCES if source.name == "dm_tor")
    assert dm_tor.group == TOR_GROUP


def test_dshield_uses_its_column_parser():
    dshield = next(source for source in SOURCES if source.name == "dshield")
    assert dshield.parser == "dshield"


def test_every_other_source_uses_the_plain_parser():
    others = [source for source in SOURCES if source.name != "dshield"]
    assert all(source.parser == "plain" for source in others)


class TestAllowlists:
    def test_registry_matches_the_configured_feeds(self):
        assert {source.name for source in ALLOWLISTS} == EXPECTED_ALLOWLIST_NAMES

    def test_names_are_unique(self):
        names = [source.name for source in ALLOWLISTS]
        assert len(names) == len(set(names))

    def test_urls_are_unique(self):
        urls = [source.url for source in ALLOWLISTS]
        assert len(urls) == len(set(urls))

    def test_every_url_is_https(self):
        assert all(source.url.startswith("https://") for source in ALLOWLISTS)

    def test_every_parser_is_implemented(self):
        assert all(source.parser in PARSERS for source in ALLOWLISTS)

    def test_names_do_not_clash_with_blocklist_feeds(self):
        block = {source.name for source in SOURCES}
        allow = {source.name for source in ALLOWLISTS}
        assert block.isdisjoint(allow)
