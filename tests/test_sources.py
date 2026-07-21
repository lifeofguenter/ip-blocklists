"""Guards on the source registry itself."""

from blocklists.parse import PARSERS
from blocklists.sources import MAIN_GROUP, SOURCES, TOR_GROUP

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
