"""End-to-end orchestration tests with a stubbed fetcher (no network)."""

import pytest

from builder import build as build_module
from builder.build import BuildError, build, collect, main, output_names
from builder.fetch import FetchError
from builder.parse import ParseError
from builder.sanitize import SanitizeError
from builder.sources import ALLOWLISTS, Source

IPV4_FEED = Source("feed_v4", "https://example.test/v4")
IPV6_FEED = Source("feed_v6", "https://example.test/v6")
DSHIELD_FEED = Source("feed_dshield", "https://example.test/dshield", "dshield")
TOR_FEED = Source("feed_tor", "https://example.test/tor", group="tor")

#: Where each allow feed can be reached, by name, for tests that need to point a
#: specific provider at a chosen range.
ALLOW_URL = {source.name: source.url for source in ALLOWLISTS}


def _allow_stub(parser):
    """A minimal valid body for an allow feed of the given parser shape.

    The ranges here are globally-routable but intersect none of the blocklist
    fixtures, so by default the allow path runs, survives sanitising, yet removes
    nothing and every existing assertion still holds. (Documentation/TEST-NET
    ranges cannot be used: sanitize drops them as bogons.)
    """
    if parser == "aws":
        return (
            '{"prefixes":[{"ip_prefix":"1.1.1.0/24"}],'
            '"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/40"}]}'
        )
    if parser == "gcp":
        return (
            '{"prefixes":[{"ipv4Prefix":"1.1.1.0/24"},'
            '{"ipv6Prefix":"2600:1f00::/40"}]}'
        )
    return '["1.1.1.1"]'  # bunny


ALLOW_BODIES = {source.url: _allow_stub(source.parser) for source in ALLOWLISTS}

BODIES = {
    "https://example.test/v4": "1.2.3.4\n1.2.3.5\n10.0.0.1\n",
    "https://example.test/v6": "2606:4700::1\n2606:4700::2\n",
    "https://example.test/dshield": "8.8.8.0\t8.8.8.255\t24\t9\tx\tUS\tx@example.com\n",
    "https://example.test/tor": "9.9.9.9\n2606:4700::99\n",
    **ALLOW_BODIES,
}


def fetcher(bodies=None):
    bodies = BODIES if bodies is None else bodies

    def _fetch(url):
        value = bodies[url]
        if isinstance(value, Exception):
            raise value
        return value

    return _fetch


def quiet(*_args, **_kwargs):
    return None


class TestCollect:
    def test_combines_all_sources(self):
        ipv4, ipv6 = collect([IPV4_FEED, IPV6_FEED], fetcher(), log=quiet)
        assert {str(n) for n in ipv4} == {"1.2.3.4/32", "1.2.3.5/32"}
        assert {str(n) for n in ipv6} == {"2606:4700::1/128", "2606:4700::2/128"}

    def test_drops_private_addresses_from_the_combined_set(self):
        ipv4, _ = collect([IPV4_FEED, IPV6_FEED], fetcher(), log=quiet)
        assert not any(net.is_private for net in ipv4)

    def test_requires_a_non_empty_ipv4_set(self):
        with pytest.raises(BuildError, match="IPv4 set is empty"):
            collect([IPV6_FEED], fetcher(), log=quiet)

    def test_requires_a_non_empty_ipv6_set(self):
        with pytest.raises(BuildError, match="IPv6 set is empty"):
            collect([IPV4_FEED], fetcher(), log=quiet)


class TestGrouping:
    def test_main_group_uses_unprefixed_filenames(self):
        assert output_names("main") == ("ipv4.txt", "ipv6.txt")

    def test_other_groups_are_prefixed(self):
        assert output_names("tor") == ("tor_ipv4.txt", "tor_ipv6.txt")

    def test_tor_is_written_to_its_own_files(self, tmp_path):
        build([IPV4_FEED, IPV6_FEED, TOR_FEED], fetcher(), output_dir=tmp_path, log=quiet)
        assert (tmp_path / "tor_ipv4.txt").read_text() == "9.9.9.9/32  # [feed_tor]\n"
        assert (tmp_path / "tor_ipv6.txt").read_text() == (
            "2606:4700::99/128  # [feed_tor]\n"
        )

    def test_tor_entries_are_absent_from_the_main_lists(self, tmp_path):
        build([IPV4_FEED, IPV6_FEED, TOR_FEED], fetcher(), output_dir=tmp_path, log=quiet)
        assert "9.9.9.9" not in (tmp_path / "ipv4.txt").read_text()
        assert "2606:4700::99" not in (tmp_path / "ipv6.txt").read_text()

    def test_all_four_files_are_written(self, tmp_path):
        written = build(
            [IPV4_FEED, IPV6_FEED, TOR_FEED], fetcher(), output_dir=tmp_path, log=quiet
        )
        assert {path.name for path in written} == {
            "ipv4.txt",
            "ipv6.txt",
            "tor_ipv4.txt",
            "tor_ipv6.txt",
        }


class TestBuildOutput:
    def test_writes_both_files(self, tmp_path):
        """1.2.3.4 and 1.2.3.5 are an aligned pair, so they collapse to a /31."""
        build([IPV4_FEED, IPV6_FEED], fetcher(), output_dir=tmp_path, log=quiet)
        assert (tmp_path / "ipv4.txt").read_text() == "1.2.3.4/31  # [feed_v4]\n"
        assert (tmp_path / "ipv6.txt").read_text() == (
            "2606:4700::1/128  # [feed_v6]\n2606:4700::2/128  # [feed_v6]\n"
        )

    def test_compresses_across_sources(self, tmp_path):
        """Host routes contributed by different feeds merge into one CIDR."""
        sources = [
            Source("a", "https://example.test/a"),
            Source("b", "https://example.test/b"),
            IPV6_FEED,
        ]
        bodies = {
            "https://example.test/a": "1.2.3.0\n1.2.3.1\n",
            "https://example.test/b": "1.2.3.2\n1.2.3.3\n",
            "https://example.test/v6": BODIES["https://example.test/v6"],
            **ALLOW_BODIES,
        }
        build(sources, fetcher(bodies), output_dir=tmp_path, log=quiet)
        # The merged /30 is credited to both feeds that contributed a half.
        assert (tmp_path / "ipv4.txt").read_text() == "1.2.3.0/30  # [a, b]\n"

    def test_handles_the_dshield_parser(self, tmp_path):
        build([DSHIELD_FEED, IPV6_FEED], fetcher(), output_dir=tmp_path, log=quiet)
        assert (tmp_path / "ipv4.txt").read_text() == "8.8.8.0/24  # [feed_dshield] x, US\n"


class TestFailFast:
    @pytest.mark.parametrize(
        "body,error",
        [
            (FetchError("upstream down"), FetchError),
            ("<html><body>503</body></html>\n", ParseError),
            ("# only comments\n", ParseError),
            ("0.0.0.0/0\n", SanitizeError),
        ],
    )
    def test_a_broken_source_aborts_the_run(self, tmp_path, body, error):
        bodies = dict(BODIES, **{"https://example.test/v4": body})
        with pytest.raises(error):
            build([IPV4_FEED, IPV6_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet)

    def test_existing_lists_are_left_untouched_on_failure(self, tmp_path):
        """The whole point: a bad feed must never overwrite good lists."""
        (tmp_path / "ipv4.txt").write_text("9.9.9.9/32\n")
        (tmp_path / "ipv6.txt").write_text("2001:db8::99/128\n")

        bodies = dict(BODIES, **{"https://example.test/v6": FetchError("down")})
        with pytest.raises(FetchError):
            build([IPV4_FEED, IPV6_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet)

        assert (tmp_path / "ipv4.txt").read_text() == "9.9.9.9/32\n"
        assert (tmp_path / "ipv6.txt").read_text() == "2001:db8::99/128\n"

    def test_a_failing_tor_feed_blocks_the_main_lists_too(self, tmp_path):
        """All groups are collected before anything is written."""
        bodies = dict(BODIES, **{"https://example.test/tor": FetchError("down")})
        with pytest.raises(FetchError):
            build(
                [IPV4_FEED, IPV6_FEED, TOR_FEED],
                fetcher(bodies),
                output_dir=tmp_path,
                log=quiet,
            )
        assert not (tmp_path / "ipv4.txt").exists()
        assert not (tmp_path / "tor_ipv4.txt").exists()

    def test_nothing_is_written_when_a_later_source_fails(self, tmp_path):
        bodies = dict(BODIES, **{"https://example.test/v6": FetchError("down")})
        with pytest.raises(FetchError):
            build([IPV4_FEED, IPV6_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet)
        assert not (tmp_path / "ipv4.txt").exists()


class TestAllowlisting:
    def test_allowlisted_ip_is_removed_from_the_main_list(self, tmp_path):
        """A flagged host inside a cloud range is dropped; a neighbour is not."""
        bodies = dict(
            BODIES,
            **{
                "https://example.test/v4": "1.2.3.4\n8.8.8.8\n",
                ALLOW_URL["aws"]: (
                    '{"prefixes":[{"ip_prefix":"1.2.3.0/24"}],"ipv6_prefixes":[]}'
                ),
            },
        )
        build([IPV4_FEED, IPV6_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet)
        text = (tmp_path / "ipv4.txt").read_text()
        assert "1.2.3.4" not in text
        assert "8.8.8.8/32" in text

    def test_partial_overlap_is_split_not_dropped(self, tmp_path):
        """A /23 with one /24 allowlisted survives as the other /24."""
        bodies = dict(
            BODIES,
            **{
                "https://example.test/v4": "62.60.130.0/23\n",
                ALLOW_URL["aws"]: (
                    '{"prefixes":[{"ip_prefix":"62.60.131.0/24"}],"ipv6_prefixes":[]}'
                ),
            },
        )
        build([IPV4_FEED, IPV6_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet)
        text = (tmp_path / "ipv4.txt").read_text()
        assert "62.60.130.0/24  # [feed_v4]" in text
        assert "62.60.131" not in text
        assert "/23" not in text

    def test_allowlist_leaves_the_tor_list_alone(self, tmp_path):
        """The same address is carved from main but kept in the Tor list."""
        bodies = dict(
            BODIES,
            **{
                "https://example.test/v4": "9.9.9.9\n8.8.8.8\n",
                ALLOW_URL["aws"]: (
                    '{"prefixes":[{"ip_prefix":"9.9.9.0/24"}],"ipv6_prefixes":[]}'
                ),
            },
        )
        build(
            [IPV4_FEED, IPV6_FEED, TOR_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet
        )
        assert "9.9.9.9" not in (tmp_path / "ipv4.txt").read_text()
        assert "9.9.9.9/32" in (tmp_path / "tor_ipv4.txt").read_text()

    def test_a_failing_allow_feed_aborts_the_build(self, tmp_path):
        bodies = dict(BODIES, **{ALLOW_URL["aws"]: FetchError("allow feed down")})
        with pytest.raises(FetchError):
            build([IPV4_FEED, IPV6_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet)
        assert not (tmp_path / "ipv4.txt").exists()

    def test_a_poisoned_allow_feed_aborts_the_build(self, tmp_path):
        """A default-route allow entry must never silently un-block everything."""
        bodies = dict(
            BODIES,
            **{
                ALLOW_URL["aws"]: (
                    '{"prefixes":[{"ip_prefix":"0.0.0.0/0"}],"ipv6_prefixes":[]}'
                )
            },
        )
        with pytest.raises(SanitizeError):
            build([IPV4_FEED, IPV6_FEED], fetcher(bodies), output_dir=tmp_path, log=quiet)
        assert not (tmp_path / "ipv4.txt").exists()

    def test_no_allowlists_means_no_subtraction(self, tmp_path):
        bodies = dict(BODIES, **{"https://example.test/v4": "1.2.3.4\n"})
        build(
            [IPV4_FEED, IPV6_FEED],
            fetcher(bodies),
            allowlists=(),
            output_dir=tmp_path,
            log=quiet,
        )
        assert "1.2.3.4/32" in (tmp_path / "ipv4.txt").read_text()


class TestExitCodes:
    def test_success_exits_zero(self, monkeypatch):
        monkeypatch.setattr(build_module, "build", lambda **_kwargs: None)
        assert main([]) == 0

    @pytest.mark.parametrize(
        "error",
        [
            FetchError("down"),
            ParseError("format drift"),
            SanitizeError("poisoned"),
            BuildError("empty"),
        ],
    )
    def test_fatal_errors_exit_non_zero(self, monkeypatch, capsys, error):
        def explode(**_kwargs):
            raise error

        monkeypatch.setattr(build_module, "build", explode)
        assert main([]) == 1
        assert "FATAL" in capsys.readouterr().err

    def test_failure_message_mentions_lists_are_unchanged(self, monkeypatch, capsys):
        def explode(**_kwargs):
            raise FetchError("down")

        monkeypatch.setattr(build_module, "build", explode)
        main([])
        assert "left unchanged" in capsys.readouterr().err
