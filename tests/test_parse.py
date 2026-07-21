"""Parsing tests built on samples of each real upstream format."""

import ipaddress

import pytest

from blocklists.parse import ParseError, parse, strip_comment


def nets(*cidrs):
    return {ipaddress.ip_network(cidr) for cidr in cidrs}


class TestStripComment:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ("1.2.3.4", "1.2.3.4"),
            ("1.2.3.4  # trailing note", "1.2.3.4"),
            ("# whole line", ""),
            ("1.2.3.0/24 ; SBL256894", "1.2.3.0/24"),
            ("; whole line", ""),
            ("1.2.3.4 // note", "1.2.3.4"),
            ("   1.2.3.4   ", "1.2.3.4"),
            ("", ""),
        ],
    )
    def test_strips(self, line, expected):
        assert strip_comment(line) == expected

    def test_truncates_at_earliest_marker(self):
        assert strip_comment("1.2.3.4 ; first # second") == "1.2.3.4"
        assert strip_comment("1.2.3.4 # first ; second") == "1.2.3.4"


class TestPlainFormats:
    def test_bare_ip_list(self):
        """blocklist_de / ciarmy / et_compromised / yoyo style."""
        text = "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
        assert parse(text) == nets("1.2.3.4/32", "5.6.7.8/32", "9.10.11.12/32")

    def test_firehol_ipset(self):
        """bruteforceblocker / cruzit_web_attacks / nixspam style."""
        text = (
            "#\n"
            "# bruteforceblocker\n"
            "#\n"
            "# Source: http://danger.rulez.sk/index.php/bruteforceblocker/\n"
            "# Maintainer: FireHOL\n"
            "#\n"
            "1.2.3.4\n"
            "5.6.7.0/24\n"
        )
        assert parse(text) == nets("1.2.3.4/32", "5.6.7.0/24")

    def test_spamhaus_drop(self):
        """Semicolon comments plus an inline SBL reference on each entry."""
        text = (
            "; Spamhaus DROP List 2024/01/01 - (c) 2024 The Spamhaus Project\n"
            "; Last-Modified: Mon, 01 Jan 2024 00:00:00 GMT\n"
            "1.10.16.0/20 ; SBL256894\n"
            "1.19.0.0/16 ; SBL434604\n"
        )
        assert parse(text) == nets("1.10.16.0/20", "1.19.0.0/16")

    def test_alienvault_hash_separated_fields(self):
        """The '#' field separator doubles as our comment marker."""
        text = (
            "222.186.21.40#4#2#Scanning Host#US#38.0,-97.0#11\n"
            "185.220.101.5#6#3#Malicious Host#DE#51.0,9.0#4\n"
        )
        assert parse(text) == nets("222.186.21.40/32", "185.220.101.5/32")

    def test_mixed_ipv4_and_ipv6(self):
        """dm_tor publishes both families in one flat list."""
        text = "2.58.56.43\n2001:db8::1\n2a0b:f4c2:2::5\n185.220.101.34\n"
        assert parse(text) == nets(
            "2.58.56.43/32", "185.220.101.34/32", "2001:db8::1/128", "2a0b:f4c2:2::5/128"
        )

    def test_double_slash_comments(self):
        text = "// Malc0de IP blacklist\n1.2.3.4\n5.6.7.8\n"
        assert parse(text) == nets("1.2.3.4/32", "5.6.7.8/32")

    def test_deduplicates_repeated_entries(self):
        text = "1.2.3.4\n1.2.3.4\n1.2.3.4\n5.6.7.8\n"
        assert parse(text) == nets("1.2.3.4/32", "5.6.7.8/32")

    def test_host_bits_are_tolerated(self):
        """A non-aligned CIDR is normalised rather than rejected."""
        assert parse("1.2.3.4/24\n") == nets("1.2.3.0/24")


class TestDshieldFormat:
    def test_parses_start_and_netmask_columns(self):
        text = (
            "#\n"
            "# DShield.org Recommended Block List\n"
            "#\n"
            "#Start\tEnd\tNetmask\tnAttacks\tName\tCountry\tEmail\n"
            "43.229.53.0\t43.229.53.255\t24\t1234\tExample Net\tCN\tabuse@example.com\n"
            "185.220.101.0\t185.220.101.255\t24\t500\tOther Net\tDE\tabuse@example.net\n"
        )
        assert parse(text, "dshield") == nets("43.229.53.0/24", "185.220.101.0/24")

    def test_uses_netmask_column_not_a_host_route(self):
        """Regression guard: the /24 must come from column 3, not default to /32."""
        result = parse("8.8.8.0\t8.8.8.255\t24\t1\tx\tUS\tx@example.com\n", "dshield")
        assert result == nets("8.8.8.0/24")


class TestFailFast:
    def test_html_error_page_is_rejected(self):
        text = (
            "<!DOCTYPE html>\n"
            "<html><head><title>503 Service Unavailable</title></head>\n"
            "<body><h1>Service Unavailable</h1></body>\n"
            "</html>\n"
        )
        with pytest.raises(ParseError, match="format may have changed"):
            parse(text, name="broken_feed")

    def test_comments_only_feed_is_rejected(self):
        with pytest.raises(ParseError, match="no data lines"):
            parse("# header\n# more header\n\n", name="empty_feed")

    def test_completely_empty_feed_is_rejected(self):
        with pytest.raises(ParseError, match="no data lines"):
            parse("", name="empty_feed")

    def test_mostly_garbage_feed_is_rejected(self):
        text = "1.2.3.4\n" + "".join(f"garbage line {i}\n" for i in range(20))
        with pytest.raises(ParseError, match="format may have changed"):
            parse(text, name="drifted_feed")

    def test_a_little_noise_is_tolerated(self):
        """One malformed line among many good ones must not fail the build."""
        text = "".join(f"1.2.3.{i}\n" for i in range(50)) + "not-an-ip\n"
        assert len(parse(text)) == 50

    def test_error_message_names_the_source(self):
        with pytest.raises(ParseError, match="my_feed"):
            parse("nonsense\n", name="my_feed")

    def test_unknown_parser_is_rejected(self):
        with pytest.raises(ParseError, match="unknown parser"):
            parse("1.2.3.4\n", "nope", name="my_feed")
