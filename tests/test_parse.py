"""Parsing tests built on samples of each real upstream format."""

import ipaddress

import pytest

from builder.parse import MAX_NOTE_LENGTH, ParseError, extract_note, parse, strip_comment


def nets(*cidrs):
    return {ipaddress.ip_network(cidr) for cidr in cidrs}


def networks_in(text, parser="plain", **kwargs):
    """The networks a feed yields, ignoring their notes."""
    return set(parse(text, parser, **kwargs))


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
        assert networks_in(text) == nets("1.2.3.4/32", "5.6.7.8/32", "9.10.11.12/32")

    def test_firehol_ipset(self):
        """bruteforceblocker / cruzit_web_attacks / nixspam style."""
        text = (
            "#\n"
            "# bruteforceblocker\n"
            "#\n"
            "# Maintainer: FireHOL\n"
            "#\n"
            "1.2.3.4\n"
            "5.6.7.0/24\n"
        )
        assert networks_in(text) == nets("1.2.3.4/32", "5.6.7.0/24")

    def test_spamhaus_drop(self):
        """Semicolon comments plus an inline SBL reference on each entry."""
        text = (
            "; Spamhaus DROP List 2024/01/01 - (c) 2024 The Spamhaus Project\n"
            "; Last-Modified: Mon, 01 Jan 2024 00:00:00 GMT\n"
            "1.10.16.0/20 ; SBL256894\n"
            "1.19.0.0/16 ; SBL434604\n"
        )
        assert networks_in(text) == nets("1.10.16.0/20", "1.19.0.0/16")

    def test_alienvault_reputation(self):
        """A bare IP followed by a '#' comment describing the host."""
        text = (
            "49.143.32.6 # Malicious Host KR,,37.5111999512,126.974098206\n"
            "222.77.181.28 # Malicious Host CN,,24.4797992706,118.08190155\n"
        )
        assert networks_in(text) == nets("49.143.32.6/32", "222.77.181.28/32")

    def test_mixed_ipv4_and_ipv6(self):
        """dm_tor publishes both families in one flat list."""
        text = "2.58.56.43\n2001:db8::1\n2a0b:f4c2:2::5\n185.220.101.34\n"
        assert networks_in(text) == nets(
            "2.58.56.43/32", "185.220.101.34/32", "2001:db8::1/128", "2a0b:f4c2:2::5/128"
        )

    def test_double_slash_comments(self):
        assert networks_in("// Malc0de IP blacklist\n1.2.3.4\n5.6.7.8\n") == nets(
            "1.2.3.4/32", "5.6.7.8/32"
        )

    def test_deduplicates_repeated_entries(self):
        assert networks_in("1.2.3.4\n1.2.3.4\n1.2.3.4\n5.6.7.8\n") == nets(
            "1.2.3.4/32", "5.6.7.8/32"
        )

    def test_host_bits_are_tolerated(self):
        """A non-aligned CIDR is normalised rather than rejected."""
        assert networks_in("1.2.3.4/24\n") == nets("1.2.3.0/24")


class TestNotes:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ("1.2.3.4", ""),
            ("1.2.3.0/20 ; SBL256894", "SBL256894"),
            ("1.2.3.4 # brute force", "brute force"),
            ("1.2.3.4 // seen scanning", "seen scanning"),
            # AlienVault's real shape: a bare IP plus a descriptive comment.
            ("49.143.32.6 # Malicious Host KR,,37.51,126.97", "Malicious Host KR,,37.51,126.97"),
            # A feed packing several fields after the marker still reads as one note.
            ("1.2.3.4 # scanning#US#11", "scanning, US, 11"),
        ],
    )
    def test_extracts(self, line, expected):
        assert extract_note(line) == expected

    def test_spamhaus_note_is_kept_against_its_network(self):
        entries = parse("1.10.16.0/20 ; SBL256894\n")
        assert entries[ipaddress.ip_network("1.10.16.0/20")] == "SBL256894"

    def test_entries_without_notes_get_an_empty_string(self):
        entries = parse("1.2.3.4\n")
        assert entries[ipaddress.ip_network("1.2.3.4/32")] == ""

    def test_duplicate_entry_keeps_the_informative_note(self):
        entries = parse("1.2.3.4\n1.2.3.4 ; SBL1\n")
        assert entries[ipaddress.ip_network("1.2.3.4/32")] == "SBL1"

    def test_long_notes_are_truncated(self):
        entries = parse(f"1.2.3.4 # {'x' * 500}\n")
        assert len(entries[ipaddress.ip_network("1.2.3.4/32")]) <= MAX_NOTE_LENGTH


class TestDshieldFormat:
    TEXT = (
        "#\n"
        "# DShield.org Recommended Block List\n"
        "#\n"
        "#Start\tEnd\tNetmask\tnAttacks\tName\tCountry\tEmail\n"
        "43.229.53.0\t43.229.53.255\t24\t1234\tExample Net\tCN\tabuse@example.com\n"
        "185.220.101.0\t185.220.101.255\t24\t500\tOther Net\tDE\tabuse@example.net\n"
    )

    def test_parses_start_and_netmask_columns(self):
        assert networks_in(self.TEXT, "dshield") == nets("43.229.53.0/24", "185.220.101.0/24")

    def test_uses_netmask_column_not_a_host_route(self):
        """Regression guard: the /24 must come from column 3, not default to /32."""
        text = "8.8.8.0\t8.8.8.255\t24\t1\tx\tUS\tx@example.com\n"
        assert networks_in(text, "dshield") == nets("8.8.8.0/24")

    def test_note_comes_from_the_name_and_country_columns(self):
        entries = parse(self.TEXT, "dshield")
        assert entries[ipaddress.ip_network("43.229.53.0/24")] == "Example Net, CN"

    def test_note_survives_a_name_containing_spaces(self):
        """Columns are tab-delimited, so a spaced name must not shift them."""
        entries = parse(self.TEXT, "dshield")
        assert entries[ipaddress.ip_network("185.220.101.0/24")] == "Other Net, DE"


class TestJsonFormats:
    def test_aws_ip_ranges(self):
        """AWS publishes ip_prefix and ipv6_prefix under two separate keys."""
        text = (
            '{"syncToken":"1","prefixes":['
            '{"ip_prefix":"3.4.12.4/32","service":"AMAZON"},'
            '{"ip_prefix":"52.94.0.0/22","service":"EC2"}],'
            '"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/40"}]}'
        )
        assert networks_in(text, "aws") == nets(
            "3.4.12.4/32", "52.94.0.0/22", "2600:1f00::/40"
        )

    def test_gcp_cloud_json(self):
        """GCP tags each prefix with either ipv4Prefix or ipv6Prefix."""
        text = (
            '{"syncToken":"1","prefixes":['
            '{"ipv4Prefix":"34.1.208.0/20","scope":"africa-south1"},'
            '{"ipv6Prefix":"2600:1900::/28","scope":"us-central1"},'
            '{"ipv4Prefix":"34.152.86.0/23"}]}'
        )
        assert networks_in(text, "gcp") == nets(
            "34.1.208.0/20", "2600:1900::/28", "34.152.86.0/23"
        )

    def test_bunny_bare_ip_array(self):
        """BunnyCDN returns a plain JSON array of addresses, no CIDR suffix."""
        text = '["89.187.188.227","89.187.162.249","2400:52e0:1500::714:1"]'
        assert networks_in(text, "bunny") == nets(
            "89.187.188.227/32", "89.187.162.249/32", "2400:52e0:1500::714:1/128"
        )

    def test_json_entries_carry_no_note(self):
        entries = parse('["1.2.3.4"]', "bunny")
        assert entries[ipaddress.ip_network("1.2.3.4/32")] == ""

    def test_json_host_bits_are_tolerated(self):
        assert networks_in('{"prefixes":[{"ipv4Prefix":"1.2.3.4/24"}]}', "gcp") == nets(
            "1.2.3.0/24"
        )


class TestJsonFailFast:
    def test_invalid_json_is_rejected(self):
        with pytest.raises(ParseError, match="valid JSON"):
            parse("<html>503</html>\n", "aws", name="aws")

    def test_aws_shape_drift_is_rejected(self):
        """A renamed or missing top-level key must fail, not silently yield nothing."""
        with pytest.raises(ParseError, match="format may have changed"):
            parse('{"unexpected":[]}', "aws", name="aws")

    def test_gcp_shape_drift_is_rejected(self):
        with pytest.raises(ParseError, match="format may have changed"):
            parse('{"unexpected":[]}', "gcp", name="gcp")

    def test_empty_json_feed_is_rejected(self):
        with pytest.raises(ParseError, match="zero IPs"):
            parse('{"prefixes":[],"ipv6_prefixes":[]}', "aws", name="aws")

    def test_empty_bunny_array_is_rejected(self):
        with pytest.raises(ParseError, match="zero IPs"):
            parse("[]", "bunny", name="bunny")

    def test_json_error_message_names_the_source(self):
        with pytest.raises(ParseError, match="my_feed"):
            parse("not json", "aws", name="my_feed")


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
