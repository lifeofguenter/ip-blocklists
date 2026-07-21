"""Sanitisation tests: bogons out, poisoned feeds rejected."""

import ipaddress

import pytest

from builder.sanitize import SanitizeError, is_bogon, sanitize


def split(*cidrs, **kwargs):
    """Sanitise ``cidrs`` and return the two families as plain sets."""
    ipv4, ipv6 = sanitize(nets(*cidrs), **kwargs)
    return set(ipv4), set(ipv6)


def nets(*cidrs):
    return {ipaddress.ip_network(cidr) for cidr in cidrs}


class TestBogons:
    @pytest.mark.parametrize(
        "cidr",
        [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.0/24",
            "127.0.0.1/32",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "100.64.0.0/10",
            "192.0.2.0/24",
            "198.18.0.0/15",
            "::1/128",
            "fe80::/10",
            "fc00::/7",
            "2001:db8::/32",
            "64:ff9b::/96",
        ],
    )
    def test_non_routable_entries_are_dropped(self, cidr):
        assert is_bogon(ipaddress.ip_network(cidr))
        assert split(cidr) == (set(), set())

    def test_routable_entries_are_kept(self):
        ipv4, ipv6 = split("1.2.3.4/32", "8.8.8.0/24")
        assert ipv4 == nets("1.2.3.4/32", "8.8.8.0/24")
        assert ipv6 == set()

    def test_reserved_supernet_is_dropped_not_fatal(self):
        """240.0.0.0/4 is broader than the /8 cap but is junk, not poison."""
        assert split("240.0.0.0/4") == (set(), set())


class TestFamilySplit:
    def test_splits_ipv4_from_ipv6(self):
        ipv4, ipv6 = split("1.2.3.4/32", "2606:4700::1/128", "8.8.8.0/24")
        assert ipv4 == nets("1.2.3.4/32", "8.8.8.0/24")
        assert ipv6 == nets("2606:4700::1/128")

    def test_empty_input_gives_empty_sets(self):
        assert split() == (set(), set())


class TestPoisonedFeeds:
    @pytest.mark.parametrize("cidr", ["0.0.0.0/0", "0.0.0.0/1", "8.0.0.0/6", "128.0.0.0/2"])
    def test_overly_broad_ipv4_is_fatal(self, cidr):
        with pytest.raises(SanitizeError, match="broader than /8"):
            sanitize(nets(cidr), name="poisoned")

    @pytest.mark.parametrize("cidr", ["::/0", "2000::/3", "2001::/16"])
    def test_overly_broad_ipv6_is_fatal(self, cidr):
        with pytest.raises(SanitizeError, match="broader than /19"):
            sanitize(nets(cidr), name="poisoned")

    def test_boundary_prefixes_are_allowed(self):
        ipv4, ipv6 = split("11.0.0.0/8", "2001:2000::/19")
        assert ipv4 == nets("11.0.0.0/8")
        assert ipv6 == nets("2001:2000::/19")

    def test_error_message_names_the_source(self):
        with pytest.raises(SanitizeError, match="my_feed"):
            sanitize(nets("0.0.0.0/0"), name="my_feed")

    def test_one_bad_entry_poisons_the_whole_source(self):
        with pytest.raises(SanitizeError):
            sanitize(nets("1.2.3.4/32", "0.0.0.0/0"), name="my_feed")
