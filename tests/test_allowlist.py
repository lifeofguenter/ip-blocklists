"""Subtracting allowlisted ranges out of a blocklist provenance map."""

import ipaddress

from builder.allowlist import subtract


def net(cidr):
    return ipaddress.ip_network(cidr)


def prov(mapping):
    """Build a ``{network: {source: note}}`` map from ``{cidr: {source: note}}``."""
    return {net(cidr): dict(sources) for cidr, sources in mapping.items()}


class TestSubtract:
    def test_disjoint_network_is_kept_with_its_provenance(self):
        networks = prov({"1.2.3.0/24": {"feed": "note"}})
        assert subtract(networks, [net("9.9.9.0/24")]) == prov(
            {"1.2.3.0/24": {"feed": "note"}}
        )

    def test_empty_allowlist_leaves_everything_untouched(self):
        networks = prov({"1.2.3.0/24": {"feed": ""}, "5.6.7.8/32": {"other": ""}})
        assert subtract(networks, []) == networks

    def test_fully_contained_network_is_dropped(self):
        networks = prov({"1.2.3.4/32": {"feed": ""}})
        assert subtract(networks, [net("1.2.3.0/24")]) == {}

    def test_network_equal_to_an_allow_range_is_dropped(self):
        networks = prov({"1.2.3.0/24": {"feed": ""}})
        assert subtract(networks, [net("1.2.3.0/24")]) == {}

    def test_allow_supernet_drops_the_block(self):
        networks = prov({"1.2.3.0/24": {"feed": ""}})
        assert subtract(networks, [net("1.2.0.0/16")]) == {}

    def test_partial_overlap_is_split_and_pieces_keep_provenance(self):
        """A /23 with one /24 allowlisted survives as the other /24."""
        networks = prov({"62.60.130.0/23": {"spamhaus_drop": "SBL683637"}})
        result = subtract(networks, [net("62.60.131.0/24")])
        assert result == prov({"62.60.130.0/24": {"spamhaus_drop": "SBL683637"}})

    def test_multiple_allow_ranges_inside_one_block(self):
        """Two /26 holes punched in a /24 leave the two /26 gaps between them."""
        networks = prov({"10.0.0.0/24": {"feed": ""}})
        result = subtract(networks, [net("10.0.0.0/26"), net("10.0.0.128/26")])
        assert set(result) == {net("10.0.0.64/26"), net("10.0.0.192/26")}
        assert all(sources == {"feed": ""} for sources in result.values())

    def test_ipv6_fully_contained_is_dropped(self):
        networks = prov({"2600:1f00::abcd/128": {"feed": ""}})
        assert subtract(networks, [net("2600:1f00::/40")]) == {}

    def test_ipv6_disjoint_is_kept(self):
        networks = prov({"2001:db8::1/128": {"feed": ""}})
        assert subtract(networks, [net("2600:1f00::/40")]) == networks

    def test_only_the_overlapping_entry_is_affected(self):
        networks = prov(
            {
                "1.2.3.4/32": {"a": ""},  # inside the allow range -> dropped
                "8.8.8.8/32": {"b": "keep"},  # untouched
            }
        )
        result = subtract(networks, [net("1.2.3.0/24")])
        assert result == prov({"8.8.8.8/32": {"b": "keep"}})

    def test_input_map_is_not_mutated(self):
        networks = prov({"1.2.3.4/32": {"feed": ""}})
        subtract(networks, [net("1.2.3.0/24")])
        assert networks == prov({"1.2.3.4/32": {"feed": ""}})
