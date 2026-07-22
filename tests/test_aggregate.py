"""Compression tests: dedupe, merge, subsume, and stable rendering."""

import ipaddress

from builder.aggregate import attribute, collapse, render


def nets(*cidrs):
    return {ipaddress.ip_network(cidr) for cidr in cidrs}


def net(cidr):
    return ipaddress.ip_network(cidr)


def attributed(provenance):
    """Collapse ``{network: {source: note}}`` and render it with provenance."""
    cidrs = collapse(provenance)
    return render(cidrs, attribute(cidrs, provenance))


class TestCollapse:
    def test_merges_adjacent_networks(self):
        assert collapse(nets("1.2.2.0/24", "1.2.3.0/24")) == [ipaddress.ip_network("1.2.2.0/23")]

    def test_merges_a_full_run_of_host_routes(self):
        """Four aligned /32s collapse into a single /30."""
        hosts = nets(*(f"1.2.3.{i}/32" for i in range(4)))
        assert collapse(hosts) == [ipaddress.ip_network("1.2.3.0/30")]

    def test_does_not_merge_unaligned_neighbours(self):
        """1.2.3.0/24 and 1.2.4.0/24 share no supernet they fully cover."""
        assert collapse(nets("1.2.3.0/24", "1.2.4.0/24")) == [
            ipaddress.ip_network("1.2.3.0/24"),
            ipaddress.ip_network("1.2.4.0/24"),
        ]

    def test_subsumes_hosts_into_their_covering_network(self):
        assert collapse(nets("1.2.3.0/24", "1.2.3.4/32", "1.2.3.99/32")) == [
            ipaddress.ip_network("1.2.3.0/24")
        ]

    def test_removes_duplicates(self):
        assert collapse([ipaddress.ip_network("1.2.3.4/32")] * 5) == [
            ipaddress.ip_network("1.2.3.4/32")
        ]

    def test_output_is_sorted(self):
        result = collapse(nets("9.9.9.9/32", "1.1.1.1/32", "5.5.5.5/32"))
        assert result == sorted(result)

    def test_never_widens_coverage(self):
        """The collapsed set must cover exactly the input addresses, no more."""
        original = nets("1.2.3.0/25", "1.2.3.128/25", "8.8.8.8/32")
        collapsed = collapse(original)
        assert sum(net.num_addresses for net in collapsed) == sum(
            net.num_addresses for net in original
        )

    def test_collapses_ipv6(self):
        assert collapse(nets("2001:db8::/33", "2001:db8:8000::/33")) == [
            ipaddress.ip_network("2001:db8::/32")
        ]


class TestRender:
    def test_one_cidr_per_line_with_trailing_newline(self):
        text = render(collapse(nets("1.2.3.0/24", "8.8.8.8/32")))
        assert text == "1.2.3.0/24\n8.8.8.8/32\n"

    def test_host_routes_keep_explicit_prefix(self):
        assert render(collapse(nets("8.8.8.8/32"))) == "8.8.8.8/32\n"

    def test_ipv6_rendering(self):
        assert render(collapse(nets("2001:db8::1/128"))) == "2001:db8::1/128\n"

    def test_empty_input_renders_empty(self):
        assert render([]) == ""

    def test_output_is_deterministic(self):
        """Stable ordering keeps the daily commit diffs meaningful."""
        cidrs = nets("9.9.9.9/32", "1.1.1.1/32", "5.5.5.5/32")
        assert render(collapse(cidrs)) == render(collapse(cidrs))


class TestAttribution:
    def test_credits_the_contributing_source(self):
        result = attribute([net("1.2.3.4/32")], {net("1.2.3.4/32"): {"feed_a": ""}})
        assert set(result[net("1.2.3.4/32")]) == {"feed_a"}

    def test_a_merged_cidr_is_credited_to_every_contributor(self):
        """Collapsing across feeds must not lose either feed's claim."""
        provenance = {
            net("1.2.3.0/25"): {"feed_a": ""},
            net("1.2.3.128/25"): {"feed_b": ""},
        }
        cidrs = collapse(provenance)
        assert cidrs == [net("1.2.3.0/24")]
        assert set(attribute(cidrs, provenance)[net("1.2.3.0/24")]) == {"feed_a", "feed_b"}

    def test_a_subsumed_host_route_keeps_its_source(self):
        provenance = {
            net("1.2.3.0/24"): {"feed_a": ""},
            net("1.2.3.9/32"): {"feed_b": "seen scanning"},
        }
        cidrs = collapse(provenance)
        assert set(attribute(cidrs, provenance)[net("1.2.3.0/24")]) == {"feed_a", "feed_b"}

    def test_notes_are_collected_per_cidr(self):
        provenance = {net("1.10.16.0/20"): {"spamhaus_drop": "SBL256894"}}
        result = attribute([net("1.10.16.0/20")], provenance)
        assert result[net("1.10.16.0/20")]["spamhaus_drop"] == {"SBL256894"}

    def test_empty_input(self):
        assert attribute([], {}) == {}


class TestAttributedRender:
    def test_entries_are_sorted_by_address_not_grouped_by_source(self):
        """One flat ascending list, so an entry never moves when its feeds change."""
        text = attributed(
            {
                net("1.1.1.1/32"): {"feed_a": ""},
                net("3.3.3.3/32"): {"feed_a": ""},
                net("2.2.2.2/32"): {"feed_b": ""},
            }
        )
        assert text == (
            "1.1.1.1/32  # [feed_a]\n"
            "2.2.2.2/32  # [feed_b]\n"
            "3.3.3.3/32  # [feed_a]\n"
        )

    def test_every_entry_carries_its_own_sources(self):
        """Searching for any single IP must reveal which feed listed it."""
        # Spaced apart so they cannot collapse into fewer CIDRs.
        provenance = {net(f"1.{i}.0.0/24"): {"feed_a": ""} for i in range(50)}
        text = attributed(provenance)
        assert text.count("# [feed_a]") == 50
        assert len(text.splitlines()) == 50

    def test_notes_follow_the_source_bracket_on_the_same_line(self):
        text = attributed({net("1.10.16.0/20"): {"spamhaus_drop": "SBL256894"}})
        assert text == "1.10.16.0/20  # [spamhaus_drop] SBL256894\n"

    def test_multiple_sources_are_listed_alphabetically_in_one_bracket(self):
        text = attributed({net("1.2.3.4/32"): {"zeta": "n2", "alpha": "n1"}})
        assert text == "1.2.3.4/32  # [alpha, zeta] n1; n2\n"

    def test_entries_without_any_source_are_marked_unknown(self):
        assert render([net("1.2.3.4/32")], {}) == "1.2.3.4/32  # [unknown]\n"

    def test_output_is_ordered_deterministically(self):
        provenance = {
            net("9.9.9.9/32"): {"zeta": ""},
            net("1.1.1.1/32"): {"alpha": ""},
        }
        assert attributed(provenance) == attributed(provenance)
        assert attributed(provenance).index("1.1.1.1") < attributed(provenance).index("9.9.9.9")

    def test_output_is_still_parseable_as_a_cidr_list(self):
        """Stripping comments must leave exactly the collapsed CIDRs, in order."""
        provenance = {
            net("1.10.16.0/20"): {"spamhaus_drop": "SBL256894"},
            net("8.8.8.8/32"): {"feed_a": ""},
        }
        text = attributed(provenance)
        cidrs = [
            line.split("#")[0].strip()
            for line in text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert cidrs == ["1.10.16.0/20", "8.8.8.8/32"]

    def test_empty_input_renders_empty(self):
        assert attributed({}) == ""
