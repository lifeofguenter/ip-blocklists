"""Compression tests: dedupe, merge, subsume, and stable rendering."""

import ipaddress

from blocklists.aggregate import collapse, render


def nets(*cidrs):
    return {ipaddress.ip_network(cidr) for cidr in cidrs}


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
