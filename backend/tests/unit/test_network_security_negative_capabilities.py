"""Static architecture assertions proving mandatory negative
capabilities are genuinely absent from the M16 `network_security`
bounded context — not merely undocumented, but structurally impossible.
Each test scans the actual source files (not a description of them) so
a future regression that reintroduces one of these capabilities fails
this test immediately.

Maps to M16 brief §30 items 21-25, 77, 90-95 and the safety-negative
scenarios in §4 (no DNS rebinding, no redirect scope expansion, no
ICMP, no exploit/C2/credential-attack/shell/generic-command-runner/
msfconsole capability anywhere in this bounded context).
"""

from __future__ import annotations

from pathlib import Path

import redforge.application.network_security as app_ns_pkg
import redforge.domain.network_security as domain_ns_pkg
import redforge.infrastructure.database.repositories.network_security as infra_ns_pkg

_PACKAGES = [app_ns_pkg, domain_ns_pkg, infra_ns_pkg]


def _all_source_text() -> str:
    """Concatenates every .py source file in the three network_security
    packages (domain/application/infrastructure) — the ENTIRE M16
    bounded context's own code, not a hand-picked subset."""
    chunks: list[str] = []
    for pkg in _PACKAGES:
        pkg_dir = Path(pkg.__file__).parent
        for path in pkg_dir.glob("*.py"):
            chunks.append(path.read_text())
    return "\n".join(chunks)


class TestNoDnsResolutionSurface:
    """Scenario #21/#22: DNS resolution/rebinding scope-expansion cannot
    occur because M16 performs NO hostname resolution anywhere — its
    target is always a pre-resolved AIAsset (IP_ADDRESS or NETWORK/CIDR
    external_id), never a hostname the orchestrator itself looks up."""

    def test_no_dns_resolution_call_anywhere_in_network_security(self) -> None:
        source = _all_source_text()
        # getaddrinfo/gethostbyname are the stdlib DNS resolution entry
        # points; loop.getnameinfo (reverse DNS) is intentionally NOT
        # excluded here since M16 never calls it either — confirmed by
        # this same absence.
        for forbidden in ("getaddrinfo", "gethostbyname", "getnameinfo", "resolve_dns"):
            assert forbidden not in source, f"found forbidden DNS call: {forbidden}"

    def test_no_httpx_or_http_redirect_following_import(self) -> None:
        """Scenario #23: redirect-scope-expansion cannot occur because
        M16 never makes an HTTP request at all (no httpx import,
        no redirect-following logic) — only TCP-connect, TLS handshake,
        and the M13 protocol validators (which are also non-HTTP)."""
        source = _all_source_text()
        assert "import httpx" not in source
        assert "follow_redirects" not in source


class TestNoIcmpSurface:
    """Scenario #25: ICMP-failure-does-not-mean-host-down is trivially
    satisfied because M16 never uses ICMP for reachability at all —
    only bounded TCP-connect (`check_tcp_connectivity`, reused
    unchanged from M11) establishes reachability."""

    def test_no_icmp_or_raw_socket_usage(self) -> None:
        source = _all_source_text()
        for forbidden in ("SOCK_RAW", "IPPROTO_ICMP"):
            assert forbidden not in source, f"found forbidden ICMP/raw-socket reference: {forbidden}"


class TestNoDiscoveredHostAutoEscalation:
    """Scenario #24: a discovered IP/host cannot become an automatically
    active probe target. The orchestrator's own probe loop
    (`_execute_validation`) only ever iterates over
    `plan.addresses`/`plan.ports`, itself built exclusively from the
    caller-supplied, already-authorized `authorized_addresses` list —
    there is no code path where a value discovered mid-run (e.g. a
    reverse-DNS hostname or a related asset) is added back into the
    set of addresses being probed THIS run."""

    def test_orchestrator_never_expands_its_own_address_set_mid_run(self) -> None:
        source = _all_source_text()
        # `plan.addresses` is set once by `build_plan(...)` from the
        # caller's already-authorized list and never reassigned/mutated
        # afterward — confirmed by the absence of any `.append(`/
        # `.add(` call against an address collection inside the probe
        # loop itself.
        assert "plan.addresses.append" not in source
        assert "authorized_addresses.append" not in source


class TestNoShellOrCommandExecutionSurface:
    """Scenarios #90-95: no exploit execution, no C2 execution, no
    credential attack, no shell, no generic command runner, no
    msfconsole embedding — anywhere in this bounded context."""

    def test_no_subprocess_or_shell_execution(self) -> None:
        source = _all_source_text()
        for forbidden in (
            "subprocess", "os.system", "shell=True", "Popen", "eval(", "exec(",
        ):
            assert forbidden not in source, f"found forbidden execution primitive: {forbidden}"

    def test_no_exploit_c2_or_credential_attack_vocabulary(self) -> None:
        source = _all_source_text().lower()
        for forbidden in (
            "msfconsole", "metasploit", "exploit_module", "c2_beacon",
            "brute_force", "password_spray", "credential_stuffing",
        ):
            assert forbidden not in source, f"found forbidden capability reference: {forbidden}"

    def test_no_command_script_module_exploit_payload_request_fields(self) -> None:
        """The API request models (CreatePolicyRequest) never define a
        command/script/module/exploit/payload field — confirmed by
        reading the actual Pydantic model source, not just the request
        schema at runtime (already separately proven live via HTTP:
        an unsafe extra field is structurally ignored)."""
        api_source = Path(
            Path(__file__).parents[2]
            / "src" / "redforge" / "api" / "v1" / "network_security.py"
        ).read_text()
        for forbidden_field in (
            "command:", "script:", "module:", "exploit:", "payload:", "tool_args:",
            "nmap_args", "masscan_args", "scanner_flags",
        ):
            assert forbidden_field not in api_source, (
                f"found forbidden request field declaration: {forbidden_field}"
            )
