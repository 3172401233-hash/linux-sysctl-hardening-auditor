"""Audit resolved sysctl config against per-namespace /proc/sys snapshots."""

from __future__ import annotations

from typing import Dict, List

from . import keys as keymod
from . import units
from .engine import resolve
from .keys import KeyTrie, is_net_key
from .models import (
    AuditReport,
    Finding,
    FindingKind,
    Namespace,
    NamespaceKind,
    SysctlConfigFile,
)


class AuditEngine:
    """Compute effective sysctl values per namespace and diff vs runtime."""

    def __init__(
        self,
        config_files: List[SysctlConfigFile],
        namespaces: List[Namespace],
    ) -> None:
        self.config_files = config_files
        self.namespaces = namespaces
        hosts = [ns for ns in namespaces if ns.kind is NamespaceKind.HOST]
        if not hosts:
            raise ValueError("at least one host namespace is required")
        self.host = hosts[0]

    def audit(self) -> AuditReport:
        resolved, findings = resolve(self.config_files)
        report = AuditReport(findings=list(findings), resolved=resolved)
        host_trie = KeyTrie(self.host.snapshot)
        ns_tries: Dict[str, KeyTrie] = {
            ns.name: KeyTrie(ns.snapshot) for ns in self.namespaces
        }
        for ns in self.namespaces:
            for key, value in resolved.items():
                report.findings.extend(
                    self._check_key(ns, key, value, host_trie, ns_tries)
                )
            report.findings.extend(self._check_ipv6_symmetry(ns, resolved, ns_tries))
        return report

    def _snapshot_for(self, ns: Namespace, key: str) -> Namespace:
        """net.* keys are per-netns; everything else resolves on the host."""
        if is_net_key(key) or ns.kind is NamespaceKind.HOST:
            return ns
        return self.host

    def _check_key(self, ns, key, resolved_value, host_trie, ns_tries):
        findings: List[Finding] = []
        config_value = resolved_value.value
        target = self._snapshot_for(ns, key)
        trie = ns_tries[target.name]
        canonical_key = trie.match(key)

        if canonical_key is None:
            # Distinguish "key exists nowhere" (typo / module absent
            # everywhere) from "missing only in this namespace's snapshot".
            elsewhere = host_trie.match(key) or any(
                t.match(key) for name, t in ns_tries.items() if name != target.name
            )
            kind = (
                FindingKind.MISSING_RUNTIME
                if elsewhere
                else FindingKind.UNKNOWN_KEY
            )
            findings.append(
                Finding(
                    kind=kind,
                    namespace=ns.name,
                    key=key,
                    message=(
                        f"{key} configured at {resolved_value.source} but not "
                        f"present in {target.name}'s /proc/sys snapshot"
                    ),
                    details={"source": str(resolved_value.source)},
                )
            )
            return findings

        readonly = {keymod.canonical(k) for k in target.readonly}
        if canonical_key in readonly:
            findings.append(
                Finding(
                    kind=FindingKind.READONLY_KEY,
                    namespace=ns.name,
                    key=canonical_key,
                    message=(
                        f"{canonical_key} is read-only in namespace "
                        f"{target.name}; write from {resolved_value.source} "
                        f"would fail or be silently dropped"
                    ),
                    details={"source": str(resolved_value.source)},
                )
            )

        runtime_value = target.snapshot[canonical_key]
        if not units.values_equal(config_value, runtime_value):
            unit = units.unit_of(canonical_key)
            if unit and unit[1]:
                findings.append(
                    Finding(
                        kind=FindingKind.UNIT_CAVEAT,
                        namespace=ns.name,
                        key=canonical_key,
                        message=(
                            f"{canonical_key}: config {config_value!r} vs "
                            f"runtime {runtime_value!r}; unit is "
                            f"{unit[0]} (HZ-dependent), cannot be judged "
                            f"from files alone"
                        ),
                        details={
                            "config": config_value,
                            "runtime": runtime_value,
                            "unit": unit[0],
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        kind=FindingKind.DRIFT,
                        namespace=ns.name,
                        key=canonical_key,
                        message=(
                            f"{canonical_key}: config {config_value!r} "
                            f"({resolved_value.source}) != runtime "
                            f"{runtime_value!r} in {target.name}"
                        ),
                        details={
                            "config": config_value,
                            "runtime": runtime_value,
                            "source": str(resolved_value.source),
                        },
                    )
                )
        return findings

    def _check_ipv6_symmetry(self, ns, resolved, ns_tries):
        findings: List[Finding] = []
        for ipv4_key, ipv6_key in keymod.IPV4_IPV6_PAIRS.items():
            if ipv6_key is None or ipv4_key not in resolved:
                continue
            target = self._snapshot_for(ns, ipv4_key)
            trie = ns_tries[target.name]
            if trie.match(ipv6_key) is None:
                continue  # IPv6 disabled or not visible in this snapshot
            if ipv6_key not in resolved:
                findings.append(
                    Finding(
                        kind=FindingKind.IPV6_ASYMMETRY,
                        namespace=ns.name,
                        key=ipv6_key,
                        message=(
                            f"{ipv4_key} is hardened "
                            f"({resolved[ipv4_key].source}) but its IPv6 "
                            f"counterpart {ipv6_key} is not configured"
                        ),
                        details={"ipv4_key": ipv4_key},
                    )
                )
        return findings
