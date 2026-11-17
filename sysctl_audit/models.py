"""Data model for sysctl hardening audit inputs and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class NamespaceKind(str, Enum):
    HOST = "host"
    NETNS = "netns"


@dataclass(frozen=True)
class SourceRef:
    """Where a sysctl assignment came from."""

    path: str
    line: int

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.path}:{self.line}"


@dataclass
class SysctlConfigFile:
    """One sysctl configuration file (sysctl.conf or a sysctl.d drop-in)."""

    path: str
    content: str


@dataclass
class Assignment:
    """A single ``key = value`` line parsed from a config file."""

    key: str
    value: str
    source: SourceRef
    ignore_errors: bool = False  # leading '-' prefix (systemd extension)


@dataclass
class ResolvedValue:
    """The winning value for a key plus the full override chain."""

    key: str
    value: str
    source: SourceRef
    history: List[Tuple[SourceRef, str]] = field(default_factory=list)


@dataclass
class Namespace:
    """A host or container network namespace plus its /proc/sys snapshot.

    ``snapshot`` maps canonical dotted keys (``net.ipv4.ip_forward``) to the
    raw string read from /proc/sys.  ``readonly`` lists keys the kernel
    refuses to write from inside this namespace (typical for unprivileged
    containers).
    """

    name: str
    kind: NamespaceKind
    snapshot: Dict[str, str]
    readonly: Set[str] = field(default_factory=set)

    @classmethod
    def host(cls, snapshot: Dict[str, str], name: str = "host") -> "Namespace":
        return cls(name=name, kind=NamespaceKind.HOST, snapshot=snapshot)

    @classmethod
    def netns(
        cls,
        name: str,
        snapshot: Dict[str, str],
        readonly: Optional[Set[str]] = None,
    ) -> "Namespace":
        return cls(
            name=name,
            kind=NamespaceKind.NETNS,
            snapshot=snapshot,
            readonly=set(readonly or ()),
        )


class FindingKind(str, Enum):
    OVERRIDE = "override"
    MASKED_FILE = "masked_file"
    UNKNOWN_KEY = "unknown_key"
    MISSING_RUNTIME = "missing_runtime"
    READONLY_KEY = "readonly_key"
    DRIFT = "drift"
    IPV6_ASYMMETRY = "ipv6_asymmetry"
    UNIT_CAVEAT = "unit_caveat"


@dataclass
class Finding:
    kind: FindingKind
    namespace: str
    key: str
    message: str
    details: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuditReport:
    findings: List[Finding] = field(default_factory=list)
    resolved: Dict[str, ResolvedValue] = field(default_factory=dict)

    def by_kind(self, kind: FindingKind) -> List[Finding]:
        return [f for f in self.findings if f.kind is kind]

    def for_namespace(self, name: str) -> List[Finding]:
        return [f for f in self.findings if f.namespace == name]

    def summary(self) -> str:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.kind.value] = counts.get(f.kind.value, 0) + 1
        parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        return f"{len(self.findings)} finding(s): {parts or 'none'}"
