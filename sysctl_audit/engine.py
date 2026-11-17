"""Config load-order resolution following systemd-sysctl semantics.

Drop-ins are collected from /usr/lib/sysctl.d, /run/sysctl.d and
/etc/sysctl.d (in that priority order) and applied sorted by filename.
A file in a higher-priority directory with the same basename *masks* the
lower-priority one entirely.  /etc/sysctl.conf is applied last, after all
drop-ins.  Later assignments of the same key override earlier ones; the
winning source (file:line) is recorded together with the full chain.
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

from .keys import canonical
from .models import (
    Assignment,
    Finding,
    FindingKind,
    ResolvedValue,
    SourceRef,
    SysctlConfigFile,
)
from .parser import parse_file

_DIR_RANK = {
    "/usr/lib/sysctl.d": 0,
    "/lib/sysctl.d": 0,
    "/usr/local/lib/sysctl.d": 1,
    "/run/sysctl.d": 2,
    "/etc/sysctl.d": 3,
}

_SYSCTL_CONF_RANK = 4  # /etc/sysctl.conf applies after every drop-in


def _sort_key(path: str) -> Tuple[int, str]:
    directory = os.path.dirname(path)
    if os.path.basename(path) == "sysctl.conf" and directory == "/etc":
        return (_SYSCTL_CONF_RANK, "sysctl.conf")
    return (_DIR_RANK.get(directory, 1), os.path.basename(path))


def order_files(
    files: List[SysctlConfigFile],
) -> Tuple[List[SysctlConfigFile], List[Finding]]:
    """Apply masking and return files in effective load order."""
    findings: List[Finding] = []
    by_basename: Dict[str, SysctlConfigFile] = {}
    for config in files:
        basename = os.path.basename(config.path)
        existing = by_basename.get(basename)
        if existing is not None and _sort_key(existing.path) < _sort_key(config.path):
            findings.append(
                Finding(
                    kind=FindingKind.MASKED_FILE,
                    namespace="*",
                    key="",
                    message=(
                        f"{existing.path} is masked by {config.path} "
                        f"(same basename in higher-priority directory)"
                    ),
                    details={"masked": existing.path, "winner": config.path},
                )
            )
            by_basename[basename] = config
        elif existing is not None:
            findings.append(
                Finding(
                    kind=FindingKind.MASKED_FILE,
                    namespace="*",
                    key="",
                    message=(
                        f"{config.path} is masked by {existing.path} "
                        f"(same basename in higher-priority directory)"
                    ),
                    details={"masked": config.path, "winner": existing.path},
                )
            )
        else:
            by_basename[basename] = config
    ordered = sorted(by_basename.values(), key=lambda c: _sort_key(c.path))
    return ordered, findings


def resolve(
    files: List[SysctlConfigFile],
) -> Tuple[Dict[str, ResolvedValue], List[Finding]]:
    """Compute the final value and override chain for every configured key."""
    ordered, findings = order_files(files)
    resolved: Dict[str, ResolvedValue] = {}
    for config in ordered:
        for assignment in parse_file(config):
            key = canonical(assignment.key)
            previous = resolved.get(key)
            history = list(previous.history) if previous else []
            history.append((assignment.source, assignment.value))
            resolved[key] = ResolvedValue(
                key=key,
                value=assignment.value,
                source=assignment.source,
                history=history,
            )
    for key, value in resolved.items():
        if len(value.history) > 1:
            chain = " -> ".join(
                f"{source} ({val})" for source, val in value.history
            )
            findings.append(
                Finding(
                    kind=FindingKind.OVERRIDE,
                    namespace="*",
                    key=key,
                    message=(
                        f"{key} set {len(value.history)} times; "
                        f"last write wins: {value.source} = {value.value!r}"
                    ),
                    details={"chain": chain},
                )
            )
    return resolved, findings
