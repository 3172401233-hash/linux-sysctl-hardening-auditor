"""Parser for sysctl.conf / sysctl.d drop-in files.

Syntax follows sysctl.d(5): blank lines and lines starting with '#' or ';'
are ignored, a leading '-' tells systemd-sysctl to ignore failures for that
line, and ``key = value`` / ``key=value`` are both accepted.  Everything
after the first '=' is the value (whitespace trimmed).
"""

from __future__ import annotations

from typing import List

from .models import Assignment, SourceRef, SysctlConfigFile


def parse_file(config: SysctlConfigFile) -> List[Assignment]:
    assignments: List[Assignment] = []
    for lineno, raw in enumerate(config.content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        ignore_errors = False
        if line.startswith("-"):
            ignore_errors = True
            line = line[1:].lstrip()
        if "=" not in line:
            # Not a valid assignment; systemd-sysctl logs and skips these.
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not key:
            continue
        assignments.append(
            Assignment(
                key=key,
                value=value,
                source=SourceRef(path=config.path, line=lineno),
                ignore_errors=ignore_errors,
            )
        )
    return assignments
