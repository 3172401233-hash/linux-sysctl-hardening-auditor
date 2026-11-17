"""Value normalization and unit metadata.

sysctl values are untyped strings.  For drift detection we compare
numerically where possible and element-wise for multi-value knobs such as
``net.ipv4.tcp_rmem``.  Some knobs are expressed in kernel-internal units
(notably jiffies, whose duration depends on CONFIG_HZ); a numeric mismatch
on those keys cannot be judged from files alone, so we emit a caveat
instead of a hard drift verdict.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

# key -> (unit, hz_dependent)
UNIT_TABLE: Dict[str, Tuple[str, bool]] = {
    "net.ipv4.icmp_ratelimit": ("jiffies", True),
    "net.ipv4.icmp_ratemask": ("bitmask", False),
    "net.ipv4.tcp_keepalive_time": ("seconds", False),
    "net.ipv4.tcp_keepalive_intvl": ("seconds", False),
    "net.ipv4.tcp_fin_timeout": ("seconds", False),
    "net.ipv4.neigh.default.gc_stale_time": ("seconds", False),
    "vm.dirty_expire_centisecs": ("centiseconds", False),
    "vm.dirty_writeback_centisecs": ("centiseconds", False),
    "vm.min_free_kbytes": ("kibibytes", False),
    "kernel.hung_task_timeout_secs": ("seconds", False),
}


def unit_of(key: str) -> Optional[Tuple[str, bool]]:
    return UNIT_TABLE.get(key)


def _as_number(text: str) -> Optional[float]:
    try:
        return float(text)
    except ValueError:
        return None


def normalize(value: str) -> Tuple[object, ...]:
    """Split multi-value knobs and coerce numeric fields to numbers."""
    parts = value.split()
    normalized = []
    for part in parts:
        number = _as_number(part)
        normalized.append(number if number is not None else part)
    return tuple(normalized)


def values_equal(config_value: str, runtime_value: str) -> bool:
    return normalize(config_value) == normalize(runtime_value)
