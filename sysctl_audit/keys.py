"""Sysctl key normalization and matching.

The kernel exposes sysctls under /proc/sys as a directory tree, but the
``sysctl`` tool and config files address them with dotted names.  Both
separators are equivalent *except* that a path component itself may contain
dots -- most notably VLAN interface names such as ``eth0.100`` under
``net.ipv4.conf.<ifname>``.  To resolve this ambiguity we match config keys
against the keys actually present in a /proc/sys snapshot using a trie, and
let one snapshot component greedily consume several dot-separated tokens.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

_SEPARATORS = re.compile(r"[./]")


def tokenize(key: str) -> List[str]:
    """Split a config key on both '.' and '/' separators."""
    return [tok for tok in _SEPARATORS.split(key.strip()) if tok]


def canonical(key: str) -> str:
    """Canonical dotted form, assuming no component contains a literal dot."""
    return ".".join(tokenize(key))


class _TrieNode:
    __slots__ = ("children", "terminal")

    def __init__(self) -> None:
        self.children: Dict[str, "_TrieNode"] = {}
        self.terminal: bool = False


class KeyTrie:
    """Trie over snapshot keys; components may contain literal dots."""

    def __init__(self, keys) -> None:
        self._root = _TrieNode()
        for key in keys:
            node = self._root
            for component in key.split("."):
                node = node.children.setdefault(component, _TrieNode())
            node.terminal = True

    def match(self, key: str) -> Optional[str]:
        """Resolve a config key to the canonical snapshot key, or None.

        At every level the longest component (most tokens joined by '.')
        wins, mirroring how nested directories like ``conf/eth0.100`` must
        be preferred over a hypothetical ``conf/eth0/100`` path.
        """
        tokens = tokenize(key)
        matched = self._descend(self._root, tokens, 0)
        if matched is None:
            return None
        return ".".join(matched)

    def _descend(
        self, node: _TrieNode, tokens: List[str], pos: int
    ) -> Optional[List[str]]:
        if pos == len(tokens):
            return [] if node.terminal else None
        # Try the longest possible component first.
        for end in range(len(tokens), pos, -1):
            component = ".".join(tokens[pos:end])
            child = node.children.get(component)
            if child is None:
                continue
            rest = self._descend(child, tokens, end)
            if rest is not None:
                return [component] + rest
        return None


def split_prefix(key: str, prefix: str) -> Optional[str]:
    """Return the remainder of ``key`` below ``prefix`` or None."""
    key_toks, pre_toks = tokenize(key), tokenize(prefix)
    if key_toks[: len(pre_toks)] == pre_toks:
        return ".".join(key_toks[len(pre_toks):])
    return None


def is_net_key(key: str) -> bool:
    """True for keys living under net.* (per-network-namespace)."""
    toks = tokenize(key)
    return bool(toks) and toks[0] == "net"


# IPv4/IPv6 knobs that harden the same protocol behaviour.  A baseline that
# sets only one side leaves the other address family exposed.
IPV4_IPV6_PAIRS: Dict[str, Optional[str]] = {
    "net.ipv4.ip_forward": "net.ipv6.conf.all.forwarding",
    "net.ipv4.conf.all.accept_redirects": "net.ipv6.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects": "net.ipv6.conf.default.accept_redirects",
    "net.ipv4.conf.all.secure_redirects": "net.ipv6.conf.all.accept_redirects",
    "net.ipv4.conf.all.accept_source_route": "net.ipv6.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route": "net.ipv6.conf.default.accept_source_route",
    "net.ipv4.conf.all.log_martians": "net.ipv6.conf.all.log_martians",
    "net.ipv4.icmp_echo_ignore_broadcasts": None,  # IPv6 has no broadcast
    "net.ipv4.conf.all.rp_filter": None,  # no direct IPv6 counterpart
}
