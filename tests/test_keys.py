import unittest

from sysctl_audit.keys import KeyTrie, canonical, is_net_key, tokenize


class KeyMatchingTest(unittest.TestCase):
    def test_dot_and_slash_forms_are_equivalent(self):
        self.assertEqual(
            canonical("net/ipv4/conf/all/rp_filter"),
            "net.ipv4.conf.all.rp_filter",
        )
        self.assertEqual(
            tokenize("net.ipv4/conf.all/rp_filter"),
            ["net", "ipv4", "conf", "all", "rp_filter"],
        )

    def test_trie_matches_simple_key(self):
        trie = KeyTrie(["net.ipv4.ip_forward", "kernel.pid_max"])
        self.assertEqual(trie.match("net/ipv4/ip_forward"), "net.ipv4.ip_forward")
        self.assertEqual(trie.match("kernel.pid_max"), "kernel.pid_max")
        self.assertIsNone(trie.match("net.ipv4.ip_forwrad"))  # typo

    def test_dotted_interface_name_component(self):
        # VLAN interface eth0.100: the directory component itself has a dot.
        trie = KeyTrie(
            [
                "net.ipv4.conf.eth0.100.rp_filter",
                "net.ipv4.conf.eth0.100.arp_ignore",
                "net.ipv4.conf.all.rp_filter",
            ]
        )
        self.assertEqual(
            trie.match("net.ipv4.conf.eth0.100.rp_filter"),
            "net.ipv4.conf.eth0.100.rp_filter",
        )
        self.assertEqual(
            trie.match("net/ipv4/conf/eth0.100/arp_ignore"),
            "net.ipv4.conf.eth0.100.arp_ignore",
        )
        # "all" must still resolve as its own component, not be absorbed.
        self.assertEqual(
            trie.match("net.ipv4.conf.all.rp_filter"),
            "net.ipv4.conf.all.rp_filter",
        )

    def test_net_key_classification(self):
        self.assertTrue(is_net_key("net.ipv4.ip_forward"))
        self.assertTrue(is_net_key("net/ipv4/ip_forward"))
        self.assertFalse(is_net_key("kernel.pid_max"))


if __name__ == "__main__":
    unittest.main()
