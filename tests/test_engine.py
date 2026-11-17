import unittest

from sysctl_audit import FindingKind, SysctlConfigFile
from sysctl_audit.engine import order_files, resolve


def conf(path, content=""):
    return SysctlConfigFile(path=path, content=content)


class LoadOrderTest(unittest.TestCase):
    def test_dropins_sorted_by_filename_across_dirs(self):
        resolved, _ = resolve(
            [
                conf("/etc/sysctl.d/50-local.conf", "net.ipv4.ip_forward = 0\n"),
                conf("/usr/lib/sysctl.d/10-base.conf", "net.ipv4.ip_forward = 1\n"),
            ]
        )
        value = resolved["net.ipv4.ip_forward"]
        self.assertEqual(value.value, "0")
        self.assertEqual(value.source.path, "/etc/sysctl.d/50-local.conf")
        self.assertEqual(len(value.history), 2)

    def test_same_basename_in_etc_masks_usrl_lib(self):
        files = [
            conf("/usr/lib/sysctl.d/50-docker.conf", "net.ipv4.ip_forward = 1\n"),
            conf("/etc/sysctl.d/50-docker.conf", "net.ipv4.ip_forward = 0\n"),
        ]
        ordered, findings = order_files(files)
        self.assertEqual([f.path for f in ordered], ["/etc/sysctl.d/50-docker.conf"])
        masked = [f for f in findings if f.kind is FindingKind.MASKED_FILE]
        self.assertEqual(len(masked), 1)
        self.assertEqual(masked[0].details["masked"], "/usr/lib/sysctl.d/50-docker.conf")

    def test_etc_sysctl_conf_applies_after_dropins(self):
        resolved, _ = resolve(
            [
                conf("/etc/sysctl.conf", "net.ipv4.ip_forward = 1\n"),
                conf("/etc/sysctl.d/99-z.conf", "net.ipv4.ip_forward = 0\n"),
            ]
        )
        value = resolved["net.ipv4.ip_forward"]
        self.assertEqual(value.value, "1")
        self.assertEqual(value.source.path, "/etc/sysctl.conf")

    def test_last_write_wins_and_source_recorded(self):
        resolved, findings = resolve(
            [
                conf("/usr/lib/sysctl.d/10-a.conf", "net.core.somaxconn = 128\n"),
                conf("/etc/sysctl.d/60-b.conf", "net.core.somaxconn = 1024\n"),
                conf("/etc/sysctl.d/70-c.conf", "net.core.somaxconn = 4096\n"),
            ]
        )
        value = resolved["net.core.somaxconn"]
        self.assertEqual(value.value, "4096")
        self.assertEqual(value.source.path, "/etc/sysctl.d/70-c.conf")
        self.assertEqual(value.source.line, 1)
        self.assertEqual(len(value.history), 3)
        overrides = [f for f in findings if f.kind is FindingKind.OVERRIDE]
        self.assertEqual(len(overrides), 1)
        self.assertIn("70-c.conf", overrides[0].details["chain"])

    def test_slash_and_dot_keys_resolve_to_same_entry(self):
        resolved, _ = resolve(
            [
                conf("/etc/sysctl.d/10-a.conf", "net/ipv4/ip_forward = 1\n"),
                conf("/etc/sysctl.d/20-b.conf", "net.ipv4.ip_forward = 0\n"),
            ]
        )
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved["net.ipv4.ip_forward"].value, "0")


if __name__ == "__main__":
    unittest.main()
