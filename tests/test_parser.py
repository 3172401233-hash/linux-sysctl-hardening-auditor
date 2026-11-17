import unittest

from sysctl_audit import SysctlConfigFile, parse_file


class ParserTest(unittest.TestCase):
    def parse(self, content, path="/etc/sysctl.conf"):
        return parse_file(SysctlConfigFile(path=path, content=content))

    def test_basic_assignment_and_comments(self):
        assignments = self.parse(
            "# comment\n"
            "; another comment\n"
            "\n"
            "net.ipv4.ip_forward = 1\n"
            "kernel.pid_max=4194304\n"
        )
        self.assertEqual(len(assignments), 2)
        self.assertEqual(assignments[0].key, "net.ipv4.ip_forward")
        self.assertEqual(assignments[0].value, "1")
        self.assertEqual(assignments[0].source.line, 4)
        self.assertEqual(assignments[1].value, "4194304")

    def test_dash_prefix_marks_ignore_errors(self):
        (assignment,) = self.parse("-net.ipv4.conf.all.rp_filter = 1\n")
        self.assertTrue(assignment.ignore_errors)
        self.assertEqual(assignment.key, "net.ipv4.conf.all.rp_filter")

    def test_value_may_contain_equals_and_whitespace(self):
        (assignment,) = self.parse("kernel.sysrq = 1  # trailing kept verbatim\n")
        self.assertEqual(assignment.value, "1  # trailing kept verbatim")
        (multi,) = self.parse("net.ipv4.tcp_rmem = 4096\t87380\t6291456\n")
        self.assertEqual(multi.value, "4096\t87380\t6291456")

    def test_invalid_lines_are_skipped(self):
        self.assertEqual(self.parse("not a valid line\n= novalue\n"), [])


if __name__ == "__main__":
    unittest.main()
