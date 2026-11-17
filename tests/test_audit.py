import unittest

from sysctl_audit import (
    AuditEngine,
    FindingKind,
    Namespace,
    SysctlConfigFile,
)


HOST_SNAPSHOT = {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.all.accept_redirects": "1",
    "net.ipv4.icmp_ratelimit": "1000",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv6.conf.all.accept_redirects": "1",
    "kernel.pid_max": "4194304",
}

CONTAINER_SNAPSHOT = {
    "net.ipv4.ip_forward": "0",
    "net.ipv4.conf.all.rp_filter": "0",
    "net.ipv4.conf.all.accept_redirects": "1",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv6.conf.all.accept_redirects": "1",
}


def conf(path, content):
    return SysctlConfigFile(path=path, content=content)


def make_engine(files, container_snapshot=None, readonly=frozenset()):
    namespaces = [Namespace.host(dict(HOST_SNAPSHOT))]
    if container_snapshot is not None:
        namespaces.append(
            Namespace.netns("web", dict(container_snapshot), readonly=set(readonly))
        )
    return AuditEngine(files, namespaces)


class ForwardingTest(unittest.TestCase):
    def test_forwarding_drift_detected_on_host(self):
        engine = make_engine(
            [conf("/etc/sysctl.d/10-hardening.conf", "net.ipv4.ip_forward = 1\n")]
        )
        report = engine.audit()
        drift = report.by_kind(FindingKind.DRIFT)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0].key, "net.ipv4.ip_forward")
        self.assertEqual(drift[0].namespace, "host")
        self.assertEqual(drift[0].details["runtime"], "0")

    def test_forwarding_consistent_when_runtime_matches(self):
        snapshot = dict(HOST_SNAPSHOT)
        snapshot["net.ipv4.ip_forward"] = "1"
        engine = AuditEngine(
            [conf("/etc/sysctl.conf", "net.ipv4.ip_forward = 1\n")],
            [Namespace.host(snapshot)],
        )
        self.assertEqual(engine.audit().by_kind(FindingKind.DRIFT), [])


class RpFilterTest(unittest.TestCase):
    def test_container_rp_filter_differs_from_host(self):
        files = [conf("/etc/sysctl.d/10-base.conf", "net.ipv4.conf.all.rp_filter = 1\n")]
        engine = make_engine(files, container_snapshot=CONTAINER_SNAPSHOT)
        report = engine.audit()
        host_drift = [
            f for f in report.by_kind(FindingKind.DRIFT) if f.namespace == "host"
        ]
        container_drift = [
            f for f in report.by_kind(FindingKind.DRIFT) if f.namespace == "web"
        ]
        self.assertEqual(host_drift, [])  # host runtime already 1
        self.assertEqual(len(container_drift), 1)
        self.assertEqual(container_drift[0].key, "net.ipv4.conf.all.rp_filter")


class IcmpRedirectTest(unittest.TestCase):
    def test_ipv6_counterpart_missing_flags_asymmetry(self):
        files = [
            conf(
                "/etc/sysctl.d/10-hardening.conf",
                "net.ipv4.conf.all.accept_redirects = 0\n",
            )
        ]
        engine = make_engine(files)
        report = engine.audit()
        asym = report.by_kind(FindingKind.IPV6_ASYMMETRY)
        self.assertEqual(len(asym), 1)
        self.assertEqual(asym[0].key, "net.ipv6.conf.all.accept_redirects")

    def test_symmetric_redirect_hardening_is_quiet(self):
        snapshot = dict(HOST_SNAPSHOT)
        snapshot["net.ipv4.conf.all.accept_redirects"] = "0"
        snapshot["net.ipv6.conf.all.accept_redirects"] = "0"
        files = [
            conf(
                "/etc/sysctl.d/10-hardening.conf",
                "net.ipv4.conf.all.accept_redirects = 0\n"
                "net.ipv6.conf.all.accept_redirects = 0\n",
            )
        ]
        engine = AuditEngine(files, [Namespace.host(snapshot)])
        report = engine.audit()
        self.assertEqual(report.by_kind(FindingKind.IPV6_ASYMMETRY), [])
        self.assertEqual(report.by_kind(FindingKind.DRIFT), [])


class ContainerIsolationTest(unittest.TestCase):
    def test_readonly_key_in_container_flagged(self):
        files = [conf("/etc/sysctl.d/10-base.conf", "net.ipv4.ip_forward = 1\n")]
        engine = make_engine(
            files,
            container_snapshot=CONTAINER_SNAPSHOT,
            readonly={"net.ipv4.ip_forward"},
        )
        report = engine.audit()
        readonly = [
            f
            for f in report.by_kind(FindingKind.READONLY_KEY)
            if f.namespace == "web"
        ]
        self.assertEqual(len(readonly), 1)
        self.assertEqual(readonly[0].key, "net.ipv4.ip_forward")
        # Host namespace is unaffected by the container's read-only set.
        host_readonly = [
            f
            for f in report.by_kind(FindingKind.READONLY_KEY)
            if f.namespace == "host"
        ]
        self.assertEqual(host_readonly, [])

    def test_global_keys_resolve_against_host_snapshot(self):
        files = [conf("/etc/sysctl.conf", "kernel.pid_max = 32768\n")]
        engine = make_engine(files, container_snapshot=CONTAINER_SNAPSHOT)
        report = engine.audit()
        drift = report.by_kind(FindingKind.DRIFT)
        # kernel.* is not per-netns: both namespaces see the host value.
        self.assertEqual(len(drift), 2)
        self.assertTrue(all(f.key == "kernel.pid_max" for f in drift))
        self.assertTrue(all(f.details["runtime"] == "4194304" for f in drift))


class MissingAndUnknownKeyTest(unittest.TestCase):
    def test_missing_runtime_value_in_container(self):
        # Container snapshot lacks net.ipv4.icmp_ratelimit (e.g. module
        # restriction); host has it, so this is MISSING_RUNTIME not unknown.
        files = [conf("/etc/sysctl.conf", "net.ipv4.icmp_ratelimit = 500\n")]
        engine = make_engine(files, container_snapshot=CONTAINER_SNAPSHOT)
        report = engine.audit()
        missing = [
            f
            for f in report.by_kind(FindingKind.MISSING_RUNTIME)
            if f.namespace == "web"
        ]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0].key, "net.ipv4.icmp_ratelimit")

    def test_unknown_key_not_present_anywhere(self):
        files = [conf("/etc/sysctl.conf", "net.ipv4.tcp_magic_turbo = 1\n")]
        engine = make_engine(files, container_snapshot=CONTAINER_SNAPSHOT)
        report = engine.audit()
        unknown = report.by_kind(FindingKind.UNKNOWN_KEY)
        self.assertEqual(len(unknown), 2)  # host + container
        self.assertTrue(all(f.key == "net.ipv4.tcp_magic_turbo" for f in unknown))


class UnitDifferenceTest(unittest.TestCase):
    def test_jiffies_unit_produces_caveat_not_drift(self):
        files = [conf("/etc/sysctl.conf", "net.ipv4.icmp_ratelimit = 500\n")]
        engine = make_engine(files)
        report = engine.audit()
        caveats = report.by_kind(FindingKind.UNIT_CAVEAT)
        self.assertEqual(len(caveats), 1)
        self.assertEqual(caveats[0].key, "net.ipv4.icmp_ratelimit")
        self.assertEqual(caveats[0].details["unit"], "jiffies")
        self.assertEqual(report.by_kind(FindingKind.DRIFT), [])

    def test_multivalue_numeric_comparison(self):
        snapshot = dict(HOST_SNAPSHOT)
        snapshot["net.ipv4.tcp_rmem"] = "4096\t87380\t6291456"
        files = [
            conf("/etc/sysctl.conf", "net.ipv4.tcp_rmem = 4096 87380 6291456\n")
        ]
        engine = AuditEngine(files, [Namespace.host(snapshot)])
        self.assertEqual(engine.audit().by_kind(FindingKind.DRIFT), [])


if __name__ == "__main__":
    unittest.main()
