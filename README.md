# linux-sysctl-hardening-auditor
Python Linux sysctl 加固审计库，处理配置优先级、网络参数、覆盖关系和基线差异

## 功能

- 按 systemd-sysctl 语义合并 `/usr/lib/sysctl.d`、`/run/sysctl.d`、`/etc/sysctl.d`
  与 `/etc/sysctl.conf`：同名文件掩码、按文件名排序、后加载覆盖先加载，
  并记录每个 key 的最终来源（文件:行号）与完整覆盖链。
- key 匹配同时接受点号路径（`net.ipv4.conf.all.rp_filter`）与嵌套目录形式
  （`net/ipv4/conf/all/rp_filter`）；对含点号的目录组件（如 VLAN 接口
  `eth0.100`）用快照 trie 做最长组件匹配。
- 分别计算 host 与每个容器网络 namespace 的最终值：`net.*` 按各 namespace
  快照解析，其余 key 回落到 host 快照。
- 识别：sysctl.d drop-in 掩码、后加载覆盖、未知 key、只读 namespace、
  运行值与配置漂移、IPv4/IPv6 同名参数不对称加固、单位差异
  （jiffies 等 HZ 相关单位只给 caveat 不下漂移结论）、缺失运行时值。

## 用法

```python
from sysctl_audit import AuditEngine, Namespace, SysctlConfigFile

files = [
    SysctlConfigFile("/usr/lib/sysctl.d/50-docker.conf", "net.ipv4.ip_forward = 1\n"),
    SysctlConfigFile("/etc/sysctl.d/10-hardening.conf", "net.ipv4.conf.all.rp_filter = 1\n"),
    SysctlConfigFile("/etc/sysctl.conf", "net.ipv4.ip_forward = 0\n"),
]
host = Namespace.host({"net.ipv4.ip_forward": "1", ...})
web = Namespace.netns("web", {...}, readonly={"net.ipv4.ip_forward"})

report = AuditEngine(files, [host, web]).audit()
for finding in report.findings:
    print(finding.kind.value, finding.namespace, finding.key, finding.message)
```

## 测试

```
python -m unittest discover -s tests
```

## 无法从文件判断的内核特例

以下行为取决于内核运行时状态，静态审计只能标注、无法定论：

- **`all` / `default` / 具体接口的合并语义因 key 而异**：`forwarding`、
  `accept_redirects` 生效值是 `all` 与接口值的 AND；`rp_filter`、
  `arp_ignore` 等取 max。仅看配置文件无法推出某接口的有效值。
- **`default` 只影响之后创建的接口**：已存在的接口保持旧值，重启网络
  或新建 veth 前后快照会不同。
- **IPv6 forwarding 是 per-interface**：`net.ipv6.conf.all.forwarding`
  与 IPv4 的全局 `ip_forward` 语义不同；写 forwarding=1 还会联动
  关闭该接口的 `accept_ra` 自动配置。
- **模块未加载时 key 不存在**：`bridge-nf-*`、`conntrack` 等参数只在
  对应模块加载后出现；配置里的"未知 key"可能运行时完全合法。
- **jiffies / HZ 相关单位**：如 `net.ipv4.icmp_ratelimit`，其时间含义
  取决于内核 CONFIG_HZ，文件中的数值无法换算成秒。
- **user namespace 容器中的写权限**：非特权容器里部分 `net.*` key 只读
  或写时被静默忽略，是否如此取决于运行时的 userns/sysctl 许可表，
  配置文件本身看不出来。
- **`-` 前缀行**：systemd-sysctl 对失败静默忽略，文件中存在不等于已生效。
