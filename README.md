# cidr-witness

Review what a CIDR allowlist change **actually allows**. Text diffs are noisy
when networks are split, merged or overlap. cidr-witness compares the effective
IPv4 and IPv6 address sets and reports exact additions/removals, minimal CIDRs,
and a witness address traced to source lines.

Offline Python 3.11+ CLI, no runtime dependencies. Uses interval arithmetic;
even IPv6 `/0` is handled without enumerating its addresses. It opens two local
files read-only and does not contact or configure a firewall.

## Install and reproduce

```sh
git clone https://github.com/KanadeK/cidr-witness.git
cd cidr-witness
python -m venv .venv
```

Activate with `source .venv/bin/activate` (macOS/Linux) or
`.venv\Scripts\Activate.ps1` (PowerShell), then:

```sh
python -m pip install .
cidr-witness examples/before.txt examples/equivalent.txt --fail-on-change
cidr-witness examples/before.txt examples/expanded.txt --fail-on-expansion --format json
```

The first command passes: the candidate IPv4 `/26` entries cover exactly the
original `/25`, and the expanded IPv6 spelling represents the same range.
The second exits 1: it adds `192.0.2.128/25` (128 IPv4 addresses) and
`2001:db8::2/127` (two IPv6 addresses). Each family includes an added-address
witness and the candidate line that allows it.

`python -m cidr_witness ...` works from a checkout. Release wheels can be
installed directly; the package is not advertised as available on PyPI.
Uninstall with `python -m pip uninstall cidr-witness`. The tool creates no cache
or configuration; clean up only reports you explicitly redirected to a file.

## Input contract

One literal IP address or canonical network CIDR per line. IPv4 and IPv6 may be
mixed. Blank lines, surrounding whitespace and `#` comments are allowed. UTF-8
with an optional initial BOM and LF/CRLF line endings are supported. Bare IPs
mean `/32` or `/128`. Numeric prefixes only; dotted netmasks, zone IDs, hostnames,
negations and CIDRs with host bits set are rejected rather than silently repaired.

```text
# Synthetic documentation ranges
192.0.2.0/24
2001:db8::/48
198.51.100.17  # a single address
```

Each file means an **unordered union of allowed addresses for the same context**.
Order, duplicate entries and overlapping networks do not affect coverage. Counts
include network and broadcast addresses, not just usable host addresses. Empty
files represent empty sets. IPv4-mapped IPv6 addresses stay in the IPv6 family;
they are not treated as IPv4 aliases.

## Policy gates and reports

By default this is a comparison: changes are reported and a complete valid
comparison exits 0. **`ok` means the selected policy passed; `equivalent` means
coverage is unchanged.** To block expansions in CI, select a gate explicitly:

```sh
cidr-witness old.txt new.txt --fail-on-expansion
cidr-witness old.txt new.txt --fail-on-change
cidr-witness old.txt new.txt --max-added-v4 256 --max-added-v6 0 --format json
```

The first two gates are mutually exclusive. Per-family address budgets may be
combined with either gate. Budget equality passes; zero permits no new addresses.
IPv6 budgets count individual addresses, so a new `/64` adds 2^64 addresses.

- **0**: complete, valid comparison and selected policy passes.
- **1**: complete comparison with an expansion/change/budget policy violation.
- **2**: invalid/unreadable input or a resource/output limit. No partial report
  is emitted on exit 2.

JSON schema version 1 includes `families.ipv4` and `families.ipv6`, with
`before_addresses`, `after_addresses`, `added_addresses`, `removed_addresses`,
`added_cidrs`, `removed_cidrs`, `added_witness`, and `removed_witness`.
**Address counts and budgets are decimal strings**, preserving all 128 bits in
JavaScript and other JSON readers. Entry counts and source line numbers are
ordinary integers. CIDRs are canonical and minimal for each effective delta.
The witness is the first address in that family's delta; it is one concrete
example, not a sample of every changed CIDR. Up to 20 containing source lines
are listed in original order, with total count and a truncation flag. Removed
witnesses refer to `before`; added witnesses refer to `after`.

Defaults per input: `--max-entries 100000`, `--max-bytes 8388608` (8 MiB),
4,096 bytes per physical line including its terminator. The combined added and
removed report is bounded by `--max-output-cidrs 10000`. Increase bounds
deliberately for larger trusted files. Size checks use at most one lookahead
byte. Work scales with the input/difference intervals, not the number of IPs;
input bounds are not whole-process memory or CPU quotas.

```python
from cidr_witness.core import compare

report = compare("old.txt", "new.txt", fail_on_expansion=True)
if not report["ok"]:
    print(report["findings"])
```

## Scope and alternatives

This is address-set evidence, not a full firewall-policy evaluator. Ports,
protocols, rule order, deny rules, security-group combinations, routing, DNS,
identity, runtime reachability and device-specific IPv4/IPv6 alias behavior
are outside scope. Compare lists governing the same policy context. A passing
comparison is not a declaration that the rules are secure or correctly deployed.

Use [netaddr.IPSet](https://github.com/netaddr/netaddr) when integrating set
operations into Python, or [cidr-diff](https://github.com/strizhechenko/cidr-diff)
for subtraction pipelines. cidr-witness adds a complete before/after review,
both families/directions, exact JSON counts, source witnesses, and explicit CI
gates in a dependency-free package. It does not invent network set arithmetic.

Reports intentionally include network ranges and witness addresses. These may
reveal private infrastructure; review them before sharing. No network access,
telemetry or source-file mutation. Files must remain stable while read; the two
files are not locked into an atomic snapshot.

## Verify

```sh
python -m unittest discover -s tests -v
python -m pip install ruff==0.14.1 build==1.3.0
python -m ruff check .
python -m ruff format --check .
python -m build
```

The tests include 240 seeded comparisons with an independent enumerated-set
oracle for small IPv4/IPv6 spaces, whole-space boundaries, split/merge equivalence,
witness provenance, resource limits, unchanged input hashes and CLI gates.
See [VALIDATION.md](VALIDATION.md). MIT; [contributing](CONTRIBUTING.md),
[security](SECURITY.md), [third-party notice](THIRD_PARTY.md).

## 中文说明

本工具比较两个 IP/CIDR 白名单的实际地址覆盖范围，识别拆分、合并和重叠产生的
文本噪声，输出真正新增/移除的网段、精确地址数量，以及可追溯到源文件行号的
地址见证。支持 IPv4、IPv6 和混合列表；计数使用十进制字符串，避免 JSON 数字
精度损失。默认只比较，CI 阻止扩权请加 `--fail-on-expansion`；`ok` 不代表覆盖不变，
应查看 `equivalent`。不解析端口、协议、拒绝规则或规则顺序，不连接/修改防火墙。
报告包含地址信息，分享前请确认是否敏感。
