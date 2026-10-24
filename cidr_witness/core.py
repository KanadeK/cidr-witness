"""Effective allowlist set differences using intervals, never address expansion."""

import ipaddress
from dataclasses import dataclass
from pathlib import Path


class InputError(ValueError):
    """Cannot produce a complete, trustworthy comparison."""


@dataclass(frozen=True)
class Entry:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    line: int


def _read(path, side, max_entries, max_bytes):
    entries = []
    consumed = line = 0
    with Path(path).open("rb") as stream:
        while True:
            raw = stream.readline(min(4097, max_bytes - consumed + 1))
            if not raw:
                break
            consumed += len(raw)
            line += 1
            if consumed > max_bytes:
                raise InputError(f"{side}: input byte limit exceeded")
            if len(raw) > 4096:
                raise InputError(f"{side}: line {line} exceeds 4096 bytes")
            try:
                text = raw.decode("utf-8-sig" if line == 1 else "utf-8")
            except UnicodeDecodeError as error:
                raise InputError(f"{side}: line {line} is not valid UTF-8") from error
            token = text.split("#", 1)[0].strip()
            if not token:
                continue
            if len(entries) >= max_entries:
                raise InputError(f"{side}: network entry limit exceeded")
            _, slash, prefix = token.partition("/")
            if "%" in token or (
                slash
                and (not prefix.isascii() or not prefix.isdigit() or str(int(prefix)) != prefix)
            ):
                raise InputError(f"{side}: line {line} requires an IP or numeric-prefix CIDR")
            try:
                network = ipaddress.ip_network(token, strict=True)
            except ValueError as error:
                raise InputError(f"{side}: line {line} is invalid or has host bits set") from error
            entries.append(Entry(network, line))
    return entries


def _union(entries, version):
    ranges = sorted(
        (int(entry.network.network_address), int(entry.network.broadcast_address))
        for entry in entries
        if entry.network.version == version
    )
    output = []
    for start, end in ranges:
        if output and start <= output[-1][1] + 1:
            output[-1] = (output[-1][0], max(output[-1][1], end))
        else:
            output.append((start, end))
    return output


def _subtract(left, right):
    """A minus B for sorted, disjoint, inclusive interval unions."""
    output = []
    index = 0
    for start, end in left:
        while index < len(right) and right[index][1] < start:
            index += 1
        cursor = start
        other = index
        while other < len(right) and right[other][0] <= end:
            cut_start, cut_end = right[other]
            if cursor < cut_start:
                output.append((cursor, cut_start - 1))
            cursor = max(cursor, cut_end + 1)
            if cursor > end:
                break
            other += 1
        if cursor <= end:
            output.append((cursor, end))
        index = other
    return output


def _size(ranges):
    return sum(end - start + 1 for start, end in ranges)


def _cidrs(ranges, version, remaining):
    address = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    output = []
    for start, end in ranges:
        for network in ipaddress.summarize_address_range(address(start), address(end)):
            if len(output) >= remaining:
                raise InputError("output CIDR limit exceeded; comparison is not emitted")
            output.append(str(network))
    return output


def _witness(ranges, entries, version, source):
    if not ranges:
        return None
    address = (ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address)(ranges[0][0])
    lines = []
    total = 0
    for entry in entries:
        if entry.network.version == version and address in entry.network:
            total += 1
            if len(lines) < 20:
                lines.append(entry.line)
    return {
        "address": str(address),
        "source": source,
        "source_lines": lines,
        "matching_source_line_count": total,
        "source_lines_truncated": total > len(lines),
    }


def compare(
    before,
    after,
    *,
    fail_on_expansion=False,
    fail_on_change=False,
    max_added_v4=None,
    max_added_v6=None,
    max_entries=100_000,
    max_bytes=8_388_608,
    max_output_cidrs=10_000,
):
    """Compare unions of IPs/CIDRs. This is not an ordered ACL evaluator.

    Address totals are decimal strings to preserve IPv6 /0 counts in JSON readers.
    All addresses, including subnet network/broadcast addresses, are counted.
    """
    for limit in (max_entries, max_bytes, max_output_cidrs):
        if type(limit) is not int or limit < 1:
            raise InputError("input and output limits must be positive integers")
    for budget in (max_added_v4, max_added_v6):
        if budget is not None and (type(budget) is not int or budget < 0):
            raise InputError("address budgets must be nonnegative integers")
    if type(fail_on_expansion) is not bool or type(fail_on_change) is not bool:
        raise InputError("policy switches must be booleans")
    old_entries = _read(before, "before", max_entries, max_bytes)
    new_entries = _read(after, "after", max_entries, max_bytes)
    families = {}
    findings = []
    emitted = 0
    equivalent = True
    for version, family, budget in ((4, "ipv4", max_added_v4), (6, "ipv6", max_added_v6)):
        old = _union(old_entries, version)
        new = _union(new_entries, version)
        added = _subtract(new, old)
        removed = _subtract(old, new)
        added_size = _size(added)
        changed = bool(added or removed)
        equivalent &= not changed
        added_cidrs = _cidrs(added, version, max_output_cidrs - emitted)
        emitted += len(added_cidrs)
        removed_cidrs = _cidrs(removed, version, max_output_cidrs - emitted)
        emitted += len(removed_cidrs)
        families[family] = {
            "before_addresses": str(_size(old)),
            "after_addresses": str(_size(new)),
            "added_addresses": str(added_size),
            "removed_addresses": str(_size(removed)),
            "added_cidrs": added_cidrs,
            "removed_cidrs": removed_cidrs,
            "added_witness": _witness(added, new_entries, version, "after"),
            "removed_witness": _witness(removed, old_entries, version, "before"),
        }
        if added_size and fail_on_expansion:
            findings.append({"code": "expansion_detected", "family": family})
        if changed and fail_on_change:
            findings.append({"code": "change_detected", "family": family})
        if budget is not None and added_size > budget:
            findings.append({"code": "added_address_budget_exceeded", "family": family})
    return {
        "schema_version": 1,
        "ok": not findings,
        "equivalent": equivalent,
        "inputs": {"before_entries": len(old_entries), "after_entries": len(new_entries)},
        "families": families,
        "policy": {
            "fail_on_expansion": fail_on_expansion,
            "fail_on_change": fail_on_change,
            "max_added_v4": None if max_added_v4 is None else str(max_added_v4),
            "max_added_v6": None if max_added_v6 is None else str(max_added_v6),
        },
        "findings": findings,
    }
