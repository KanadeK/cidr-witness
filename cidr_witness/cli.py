import argparse
import json
import sys

from . import __version__
from .core import InputError, compare


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare effective IPv4/IPv6 allowlist coverage.")
    parser.add_argument("--version", action="version", version=f"cidr-witness {__version__}")
    parser.add_argument("before", help="baseline IP/CIDR file")
    parser.add_argument("after", help="candidate IP/CIDR file")
    policy = parser.add_mutually_exclusive_group()
    policy.add_argument("--fail-on-expansion", action="store_true")
    policy.add_argument("--fail-on-change", action="store_true")
    parser.add_argument("--max-added-v4", type=int)
    parser.add_argument("--max-added-v6", type=int)
    parser.add_argument("--max-entries", type=int, default=100_000)
    parser.add_argument("--max-bytes", type=int, default=8_388_608)
    parser.add_argument("--max-output-cidrs", type=int, default=10_000)
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args(argv)
    try:
        result = compare(
            args.before,
            args.after,
            fail_on_expansion=args.fail_on_expansion,
            fail_on_change=args.fail_on_change,
            max_added_v4=args.max_added_v4,
            max_added_v6=args.max_added_v6,
            max_entries=args.max_entries,
            max_bytes=args.max_bytes,
            max_output_cidrs=args.max_output_cidrs,
        )
    except InputError as error:
        print(f"cidr-witness: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("cidr-witness: cannot read input", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"Equivalent address coverage: {result['equivalent']}")
        for family, details in result["families"].items():
            print(
                f"{family}: +{details['added_addresses']} / -{details['removed_addresses']} addresses"
            )
            for direction in ("added", "removed"):
                for network in details[direction + "_cidrs"]:
                    print(f"  {direction}: {network}")
                witness = details[direction + "_witness"]
                if witness:
                    print(
                        f"  {direction} witness: {witness['address']} in {witness['source']} "
                        f"lines {witness['source_lines']}"
                    )
        print(f"Policy gate: {'PASS' if result['ok'] else 'FAIL'}")
        for finding in result["findings"]:
            print(json.dumps(finding, sort_keys=True))
    return 0 if result["ok"] else 1
