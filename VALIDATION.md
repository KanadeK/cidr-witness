# v0.1.0 validation

Executed locally on 2026-10-24, Windows, Python 3.13.16:

- `python -m unittest discover -s tests -v`: 12 tests passed. This includes 240
  seeded IPv4/IPv6 comparisons against independent small-address set enumeration.
- Ruff 0.14.1 lint and format checks: passed.
- `python -m build`: source distribution and wheel built successfully.
- Fresh virtual environment: wheel installed offline without dependencies,
  module invoked outside the checkout in isolated mode, equivalent and expansion
  example workflows passed their expected exit codes, `pip check` passed, and
  uninstall removed the package.
- Synthetic scale check: 10,000 before + 10,000 after disjoint IPv6 singleton
  entries, 20,000 output CIDRs, exact 10,000 added/10,000 removed address counts,
  0.183 seconds locally. This is one experiment, not a performance guarantee.

Boundary coverage: IPv6 /0 yields exactly 2^128 addresses as a decimal string;
first/last-address exclusions, IPv4 /0, mapped IPv6 separation, empty lists,
equivalent split/merge/overlap, source-line provenance/truncation, exact budgets,
malformed/host-bit CIDRs, UTF-8/BOM, byte/line/entry/output bounds, unchanged
source hashes and CLI exits. Core implementation never enumerates address space.

Self-review checked inclusive interval endpoints, subtraction progress, union
adjacency, count overflow avoidance, family separation, witness membership,
strict host-bit rejection and policy/default semantics. Address-set comparison
does not model ordered ACLs, deny rules, ports, protocols or runtime reachability;
these limits and report privacy are explicit in the README.

Remote results are available in [GitHub Actions](https://github.com/KanadeK/cidr-witness/actions).
The workflow tests/builds only and cannot commit repository contents.
