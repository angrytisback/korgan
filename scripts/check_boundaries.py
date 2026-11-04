#!/usr/bin/env python3
"""
Architectural Boundary & Production Safety Linter for korgan.

Validates two strict engineering mandates:
1. Pure Hexagonal Architecture:
   - `src/domain/` and `src/application/` must NEVER import or reference
     transport, database, or cache crates (`axum`, `sqlx`, `redis`, `http::`).
2. Zero-Panic Guarantee:
   - Production code in `src/` must NEVER contain `.unwrap()` or `.expect()`.
"""

import os
import sys

FORBIDDEN_IMPORTS = ["axum", "sqlx", "redis", "http::"]
HEXAGONAL_DIRS = ["src/domain", "src/application"]

def check_hexagonal_boundaries():
    violations = []
    for directory in HEXAGONAL_DIRS:
        if not os.path.exists(directory):
            continue
        for root, _, files in os.walk(directory):
            for file in files:
                if not file.endswith(".rs"):
                    continue
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    in_test_mod = False
                    for idx, line in enumerate(f, 1):
                        trimmed = line.strip()
                        if trimmed.startswith("#[cfg(test)]"):
                            in_test_mod = True
                        if in_test_mod:
                            continue
                        if trimmed.startswith("//") or trimmed.startswith("/*") or trimmed.startswith("*"):
                            continue
                        for forbidden in FORBIDDEN_IMPORTS:
                            if forbidden in line:
                                violations.append(
                                    f"  [HEXAGONAL VIOLATION] {path}:{idx}: references forbidden crate '{forbidden}':\n    {trimmed}"
                                )
    return violations

def check_zero_panic():
    violations = []
    for root, _, files in os.walk("src"):
        for file in files:
            if not file.endswith(".rs"):
                continue
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8") as f:
                in_test_mod = False
                for idx, line in enumerate(f, 1):
                    trimmed = line.strip()
                    if trimmed.startswith("#[cfg(test)]"):
                        in_test_mod = True
                    if in_test_mod:
                        continue
                    if trimmed.startswith("//") or trimmed.startswith("/*") or trimmed.startswith("*"):
                        continue
                    if ".unwrap()" in line:
                        violations.append(
                            f"  [ZERO-PANIC VIOLATION] {path}:{idx}: found forbidden .unwrap():\n    {trimmed}"
                        )
                    if ".expect(" in line:
                        violations.append(
                            f"  [ZERO-PANIC VIOLATION] {path}:{idx}: found forbidden .expect():\n    {trimmed}"
                        )
    return violations

def main():
    print("=" * 70)
    print("Running korgan Architectural Boundary & Zero-Panic Checks")
    print("=" * 70)

    hex_violations = check_hexagonal_boundaries()
    panic_violations = check_zero_panic()

    total_violations = len(hex_violations) + len(panic_violations)

    if total_violations > 0:
        if hex_violations:
            print("\n[FAIL] Hexagonal Architecture Violations Detected:")
            for v in hex_violations:
                print(v)
        if panic_violations:
            print("\n[FAIL] Zero-Panic Violations Detected in Production Code:")
            for v in panic_violations:
                print(v)
        print(f"\nTotal violations: {total_violations}. Failing gate.")
        sys.exit(1)

    print("\n[PASS] All Hexagonal Architecture checks passed (0 forbidden imports).")
    print("[PASS] All Zero-Panic checks passed (0 unwrap/expect in production code).")
    print("=" * 70)

if __name__ == "__main__":
    main()
