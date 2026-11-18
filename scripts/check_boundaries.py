#!/usr/bin/env python3
"""
Architectural Boundary & Production Safety Linter for korgan.

Validates three strict engineering mandates:
1. Pure Hexagonal Architecture:
   - `src/domain/` and `src/application/` must NEVER import or reference
     transport, database, or cache crates (`axum`, `sqlx`, `redis`, `http::`).
2. Zero-Panic Guarantee:
   - Production code in `src/` must NEVER contain `.unwrap()` or `.expect()`.
3. Zero-Placeholder Policy:
   - Production code in `src/` must NEVER contain `todo!()` or `unimplemented!()`.
"""

import os
import re
import sys

FORBIDDEN_IMPORTS = ["axum", "sqlx", "redis", "http::"]
HEXAGONAL_DIRS = ["src/domain", "src/application"]


def clean_line(line):
    """Removes string literals and line comments to avoid false positive pattern matches."""
    # Remove single-line comments
    comment_idx = line.find("//")
    if comment_idx != -1:
        line = line[:comment_idx]

    # Remove double-quoted string literals (handling basic escapes)
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    # Remove raw string literals r#"..."#
    line = re.sub(r'r#*".*?"#*', '""', line)

    return line.strip()


def scan_file(path, check_fn):
    violations = []
    with open(path, "r", encoding="utf-8") as f:
        in_test_mod = False
        test_brace_depth = 0
        in_block_comment = False

        for idx, raw_line in enumerate(f, 1):
            line = raw_line.strip()

            # Handle block comments
            if in_block_comment:
                end_comment = line.find("*/")
                if end_comment != -1:
                    line = line[end_comment + 2 :].strip()
                    in_block_comment = False
                else:
                    continue

            start_comment = line.find("/*")
            if start_comment != -1:
                end_comment = line.find("*/", start_comment + 2)
                if end_comment != -1:
                    line = (line[:start_comment] + " " + line[end_comment + 2 :]).strip()
                else:
                    line = line[:start_comment].strip()
                    in_block_comment = True

            # Track #[cfg(test)] scope with accurate brace counting
            if "#[cfg(test)]" in line:
                in_test_mod = True
                test_brace_depth = 0

            if in_test_mod:
                test_brace_depth += line.count("{") - line.count("}")
                if test_brace_depth <= 0 and ("{" in line or "}" in line):
                    in_test_mod = False
                continue

            cleaned = clean_line(raw_line)
            if not cleaned:
                continue

            file_violations = check_fn(path, idx, cleaned, raw_line.strip())
            violations.extend(file_violations)

    return violations


def check_hexagonal_boundaries():
    violations = []

    def hex_check(path, idx, cleaned, raw):
        found = []
        for forbidden in FORBIDDEN_IMPORTS:
            # Check for crate references as identifiers or import paths
            pattern = rf"\b{re.escape(forbidden)}"
            if re.search(pattern, cleaned):
                found.append(
                    f"  [HEXAGONAL VIOLATION] {path}:{idx}: references forbidden crate '{forbidden}':\n    {raw}"
                )
        return found

    for directory in HEXAGONAL_DIRS:
        if not os.path.exists(directory):
            continue
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".rs"):
                    path = os.path.join(root, file)
                    violations.extend(scan_file(path, hex_check))

    return violations


def check_zero_panic():
    violations = []

    def panic_check(path, idx, cleaned, raw):
        found = []
        if ".unwrap()" in cleaned:
            found.append(
                f"  [ZERO-PANIC VIOLATION] {path}:{idx}: found forbidden .unwrap():\n    {raw}"
            )
        if ".expect(" in cleaned:
            found.append(
                f"  [ZERO-PANIC VIOLATION] {path}:{idx}: found forbidden .expect():\n    {raw}"
            )
        if "todo!(" in cleaned:
            found.append(
                f"  [PLACEHOLDER VIOLATION] {path}:{idx}: found forbidden todo!():\n    {raw}"
            )
        if "unimplemented!(" in cleaned:
            found.append(
                f"  [PLACEHOLDER VIOLATION] {path}:{idx}: found forbidden unimplemented!():\n    {raw}"
            )
        return found

    for root, _, files in os.walk("src"):
        for file in files:
            if file.endswith(".rs"):
                path = os.path.join(root, file)
                violations.extend(scan_file(path, panic_check))

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
            print("\n[FAIL] Zero-Panic / Placeholder Violations Detected in Production Code:")
            for v in panic_violations:
                print(v)
        print(f"\nTotal violations: {total_violations}. Failing gate.")
        sys.exit(1)

    print("\n[PASS] All Hexagonal Architecture checks passed (0 forbidden imports).")
    print("[PASS] All Zero-Panic & Placeholder checks passed (0 unwrap/expect/todo in production code).")
    print("=" * 70)


if __name__ == "__main__":
    main()
