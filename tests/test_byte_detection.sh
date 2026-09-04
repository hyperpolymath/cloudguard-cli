#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
#
# test_byte_detection.sh — Test suite for byte-level detection of BOMs and invisible characters
#
# Tests:
# 1. Leading BOM detection (EF BB BF at file start)
# 2. Mid-file invisible character detection (zero-width spaces, etc.)
# 3. NUL byte detection
# 4. Backspace character detection
# 5. Clean files should NOT be flagged

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="$SCRIPT_DIR/fixtures/byte_detection"

echo "═══════════════════════════════════════════════════"
echo "  Byte Detection Test Suite"
echo "═══════════════════════════════════════════════════"
echo ""

PASS=0
FAIL=0

# Test helper functions
test_should_match() {
    local desc="$1"
    local file="$2"
    local pattern="$3"

    if grep -qaPl "$pattern" "$file" 2>/dev/null; then
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $desc — expected match but got none"
        FAIL=$((FAIL + 1))
    fi
}

test_should_not_match() {
    local desc="$1"
    local file="$2"
    local pattern="$3"

    if grep -qaPl "$pattern" "$file" 2>/dev/null; then
        echo "  [FAIL] $desc — expected no match but got one"
        FAIL=$((FAIL + 1))
    else
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    fi
}

# Leading BOM detection pattern (specifically at start of file)
# UTF-8 BOM: EF BB BF
LEADING_BOM_PATTERN='^'"$(printf '\xef\xbb\xbf')"

# C0 control characters and NUL (blocking)
C0_NUL_PATTERN='[\x00-\x08\x0B\x0C\x0E-\x1F]'

# Mid-file invisible Unicode (advisory)
# Includes: NBSP, soft hyphen, zero-width spaces, zero-width joiners, BOM when not at start, etc.
# Note: Using the same PCRE pattern as the workflow (with (*UTF) directive)
MID_INVISIBLE_PATTERN='(*UTF)[\x00-\x08\x0B\x0C\x0E-\x1F\x{a0}\x{ad}\x{200b}-\x{200f}\x{202a}-\x{202f}\x{2060}\x{2066}-\x{2069}\x{feff}]'

echo "Test Group 1: Leading BOM Detection"
echo "───────────────────────────────────"
test_should_match \
    "Leading BOM detected at file start" \
    "$FIXTURES_DIR/with_leading_bom.txt" \
    "$LEADING_BOM_PATTERN"

test_should_not_match \
    "Clean file has no leading BOM" \
    "$FIXTURES_DIR/clean_file.txt" \
    "$LEADING_BOM_PATTERN"

test_should_not_match \
    "Mid-file BOM not detected as leading BOM" \
    "$FIXTURES_DIR/with_mid_bom.txt" \
    "$LEADING_BOM_PATTERN"

echo ""
echo "Test Group 2: C0 Control Characters (Blocking)"
echo "──────────────────────────────────────────────"
test_should_match \
    "NUL byte detected" \
    "$FIXTURES_DIR/with_nul_byte.txt" \
    "$C0_NUL_PATTERN"

test_should_match \
    "Backspace character detected" \
    "$FIXTURES_DIR/with_backspace.txt" \
    "$C0_NUL_PATTERN"

test_should_not_match \
    "Clean file has no C0/NUL characters" \
    "$FIXTURES_DIR/clean_file.txt" \
    "$C0_NUL_PATTERN"

echo ""
echo "Test Group 3: Mid-file Invisible Unicode (Advisory)"
echo "────────────────────────────────────────────────────"

# For PCRE patterns with Unicode, we need the -P flag
test_should_match_pcre() {
    local desc="$1"
    local file="$2"
    local pattern="$3"

    if grep -qaPl -P "$pattern" "$file" 2>/dev/null; then
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $desc — expected match but got none"
        FAIL=$((FAIL + 1))
    fi
}

test_should_not_match_pcre() {
    local desc="$1"
    local file="$2"
    local pattern="$3"

    if grep -qaPl -P "$pattern" "$file" 2>/dev/null; then
        echo "  [FAIL] $desc — expected no match but got one"
        FAIL=$((FAIL + 1))
    else
        echo "  [PASS] $desc"
        PASS=$((PASS + 1))
    fi
}

test_should_match_pcre \
    "Zero-width space detected" \
    "$FIXTURES_DIR/with_mid_invisible.txt" \
    "$MID_INVISIBLE_PATTERN"

test_should_match_pcre \
    "BOM detected when in middle of file" \
    "$FIXTURES_DIR/with_mid_bom.txt" \
    "$MID_INVISIBLE_PATTERN"

test_should_not_match_pcre \
    "Clean file has no invisible Unicode" \
    "$FIXTURES_DIR/clean_file.txt" \
    "$MID_INVISIBLE_PATTERN"

echo ""
echo "Test Group 4: Clean File Validation"
echo "────────────────────────────────────"
echo "  [INFO] Clean file should pass all negative tests"
echo "  [INFO] Already verified in groups above"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi

exit 0
