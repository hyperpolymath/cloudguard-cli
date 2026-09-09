<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Byte Detection Enhancement - Changes Summary

## Overview

This change implements a dedicated leading-BOM detection system and comprehensive test coverage for all byte-level detection rules in the CI pipeline.

## What Was Added

### 1. Dedicated Leading-BOM Check
- **File:** `.github/workflows/dogfood-gate.yml`
- **Change:** Added separate step to detect UTF-8 BOM (EF BB BF) at file start
- **Behavior:** Advisory warning (does NOT block)
- **Reason:** Leading BOMs are conceptually different from mid-file invisible characters

### 2. Comprehensive Test Suite
- **Test Script:** `tests/test_byte_detection.sh` (9 passing tests)
- **Test Fixtures:** `tests/fixtures/byte_detection/` (6 test files)
  - Leading BOM detection
  - Mid-file BOM detection
  - NUL byte detection
  - Backspace character detection
  - Mid-file invisible Unicode detection
  - Clean file validation

### 3. Documentation
- **`docs/byte-detection-rules.md`** - Complete specification of all detection rules
- **`docs/BYTE-DETECTION-IMPLEMENTATION.md`** - Implementation summary
- **`tests/fixtures/byte_detection/README.md`** - Test fixture documentation

### 4. Integration
- **`.gitattributes`** - Preserve test fixtures as binary
- **`Justfile`** - Added `test-byte-detection` recipe

## Detection Rules

The system now has three distinct checks:

### Check 1: Leading BOM (NEW)
- **Pattern:** UTF-8 BOM at file start only
- **Action:** Advisory warning
- **Status:** Does NOT block

### Check 2: C0/NUL Corruption (EXISTING)
- **Pattern:** Control characters and NUL bytes
- **Action:** Error + CI failure
- **Status:** BLOCKS the gate

### Check 3: Mid-file Invisible Unicode (EXISTING)
- **Pattern:** Zero-width spaces, NBSP, etc.
- **Action:** Advisory warning
- **Status:** Does NOT block

## Files Changed

```
Modified:
  .gitattributes                           (+ test fixture preservation)
  .github/workflows/dogfood-gate.yml       (+ leading BOM step, updated summary)
  Justfile                                 (+ test-byte-detection recipe)

Added:
  tests/test_byte_detection.sh             (executable test script)
  tests/fixtures/byte_detection/           (directory)
  tests/fixtures/byte_detection/README.md
  tests/fixtures/byte_detection/with_leading_bom.txt
  tests/fixtures/byte_detection/with_mid_bom.txt
  tests/fixtures/byte_detection/with_nul_byte.txt
  tests/fixtures/byte_detection/with_backspace.txt
  tests/fixtures/byte_detection/with_mid_invisible.txt
  tests/fixtures/byte_detection/clean_file.txt
  docs/byte-detection-rules.md
  docs/BYTE-DETECTION-IMPLEMENTATION.md
  CHANGES-SUMMARY.md                       (this file)
```

## Test Results

All tests pass (9/9):
```
Test Group 1: Leading BOM Detection
  ✓ Leading BOM detected at file start
  ✓ Clean file has no leading BOM
  ✓ Mid-file BOM not detected as leading BOM

Test Group 2: C0 Control Characters (Blocking)
  ✓ NUL byte detected
  ✓ Backspace character detected
  ✓ Clean file has no C0/NUL characters

Test Group 3: Mid-file Invisible Unicode (Advisory)
  ✓ Zero-width space detected
  ✓ BOM detected when in middle of file
  ✓ Clean file has no invisible Unicode
```

## Consistency Verification

✓ CI workflow patterns match test script patterns exactly
✓ Test fixtures excluded from CI scanning
✓ Git attributes preserve test fixtures
✓ Documentation complete and consistent

## How to Test Locally

```bash
# Run the full test suite
./tests/test_byte_detection.sh

# Or using Justfile
just test-byte-detection
```

Expected output: All 9 tests pass.

## CI Behavior

On pull requests and pushes to main/master:
1. Leading BOM check runs first (advisory)
2. Invisible character check runs (includes C0/NUL blocking check)
3. Summary shows counts for each category

**Blocking conditions:**
- C0/NUL corruption found → CI FAILS
- Leading BOM found → Advisory warning only
- Invisible Unicode found → Advisory warning only

## Rationale

### Why Separate Leading-BOM Check?

1. **Conceptually distinct:** File-start BOM is an encoding quirk, not mid-file typography
2. **Different detection:** Simple byte-level pattern vs complex PCRE
3. **Clear reporting:** Separate GitHub annotation makes it obvious what was found
4. **Future extensibility:** Easy to add other BOM types (UTF-16, UTF-32)

### Why Comprehensive Tests?

1. **Confidence:** Ensures patterns actually work as expected
2. **Regression prevention:** Changes to patterns immediately show impact
3. **Documentation:** Test fixtures serve as executable examples
4. **CI-local consistency:** Same patterns used in both contexts

## References

- **Recent commits:**
  - `ad483b0` - fix(ci): make invisible-character PCRE locale-independent
  - `eaa7168` - fix(ci): enforce C0/NUL corruption in-step; warn on invisible Unicode
  - `a69de22` - fix(ci): the invisible-character gate never matched anything

- **Owner ruling (2026-08-28):**
  - C0/NUL corruption → BLOCKS (file corruption)
  - Leading BOM → Advisory (encoding quirk)
  - Invisible Unicode → Advisory (legitimate typography in ~2,100 files)

## Next Steps

After merging:
1. Monitor CI runs for any new BOM detections
2. Consider externalizing patterns to `config.ncl` or `ByteDetector.affine`
3. Add support for UTF-16/UTF-32 BOM detection if needed
4. Consider building standalone `empty-linter` binary

## Questions?

See:
- **Full specification:** `docs/byte-detection-rules.md`
- **Implementation details:** `docs/BYTE-DETECTION-IMPLEMENTATION.md`
- **Test fixtures:** `tests/fixtures/byte_detection/README.md`
