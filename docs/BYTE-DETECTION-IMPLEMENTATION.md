<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Byte Detection Implementation Summary

This document summarizes the implementation of the dedicated leading-BOM detection and comprehensive byte-level character checking system.

## Implementation Overview

The byte detection system has been enhanced with the following changes:

### 1. Separate Leading-BOM Check

**Location:** `.github/workflows/dogfood-gate.yml` (new step in `empty-lint` job)

**What Changed:**
- Added a dedicated step to detect UTF-8 BOM (EF BB BF) specifically at file start
- Uses simple byte-level pattern matching: `^` followed by BOM bytes
- Runs BEFORE the general invisible character check
- Produces advisory warnings (does NOT block)

**Rationale:**
- Leading BOM is conceptually different from mid-file invisible characters
- Indicates encoding quirks (Windows/editor issues) rather than typography
- Deserves separate detection and reporting

### 2. Enhanced Invisible Character Detection

**Location:** `.github/workflows/dogfood-gate.yml` (updated existing step)

**What Changed:**
- Updated documentation to clarify this checks mid-file invisible chars
- Added note that leading BOM check is separate
- Excluded `tests/fixtures/` from scanning
- Maintained existing three-tier enforcement:
  - **Blocking:** C0/NUL corruption
  - **Advisory:** Mid-file invisible Unicode
  - **Advisory:** Leading BOM (separate step)

### 3. Comprehensive Test Suite

**Location:** `tests/test_byte_detection.sh` and `tests/fixtures/byte_detection/`

**What Was Created:**

#### Test Fixtures
All fixtures stored in `tests/fixtures/byte_detection/`:

1. **`with_leading_bom.txt`** - UTF-8 BOM at file start
2. **`with_mid_bom.txt`** - BOM in middle of file (not at start)
3. **`with_nul_byte.txt`** - Contains NUL byte (\x00)
4. **`with_backspace.txt`** - Contains backspace (\x08)
5. **`with_mid_invisible.txt`** - Contains zero-width space
6. **`clean_file.txt`** - Only normal whitespace

#### Test Script
- **Location:** `tests/test_byte_detection.sh`
- **Purpose:** Validate all detection patterns work correctly
- **Coverage:**
  - Leading BOM detection (3 tests)
  - C0/NUL control character detection (3 tests)
  - Mid-file invisible Unicode detection (3 tests)
  - Clean file validation (implicit in all groups)

**Results:** All 9 tests pass ✓

### 4. Documentation

Three documentation files were created:

1. **`tests/fixtures/byte_detection/README.md`**
   - Explains each test fixture
   - Documents expected behavior
   - Lists detection rules
   - References recent commits

2. **`docs/byte-detection-rules.md`**
   - Complete specification of all detection rules
   - Pattern definitions and rationales
   - CI integration details
   - Historical context and owner rulings

3. **`docs/BYTE-DETECTION-IMPLEMENTATION.md`** (this file)
   - Implementation summary
   - Changes made
   - Integration points

### 5. Git Configuration

**Location:** `.gitattributes`

**What Changed:**
- Added entry to preserve test fixtures as binary
- Prevents Git from normalizing the special bytes in test files

```gitattributes
tests/fixtures/byte_detection/*.txt binary
```

### 6. Justfile Integration

**Location:** `Justfile`

**What Changed:**
- Added `test-byte-detection` recipe for easy local testing

```bash
just test-byte-detection
```

## Detection Rules Summary

### Rule 1: Leading BOM (Advisory)
- **Pattern:** `^[EF BB BF]`
- **Action:** Warning annotation
- **Status:** Advisory (does NOT block)

### Rule 2: C0/NUL Corruption (Blocking)
- **Pattern:** `[\x00-\x08\x0B\x0C\x0E-\x1F]`
- **Action:** Error annotation + CI failure
- **Status:** BLOCKS the gate

### Rule 3: Mid-file Invisible Unicode (Advisory)
- **Pattern:** `(*UTF)[\x00-\x08\x0B\x0C\x0E-\x1F\x{a0}\x{ad}\x{200b}-\x{200f}\x{202a}-\x{202f}\x{2060}\x{2066}-\x{2069}\x{feff}]`
- **Action:** Warning annotation
- **Status:** Advisory (does NOT block)

## CI Workflow Structure

```
empty-lint job:
  1. Checkout
  2. Scan for leading BOM (new step)
     - Detects UTF-8 BOM at file start only
     - Advisory warnings
  3. Scan for invisible characters (updated step)
     - Detects C0/NUL (blocking)
     - Detects mid-file invisible Unicode (advisory)
  4. Write summary (updated step)
     - Shows BOM count
     - Shows blocking issues
     - Shows advisory issues
```

## Testing

### Local Testing

Run the full test suite:
```bash
./tests/test_byte_detection.sh
```

Or using Justfile:
```bash
just test-byte-detection
```

### Expected Output
```
═══════════════════════════════════════════════════
  Byte Detection Test Suite
═══════════════════════════════════════════════════

Test Group 1: Leading BOM Detection
───────────────────────────────────
  [PASS] Leading BOM detected at file start
  [PASS] Clean file has no leading BOM
  [PASS] Mid-file BOM not detected as leading BOM

Test Group 2: C0 Control Characters (Blocking)
──────────────────────────────────────────────
  [PASS] NUL byte detected
  [PASS] Backspace character detected
  [PASS] Clean file has no C0/NUL characters

Test Group 3: Mid-file Invisible Unicode (Advisory)
────────────────────────────────────────────────────
  [PASS] Zero-width space detected
  [PASS] BOM detected when in middle of file
  [PASS] Clean file has no invisible Unicode

Test Group 4: Clean File Validation
────────────────────────────────────
  [INFO] Clean file should pass all negative tests
  [INFO] Already verified in groups above

═══════════════════════════════════════════════════
  Results: 9 passed, 0 failed
═══════════════════════════════════════════════════
```

### CI Testing

The workflow will automatically run on:
- Pull requests (all branches)
- Pushes to main/master

View results in GitHub Actions → Dogfood Gate → empty-lint job

## File Extensions Checked

All checks apply to these file types:
- Source: `.rs`, `.ex`, `.exs`, `.res`, `.idr`, `.zig`, `.v`, `.jl`, `.gleam`, `.hs`, `.ml`
- Scripts: `.sh`
- Web: `.js`, `.ts`
- Data: `.json`, `.toml`, `.yml`, `.yaml`
- Docs: `.md`, `.adoc`

## Exclusions

These paths are excluded from all scans:
- `.git/`
- `node_modules/`
- `.deno/`
- `target/`
- `_build/`
- `deps/`
- `external_corpora/`
- `.lake/`
- `tests/fixtures/` (test files themselves)

## Consistency Between CI and Tests

The test suite uses the EXACT same patterns as the CI workflow:

| Check | CI Pattern | Test Pattern | Match |
|-------|-----------|--------------|-------|
| Leading BOM | `^[EF BB BF]` | `^[EF BB BF]` | ✓ |
| C0/NUL | `[\x00-\x08\x0B\x0C\x0E-\x1F]` | `[\x00-\x08\x0B\x0C\x0E-\x1F]` | ✓ |
| Mid-invisible | `(*UTF)[...]` | `(*UTF)[...]` | ✓ |

This ensures that local testing accurately reflects CI behavior.

## Historical Context

### Recent Commits
- `ad483b0` - fix(ci): make invisible-character PCRE locale-independent
- `eaa7168` - fix(ci): enforce C0/NUL corruption in-step; warn on invisible Unicode
- `a69de22` - fix(ci): the invisible-character gate never matched anything

### Owner Ruling (2026-08-28)
Three-tier enforcement model:
1. **C0/NUL corruption** → BLOCKS (file corruption)
2. **Leading BOM** → Advisory (encoding quirk)
3. **Invisible Unicode** → Advisory (legitimate typography in ~2,100 files)

## Future Enhancements

### Potential Next Steps

1. **Configuration File**
   - Externalize patterns to `config.ncl` or `ByteDetector.affine`
   - Allow per-repo customization
   - Version pattern definitions

2. **Additional BOM Types**
   - UTF-16 BE: FE FF
   - UTF-16 LE: FF FE
   - UTF-32 BE: 00 00 FE FF
   - UTF-32 LE: FF FE 00 00

3. **Homoglyph Detection**
   - Confusable characters (e.g., Cyrillic 'о' vs Latin 'o')
   - RTL override attacks
   - Emoji modifiers in unexpected contexts

4. **Compiled Linter**
   - Build standalone `empty-linter` binary
   - Distribute via package managers
   - Pre-commit hook integration

## Maintenance

### Updating Patterns

If patterns need to change:

1. Update workflow: `.github/workflows/dogfood-gate.yml`
2. Update test script: `tests/test_byte_detection.sh`
3. Update documentation: `docs/byte-detection-rules.md`
4. Run tests to validate: `just test-byte-detection`
5. Update this file with rationale

### Adding New Test Cases

1. Create fixture: `tests/fixtures/byte_detection/new_test.txt`
2. Add test case: `tests/test_byte_detection.sh`
3. Update fixture README: `tests/fixtures/byte_detection/README.md`
4. Ensure `.gitattributes` covers the new fixture
5. Run tests to validate

## Verification Checklist

- [x] Leading BOM detection implemented
- [x] Mid-file invisible character detection working
- [x] NUL byte detection working
- [x] Backspace character detection working
- [x] Clean files NOT flagged
- [x] Test fixtures created (6 files)
- [x] Test script created and passing (9/9 tests)
- [x] Documentation complete (3 files)
- [x] Git attributes configured
- [x] Justfile recipe added
- [x] CI workflow updated
- [x] Patterns consistent between CI and tests
- [x] Test fixtures excluded from scanning

## References

- Workflow: `.github/workflows/dogfood-gate.yml`
- Test Suite: `tests/test_byte_detection.sh`
- Test Fixtures: `tests/fixtures/byte_detection/`
- Rules Doc: `docs/byte-detection-rules.md`
- Git Config: `.gitattributes`
- Build System: `Justfile`
