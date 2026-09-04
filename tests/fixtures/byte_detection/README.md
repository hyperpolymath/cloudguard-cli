<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Byte Detection Test Fixtures

This directory contains test files for validating the byte-level detection of BOMs, invisible characters, and control characters in the CI pipeline.

## Test Files

### Leading BOM Detection

- **`with_leading_bom.txt`** - File with UTF-8 BOM (EF BB BF) at the very start
  - **Expected:** Should be detected by leading BOM check
  - **Status:** Advisory warning

- **`with_mid_bom.txt`** - File with BOM in the middle (not at start)
  - **Expected:** Should NOT be detected by leading BOM check
  - **Expected:** SHOULD be detected by mid-file invisible character check
  - **Status:** Advisory warning for mid-file invisible chars

### C0 Control Characters (Blocking)

- **`with_nul_byte.txt`** - File containing a NUL byte (\x00)
  - **Expected:** Should be detected by C0/NUL check
  - **Status:** BLOCKS the gate (corruption, not typography)

- **`with_backspace.txt`** - File containing a backspace character (\x08)
  - **Expected:** Should be detected by C0/NUL check
  - **Status:** BLOCKS the gate (corruption, not typography)

### Mid-file Invisible Unicode (Advisory)

- **`with_mid_invisible.txt`** - File with zero-width space (U+200B) in the middle
  - **Expected:** Should be detected by invisible character check
  - **Status:** Advisory warning (legitimate typography in ~2,100 estate files)

### Clean Files

- **`clean_file.txt`** - File with only normal whitespace (spaces, tabs, newlines)
  - **Expected:** Should NOT be detected by any checks
  - **Status:** Pass

## Test Execution

Run the test suite:

```bash
./tests/test_byte_detection.sh
```

## Detection Rules

### Leading BOM Check (ID: `leading-bom`)
- **Pattern:** `^` followed by UTF-8 BOM bytes (EF BB BF)
- **Scope:** File start only
- **Action:** Advisory warning
- **Rationale:** BOMs at file start indicate Windows/encoding issues but may be legitimate in some cases

### C0 Control Characters (ID: `c0-nul-corruption`)
- **Pattern:** `[\x00-\x08\x0B\x0C\x0E-\x1F]`
- **Scope:** Anywhere in file
- **Action:** BLOCKS the gate
- **Rationale:** Indicates file corruption, not legitimate typography (per owner ruling 2026-08-28)

### Mid-file Invisible Unicode (ID: `mid-invisible-unicode`)
- **Pattern:** `[\x{a0}\x{ad}\x{200b}-\x{200f}\x{202a}-\x{202f}\x{2060}\x{2066}-\x{2069}\x{feff}]`
- **Scope:** Anywhere in file
- **Action:** Advisory warning
- **Rationale:** Legitimate typography in ~2,100 estate files (NBSP, zero-width spaces, etc.)

## CI Integration

These checks are integrated into `.github/workflows/dogfood-gate.yml` in the `empty-lint` job:

1. **Leading BOM scan** (separate step, runs first)
2. **Invisible character scan** (includes C0/NUL detection)
3. **Enforcement:** C0/NUL blocks; BOM and other invisible chars are advisory

## Exclusions

The following paths are excluded from scanning:
- `.git/`
- `node_modules/`
- `.deno/`
- `target/`
- `_build/`
- `deps/`
- `external_corpora/`
- `.lake/`
- `tests/fixtures/` (these test files themselves!)

## References

- Recent commits:
  - `ad483b0` - fix(ci): make invisible-character PCRE locale-independent
  - `eaa7168` - fix(ci): enforce C0/NUL corruption in-step; warn on invisible Unicode
  - `a69de22` - fix(ci): the invisible-character gate never matched anything
