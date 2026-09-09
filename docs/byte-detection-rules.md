<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Byte Detection Rules

This document describes the byte-level detection rules for invisible characters, BOMs, and control characters enforced in the CI pipeline.

## Overview

The empty-linter system performs three distinct checks:

1. **Leading BOM Detection** - Detects UTF-8 BOMs at file start (advisory)
2. **C0 Control Character Detection** - Detects file corruption (blocking)
3. **Mid-file Invisible Unicode Detection** - Detects typography characters (advisory)

## Check Specifications

### 1. Leading BOM Check

**Check ID:** `leading-bom`

**Description:** Detects UTF-8 Byte Order Mark (EF BB BF) specifically at the very start of a file.

**Pattern:**
```
^[0xEF 0xBB 0xBF]
```

**Rationale:**
- UTF-8 BOMs at file start often indicate files edited on Windows or with certain editors
- While UTF-8 doesn't require a BOM (unlike UTF-16), some tools add them
- Generally considered unnecessary for UTF-8 but not harmful

**Action:** Advisory warning (does NOT block)

**Owner Ruling (2026-08-28):** Leading BOMs are advisory only - some legitimate sources may include them.

**File Types Checked:**
- Source code: `.rs`, `.ex`, `.exs`, `.res`, `.idr`, `.zig`, `.v`, `.jl`, `.gleam`, `.hs`, `.ml`
- Scripts: `.sh`
- Web: `.js`, `.ts`
- Data: `.json`, `.toml`, `.yml`, `.yaml`
- Documentation: `.md`, `.adoc`

### 2. C0 Control Character Detection

**Check ID:** `c0-nul-corruption`

**Description:** Detects C0 control characters and NUL bytes anywhere in source files.

**Pattern:**
```
[\x00-\x08\x0B\x0C\x0E-\x1F]
```

**Characters Detected:**
- `\x00` - NUL (null byte)
- `\x01-\x08` - SOH, STX, ETX, EOT, ENQ, ACK, BEL, BS (backspace)
- `\x0B` - VT (vertical tab)
- `\x0C` - FF (form feed)
- `\x0E-\x1F` - SO, SI, DLE, DC1-4, NAK, SYN, ETB, CAN, EM, SUB, ESC, FS-US

**Exclusions:** `\x09` (TAB), `\x0A` (LF), `\x0D` (CR) are allowed (normal whitespace).

**Rationale:**
- Indicates file corruption, binary data in text files, or terminal control sequences
- NOT legitimate typography
- Approximately 0 estate files should contain these

**Action:** BLOCKS the gate (CI fails)

**Owner Ruling (2026-08-28):** C0/NUL corruption blocks the gate - this is corruption, not typography.

**Error Message:**
```
C0 control characters or NUL bytes - file corruption, blocks the gate
```

### 3. Mid-file Invisible Unicode Detection

**Check ID:** `mid-invisible-unicode`

**Description:** Detects invisible Unicode characters commonly used in typography but potentially problematic in source code.

**Pattern:**
```
[\x{a0}\x{ad}\x{200b}-\x{200f}\x{202a}-\x{202f}\x{2060}\x{2066}-\x{2069}\x{feff}]
```

**Characters Detected:**
- `U+00A0` - Non-breaking space (NBSP)
- `U+00AD` - Soft hyphen
- `U+200B` - Zero-width space (ZWSP)
- `U+200C` - Zero-width non-joiner (ZWNJ)
- `U+200D` - Zero-width joiner (ZWJ)
- `U+200E` - Left-to-right mark (LRM)
- `U+200F` - Right-to-left mark (RLM)
- `U+202A-202F` - Directional formatting characters
- `U+2060` - Word joiner
- `U+2066-2069` - Directional isolates
- `U+FEFF` - Zero-width no-break space / BOM

**Rationale:**
- Legitimate in prose/documentation (~2,100 estate files use NBSP, etc.)
- Can cause subtle bugs in source code (e.g., ZWSP in identifiers)
- Not file corruption, but worth being aware of

**Action:** Advisory warning (does NOT block)

**Owner Ruling (2026-08-28):** Invisible Unicode stays advisory - about 2,100 estate files carry it as legitimate typography in prose.

## CI Integration

### Workflow Location
`.github/workflows/dogfood-gate.yml` → `empty-lint` job

### Execution Order
1. Leading BOM scan (first step)
2. Invisible character scan (includes C0/NUL detection)
3. Enforcement decision

### Exit Conditions
- **Success (exit 0):** No blocking issues found
- **Advisory (exit 0 with warnings):** BOM or invisible Unicode found
- **Failure (exit 1):** C0/NUL corruption found

### GitHub Annotations
- `::error` - C0/NUL corruption (blocks)
- `::warning` - Leading BOM or invisible Unicode (advisory)
- `::notice` - Summary of advisory findings

## Exclusions

The following paths are excluded from all scans:

```
.git/
node_modules/
.deno/
target/
_build/
deps/
external_corpora/
.lake/
tests/fixtures/
```

## Testing

### Test Suite Location
`tests/test_byte_detection.sh`

### Test Fixtures
`tests/fixtures/byte_detection/`

### Running Tests Locally
```bash
cd tests
./test_byte_detection.sh
```

### Expected Results
All tests should pass:
- Leading BOM detection works correctly
- C0/NUL detection works correctly
- Mid-file invisible Unicode detection works correctly
- Clean files are not flagged

## Historical Context

### Recent Commits
- `ad483b0` (2026-08-28) - fix(ci): make invisible-character PCRE locale-independent
- `eaa7168` (2026-08-28) - fix(ci): enforce C0/NUL corruption in-step; warn on invisible Unicode
- `a69de22` - fix(ci): the invisible-character gate never matched anything

### Owner Rulings
**2026-08-28:** Three-tier enforcement model established:
1. **Blocking:** C0/NUL corruption (file corruption)
2. **Advisory:** Leading BOM (encoding quirk)
3. **Advisory:** Invisible Unicode (legitimate typography)

### Rationale for Split
- Previous implementation lumped all invisible characters together
- Owner ruling distinguished corruption (must block) from typography (advisory)
- Leading BOM deserves separate check as it's specifically a file-start issue

## Implementation Notes

### PCRE vs Basic Regex
- Leading BOM check uses basic grep (byte-level match)
- C0/NUL check uses PCRE (`grep -P`)
- Invisible Unicode check uses PCRE with Unicode properties

### Locale Independence
- Pattern includes `(*UTF)` PCRE directive for locale-independent matching
- Fixes issue where pattern matching behavior varied by system locale

### Why Separate Steps
1. **Leading BOM** is conceptually different (file-start only)
2. **C0/NUL** must be blocking (corruption)
3. **Invisible Unicode** must be advisory (typography)

Combining them all would require complex conditional logic in a single step. Separate steps provide:
- Clear separation of concerns
- Independent pass/fail conditions
- Better GitHub annotations
- Easier debugging

## Future Considerations

### Potential Additions
- UTF-16/UTF-32 BOM detection (FF FE, FE FF, etc.)
- Emoji modifiers and combining characters
- Confusable characters (homoglyphs)
- Right-to-left override attacks

### Configuration File
Future enhancement: externalize patterns to a configuration file (e.g., `config.ncl` or `ByteDetector.affine`) rather than inline in workflow.

## References

- [Unicode Standard Annex #9 - Bidirectional Text](https://www.unicode.org/reports/tr9/)
- [RFC 3629 - UTF-8](https://www.rfc-editor.org/rfc/rfc3629)
- [Wikipedia: Byte Order Mark](https://en.wikipedia.org/wiki/Byte_order_mark)
- [Wikipedia: Zero-width space](https://en.wikipedia.org/wiki/Zero-width_space)
