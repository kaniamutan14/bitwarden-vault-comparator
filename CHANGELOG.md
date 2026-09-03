# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-09-03

### Added
- **ID-based matching** using stable Bitwarden GUIDs
- **Fuzzy matching** with weighted similarity scoring (name, username, URIs, notes, type)
- **Cross-type detection** — Login with notes ↔ SecureNote matching
- **Password change detection** with masked/redacted display
- **2FA/TOTP tracking** — detects Added, Removed, Changed states
- **Full field-level diffing** for all item types:
  - Login (username, password, TOTP, URIs, FIDO2)
  - SecureNote
  - Card (cardholder, number, expiry, CVV)
  - Identity (18 fields including SSN, passport, license)
- **Custom fields** comparison (name, value, type, linkedId)
- **Password history** comparison
- **Folder comparison** — renames, additions, removals
- **Duplicate detection** within each export
- **Colorized terminal output** (auto-disabled on non-TTY / pipe)
- **HTML report generation** (`--html report.html`) with dark theme
- **Redacted mode** by default — `--full` flag to reveal sensitive values
- **Configurable fuzzy threshold** (`--threshold 0.55`)
- **Exit codes** — 0 (identical), 1 (differences), 2 (error)
- **Change breakdown summary** — categorized counts of all change types
- **Windows UTF-8 support** — automatic encoding fix for emoji output
