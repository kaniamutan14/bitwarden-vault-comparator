# Bitwarden Vault Comparator

> Intelligently compare two Bitwarden JSON exports — detect password changes, 2FA modifications, renamed items, cross-type migrations, and more.

![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/license-MIT-green)
![No Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

---

## Why?

Bitwarden lets you export your vault as JSON, but gives you no way to **compare** two exports. If you:

- Migrated from one Bitwarden account to another and want to verify nothing was lost
- Need to audit what changed between two backup snapshots
- Want to check if passwords or 2FA secrets were accidentally modified
- Merged vaults and need to reconcile differences

This tool does it all — **zero dependencies**, single Python file, runs anywhere.

---

## Features

| Feature                          | Description                                                                                     |
| -------------------------------- | ----------------------------------------------------------------------------------------------- |
| 🔑 **Password Change Detection** | Detects changed passwords with masked display (or `--full` to reveal)                           |
| 🔐 **2FA / TOTP Tracking**       | Shows if TOTP was Added, Removed, or Changed per item                                           |
| 🆔 **ID-Based Matching**         | Uses Bitwarden's stable GUIDs for precise item pairing                                          |
| 🔍 **Fuzzy Matching**            | Weighted similarity scoring (name, username, URIs, notes) catches re-created items with new IDs |
| 🔄 **Cross-Type Detection**      | Finds items that changed type (e.g., Login with notes → SecureNote)                             |
| 📁 **Folder Comparison**         | Detects folder renames, additions, and removals                                                 |
| 💳 **Card & Identity Diffing**   | Full field-level comparison for payment cards and identity items                                |
| 🔧 **Custom Fields**             | Compares custom field names, values, and types                                                  |
| 📋 **Notes Diffing**             | Full text comparison of notes content                                                           |
| 📜 **Password History**          | Compares historical password entries                                                            |
| ⚠️ **Duplicate Detection**       | Warns about duplicate items within each export                                                  |
| 🎨 **Colorized Output**          | ANSI colors in terminal (auto-disabled when piped)                                              |
| 📄 **HTML Report**               | Dark-themed interactive HTML report with expandable sections                                    |
| 🔒 **Redacted Mode**             | Sensitive values masked by default — use `--full` to reveal                                     |

---

## Installation

No installation needed. Just download the script:

```bash
# Clone the repo
git clone https://github.com/kaniamutan14/bitwarden-vault-comparator.git
cd bitwarden-vault-comparator

# Or just download the single file
curl -O https://raw.githubusercontent.com/kaniamutan14/bitwarden-vault-comparator/main/compare_bw_exports.py
```

**Requirements:** Python 3.8+ (uses only standard library — zero external dependencies)

---

## Usage

### Basic Comparison

```bash
python compare_bw_exports.py old_export.json new_export.json
```

### Show Full Sensitive Values

```bash
python compare_bw_exports.py old.json new.json --full
```

### Generate HTML Report

```bash
python compare_bw_exports.py old.json new.json --html report.html
```

### All Options Combined

```bash
python compare_bw_exports.py old.json new.json --full --html report.html --threshold 0.5
```

### Command-Line Options

| Option        | Description                                                | Default    |
| ------------- | ---------------------------------------------------------- | ---------- |
| `file_a`      | Older / baseline Bitwarden JSON export                     | _required_ |
| `file_b`      | Newer Bitwarden JSON export                                | _required_ |
| `--full`      | Show full sensitive values (passwords, TOTP, card numbers) | Redacted   |
| `--html FILE` | Generate an HTML report at the specified path              | None       |
| `--threshold` | Fuzzy match similarity threshold (0.0–1.0)                 | 0.55       |

### Exit Codes

| Code | Meaning                                     |
| ---- | ------------------------------------------- |
| `0`  | No differences found — vaults are identical |
| `1`  | Differences found                           |
| `2`  | Error (bad file, invalid JSON, etc.)        |

---

## How to Export from Bitwarden

1. Open [Bitwarden Web Vault](https://vault.bitwarden.com) or desktop app
2. Go to **Settings → Export Vault**
3. Choose **File format: `.json`** (not encrypted, not CSV)
4. Enter your master password
5. Save the file

> ⚠️ **Security Warning:** Unencrypted JSON exports contain all your passwords in plaintext. Delete export files after comparison and never commit them to git.

---

## Example Output

```
════════════════════════════════════════════════════════════════════════════
  BITWARDEN VAULT COMPARISON REPORT
  Generated: 2026-09-03 16:25:09
════════════════════════════════════════════════════════════════════════════
  File A (baseline): old_export.json  (8 items)
  File B (compare) : new_export.json  (10 items)
════════════════════════════════════════════════════════════════════════════

📁 FOLDER CHANGES
────────────────────────────────────────────────────────────────────────────
  Renamed: Social Media → Social Accounts  (id=folder-1)
  Removed: Old Folder  (id=folder-3)
  Added  : Streaming  (id=folder-4)

❌ ONLY IN FILE A (removed / missing from B): 0
────────────────────────────────────────────────────────────────────────────
  (none)

✅ ONLY IN FILE B (added / new): 2
────────────────────────────────────────────────────────────────────────────
  [Login] Amazon (user@gmail.com) 🔐2FA
  [Login] Disney Plus (user@gmail.com) 📁Streaming

🔄 CROSS-TYPE MATCHES (Login ↔ SecureNote): 1
────────────────────────────────────────────────────────────────────────────
  A: [Login] "Twitter" → B: [SecureNote] "Twitter Backup"
     Name similarity: 67% | Notes similarity: 86%

🔍 FUZZY MATCHES (same item, different ID): 1
────────────────────────────────────────────────────────────────────────────
  Match confidence: 100%
  Name: Netflix
  Changes: 🔑 Password | 📁 Folder

📊 MATCHED BY ID — CHANGED: 5
────────────────────────────────────────────────────────────────────────────
  🔑 Password changed (1 items):
    • Google Mail  (also: fields, login.totp, login.uris, name, notes)

  🔐 2FA/TOTP changed (2 items):
    • Facebook  [ADDED]
    • Google Mail  [CHANGED]

════════════════════════════════════════════════════════════════════════════
  SUMMARY
════════════════════════════════════════════════════════════════════════════
  Total items in A         : 8
  Total items in B         : 10
  Net change               : +2
  ⚠  9 total differences detected
════════════════════════════════════════════════════════════════════════════
```

---

## How Matching Works

The tool uses a **3-phase matching strategy**:

```
Phase 1: ID Match          Phase 2: Fuzzy Match         Phase 3: Cross-Type
──────────────────         ────────────────────         ──────────────────
Same Bitwarden GUID?  ──→  Weighted similarity:    ──→  Login notes ↔
  Yes → Diff fields         • Name (35%)                SecureNote content?
  No  → Try Phase 2         • Username (20%)             Yes → Flag it
                             • URIs (20%)
                             • Type (15%)
                             • Notes (10%)
                            Score ≥ threshold? Match!
```

This catches:

- ✅ Normal edits (same ID, changed fields)
- ✅ Re-created items (deleted and re-added with new ID)
- ✅ Renamed items (name changed but same credentials)
- ✅ Type conversions (Login → SecureNote or vice versa)

---

## Security Considerations

- **Never commit vault exports to git** — the `.gitignore` in this repo excludes `*.json` files by default
- By default, passwords and TOTP secrets are **masked** in output (e.g., `Ne********s!`)
- Use `--full` only when you need to see actual values, and clear your terminal history afterward
- HTML reports contain sensitive data if `--full` is used — treat them as confidential

---

## Contributing

Contributions are welcome! Some ideas for future features:

- [ ] Password strength analysis & scoring
- [ ] Reused password detection across items
- [ ] 2FA coverage audit report
- [ ] HaveIBeenPwned breach checking (k-anonymity API)
- [ ] Line-by-line notes diffing (git-style)
- [ ] JSON machine-readable output
- [ ] Interactive TUI mode
- [ ] Multi-export timeline comparison
- [ ] Support for other password manager formats (1Password, LastPass, KeePass)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
