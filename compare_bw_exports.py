#!/usr/bin/env python3
"""
Bitwarden Export Comparator — Full-Featured Vault Diff Tool
============================================================

Compare two unencrypted Bitwarden JSON exports and produce a detailed,
intelligent diff report.

Features:
  • ID-based matching (stable Bitwarden GUIDs)
  • Fuzzy matching when IDs differ (name, username, URIs, notes similarity)
  • Cross-type detection: item in notes of one ↔ secureNote in the other
  • Password change detection with masked display
  • 2FA / TOTP change detection (login.totp field)
  • URI changes, custom-field changes, card/identity diffing
  • Folder / collection rename detection
  • Duplicate detection within each export
  • Colorized terminal output (auto-disabled on non-TTY)
  • Optional HTML report (--html report.html)
  • Optional full-value display (--full) vs. redacted mode

Usage:
    python compare_bw_exports.py old_export.json new_export.json
    python compare_bw_exports.py old.json new.json --full --html report.html

Exit codes:
    0 = no differences found
    1 = differences found
    2 = error (bad file, etc.)
"""

import json
import sys
import re
import os
import html as html_module
import argparse

# Force UTF-8 output on Windows (cp1252 can't handle emoji/unicode)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
from collections import OrderedDict, defaultdict
from datetime import datetime
from difflib import SequenceMatcher

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────

TYPE_MAP = {1: "Login", 2: "SecureNote", 3: "Card", 4: "Identity"}
SENSITIVE_FIELDS = {
    "login.password", "login.totp", "card.number", "card.code",
    "identity.ssn", "identity.passportNumber", "identity.licenseNumber",
}

# ──────────────────────────────────────────────────────────────────────
# Terminal colours (disabled when piped / on dumb terminals)
# ──────────────────────────────────────────────────────────────────────

_USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

def _c(code, text):
    if _USE_COLOR:
        return f"\033[{code}m{text}\033[0m"
    return text

def red(t):      return _c("31", t)
def green(t):    return _c("32", t)
def yellow(t):   return _c("33", t)
def cyan(t):     return _c("36", t)
def bold(t):     return _c("1", t)
def dim(t):      return _c("2", t)
def magenta(t):  return _c("35", t)

# ──────────────────────────────────────────────────────────────────────
# Loading & normalisation
# ──────────────────────────────────────────────────────────────────────

def load_export(path):
    """Load a Bitwarden JSON export, returning (raw_data, items_by_id, folder_lookup)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, OSError) as exc:
        print(red(f"ERROR: Cannot load '{path}': {exc}"), file=sys.stderr)
        sys.exit(2)

    # Bitwarden exports can have items at top-level or nested
    items = data.get("items", [])
    folders = data.get("folders", [])

    # Build lookup by id; warn on duplicates
    by_id = OrderedDict()
    duplicates = []
    for it in items:
        iid = it.get("id")
        if iid in by_id:
            duplicates.append((iid, it.get("name")))
        by_id[iid] = it

    folder_names = {f["id"]: f.get("name", "(unnamed)") for f in folders}
    return data, by_id, folder_names, duplicates


def type_label(type_int):
    return TYPE_MAP.get(type_int, f"Unknown({type_int})")

# ──────────────────────────────────────────────────────────────────────
# Field extraction — deep, type-aware
# ──────────────────────────────────────────────────────────────────────

def _normalise_uris(login):
    """Extract and sort URIs from a login object."""
    uris = login.get("uris") or []
    return sorted(
        [{"uri": u.get("uri"), "match": u.get("match")} for u in uris if u.get("uri")],
        key=lambda x: x["uri"],
    )


def _normalise_fields(fields_list):
    """Extract custom fields into a stable sorted list."""
    if not fields_list:
        return []
    return sorted(
        [
            {
                "name": f.get("name"),
                "value": f.get("value"),
                "type": f.get("type"),
                "linkedId": f.get("linkedId"),
            }
            for f in fields_list
        ],
        key=lambda x: (x["name"] or "", str(x["type"] or "")),
    )


def _normalise_password_history(hist):
    """Extract password history into a sorted list."""
    if not hist:
        return []
    return sorted(
        [{"password": h.get("password"), "lastUsedDate": h.get("lastUsedDate")} for h in hist],
        key=lambda x: x.get("lastUsedDate") or "",
    )


def extract_all_fields(it, folder_names):
    """
    Extract every meaningful field from a Bitwarden item into a flat/nested
    dict suitable for comparison.  Noise fields (revisionDate, creationDate,
    organizationId, collectionIds, etc.) are excluded unless they carry
    semantic meaning.
    """
    typ = it.get("type")
    out = OrderedDict()

    # ── Core metadata ──
    out["name"] = it.get("name")
    out["type"] = type_label(typ)
    folder_id = it.get("folderId")
    out["folder"] = folder_names.get(folder_id) if folder_id else None
    out["favorite"] = it.get("favorite", False)
    out["reprompt"] = it.get("reprompt", 0)
    out["notes"] = it.get("notes")
    out["deletedDate"] = it.get("deletedDate")

    # ── Login (type 1) ──
    if it.get("login"):
        login = it["login"]
        out["login.username"] = login.get("username")
        out["login.password"] = login.get("password")
        out["login.totp"] = login.get("totp")
        out["login.uris"] = _normalise_uris(login)
        out["login.fido2Credentials"] = login.get("fido2Credentials")

    # ── Secure Note (type 2) ──
    if it.get("secureNote"):
        out["secureNote.type"] = it["secureNote"].get("type")

    # ── Card (type 3) ──
    if it.get("card"):
        card = it["card"]
        for k in ("cardholderName", "brand", "number", "expMonth", "expYear", "code"):
            out[f"card.{k}"] = card.get(k)

    # ── Identity (type 4) ──
    if it.get("identity"):
        ident = it["identity"]
        for k in (
            "title", "firstName", "middleName", "lastName", "address1", "address2",
            "address3", "city", "state", "postalCode", "country", "company", "email",
            "phone", "ssn", "username", "passportNumber", "licenseNumber",
        ):
            out[f"identity.{k}"] = ident.get(k)

    # ── Custom fields ──
    out["fields"] = _normalise_fields(it.get("fields"))

    # ── Password history ──
    out["passwordHistory"] = _normalise_password_history(it.get("passwordHistory"))

    return out

# ──────────────────────────────────────────────────────────────────────
# Diffing
# ──────────────────────────────────────────────────────────────────────

def diff_items(item_a, item_b, folders_a, folders_b):
    """
    Compare two items field-by-field.
    Returns an OrderedDict of {field: {"A": val_a, "B": val_b}} for every
    field that differs.  Keys are ordered for readable output.
    """
    fa = extract_all_fields(item_a, folders_a)
    fb = extract_all_fields(item_b, folders_b)
    all_keys = list(dict.fromkeys(list(fa.keys()) + list(fb.keys())))
    changes = OrderedDict()
    for k in all_keys:
        va = fa.get(k)
        vb = fb.get(k)
        # Treat None and empty string / empty list as equivalent where sensible
        if _equiv(va, vb):
            continue
        if va != vb:
            changes[k] = {"A": va, "B": vb}
    return changes


def _equiv(a, b):
    """Treat None, '', [], {} as equivalent for diff noise reduction."""
    empties = (None, "", [], {}, False, 0)
    if a in empties and b in empties:
        return True
    return a == b

# ──────────────────────────────────────────────────────────────────────
# Similarity helpers for fuzzy matching
# ──────────────────────────────────────────────────────────────────────

def _text_sim(a, b):
    """SequenceMatcher ratio between two optional strings."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _uri_set(item):
    """Extract a set of URIs from a login item."""
    login = item.get("login") or {}
    return {u.get("uri", "").lower() for u in (login.get("uris") or []) if u.get("uri")}


def _notes_fingerprint(item):
    """First 200 chars of notes, lowered, whitespace-collapsed."""
    n = item.get("notes") or ""
    return re.sub(r"\s+", " ", n[:200]).strip().lower()


def compute_similarity(a, b):
    """
    Score 0..1 indicating how likely items a and b are the same entry
    despite having different Bitwarden IDs.

    Weighted components:
      - name similarity        : 35%
      - username match         : 20%
      - URI overlap            : 20%
      - notes similarity       : 10%
      - type compatibility     : 15%
    """
    name_sim = _text_sim(a.get("name"), b.get("name"))

    login_a = a.get("login") or {}
    login_b = b.get("login") or {}
    user_a = (login_a.get("username") or "").lower()
    user_b = (login_b.get("username") or "").lower()
    user_sim = 1.0 if (user_a and user_a == user_b) else (0.5 if (not user_a and not user_b) else 0.0)

    uris_a = _uri_set(a)
    uris_b = _uri_set(b)
    if uris_a or uris_b:
        intersection = uris_a & uris_b
        union = uris_a | uris_b
        uri_sim = len(intersection) / len(union) if union else 0.5
    else:
        uri_sim = 0.5  # neutral when neither has URIs

    notes_sim = _text_sim(_notes_fingerprint(a), _notes_fingerprint(b))

    # Type compatibility: same type = 1.0
    # Login(1) ↔ SecureNote(2) with matching notes = 0.6 (cross-type)
    type_a = a.get("type")
    type_b = b.get("type")
    if type_a == type_b:
        type_sim = 1.0
    elif {type_a, type_b} == {1, 2}:
        # Could be a login turned into a secure note or vice versa
        type_sim = 0.6
    else:
        type_sim = 0.0

    score = (
        0.35 * name_sim
        + 0.20 * user_sim
        + 0.20 * uri_sim
        + 0.10 * notes_sim
        + 0.15 * type_sim
    )
    return score


def find_fuzzy_matches(unmatched_a, unmatched_b, items_a, items_b, threshold=0.55):
    """
    Given sets of IDs that didn't match by GUID, try to pair them by
    content similarity.  Returns list of (a_id, b_id, score).
    """
    if not unmatched_a or not unmatched_b:
        return []

    # Build score matrix (only above threshold)
    candidates = []
    for a_id in unmatched_a:
        for b_id in unmatched_b:
            score = compute_similarity(items_a[a_id], items_b[b_id])
            if score >= threshold:
                candidates.append((score, a_id, b_id))

    # Greedy best-first matching (no item matched twice)
    candidates.sort(reverse=True)
    used_a = set()
    used_b = set()
    matches = []
    for score, a_id, b_id in candidates:
        if a_id not in used_a and b_id not in used_b:
            matches.append((a_id, b_id, score))
            used_a.add(a_id)
            used_b.add(b_id)
    return matches

# ──────────────────────────────────────────────────────────────────────
# Cross-type detection: note content ↔ secure note
# ──────────────────────────────────────────────────────────────────────

def detect_cross_type_matches(unmatched_a, unmatched_b, items_a, items_b):
    """
    Detect cases where an item's notes content in one export appears as a
    separate SecureNote in the other, or a Login was converted to a
    SecureNote (or vice versa) preserving some content.

    Returns list of dicts describing each cross-type match.
    """
    results = []

    # Collect secure notes and login items
    def _classify(ids, items):
        secure = {}
        logins = {}
        for iid in ids:
            it = items[iid]
            if it.get("type") == 2:
                secure[iid] = it
            elif it.get("type") == 1:
                logins[iid] = it
        return secure, logins

    secure_a, logins_a = _classify(unmatched_a, items_a)
    secure_b, logins_b = _classify(unmatched_b, items_b)

    # Check: login notes in A ↔ secureNote in B
    for a_id, login in logins_a.items():
        login_notes = (login.get("notes") or "").strip()
        if not login_notes:
            continue
        for b_id, snote in secure_b.items():
            snote_notes = (snote.get("notes") or "").strip()
            name_sim = _text_sim(login.get("name"), snote.get("name"))
            notes_sim = _text_sim(login_notes, snote_notes)
            if notes_sim > 0.7 or (name_sim > 0.8 and notes_sim > 0.4):
                results.append({
                    "a_id": a_id, "b_id": b_id,
                    "a_name": login.get("name"), "b_name": snote.get("name"),
                    "a_type": "Login", "b_type": "SecureNote",
                    "direction": "A→B",
                    "name_sim": name_sim, "notes_sim": notes_sim,
                })

    # Check: secureNote in A ↔ login notes in B
    for a_id, snote in secure_a.items():
        snote_notes = (snote.get("notes") or "").strip()
        if not snote_notes:
            continue
        for b_id, login in logins_b.items():
            login_notes = (login.get("notes") or "").strip()
            name_sim = _text_sim(snote.get("name"), login.get("name"))
            notes_sim = _text_sim(snote_notes, login_notes)
            if notes_sim > 0.7 or (name_sim > 0.8 and notes_sim > 0.4):
                results.append({
                    "a_id": a_id, "b_id": b_id,
                    "a_name": snote.get("name"), "b_name": login.get("name"),
                    "a_type": "SecureNote", "b_type": "Login",
                    "direction": "A→B",
                    "name_sim": name_sim, "notes_sim": notes_sim,
                })

    return results

# ──────────────────────────────────────────────────────────────────────
# Duplicate detection within a single export
# ──────────────────────────────────────────────────────────────────────

def find_duplicates(items_by_id):
    """Find items with identical (name, username) within one export."""
    seen = defaultdict(list)
    for iid, it in items_by_id.items():
        login = it.get("login") or {}
        key = (it.get("name", "").lower(), (login.get("username") or "").lower(), it.get("type"))
        seen[key].append(iid)
    dupes = {k: v for k, v in seen.items() if len(v) > 1}
    return dupes

# ──────────────────────────────────────────────────────────────────────
# Folder / collection comparison
# ──────────────────────────────────────────────────────────────────────

def diff_folders(folders_a, folders_b):
    """Compare folder lists. Returns (only_a, only_b, renamed) info."""
    ids_a = set(folders_a.keys())
    ids_b = set(folders_b.keys())
    only_a = {fid: folders_a[fid] for fid in ids_a - ids_b}
    only_b = {fid: folders_b[fid] for fid in ids_b - ids_a}
    renamed = {}
    for fid in ids_a & ids_b:
        if folders_a[fid] != folders_b[fid]:
            renamed[fid] = {"A": folders_a[fid], "B": folders_b[fid]}
    return only_a, only_b, renamed

# ──────────────────────────────────────────────────────────────────────
# Output formatting helpers
# ──────────────────────────────────────────────────────────────────────

def mask_value(val):
    """Mask a sensitive value for display."""
    if val is None:
        return "<empty>"
    s = str(val)
    if len(s) <= 4:
        return "****"
    return s[:2] + "*" * (len(s) - 4) + s[-2:]


def format_value(val, field, show_full):
    """Format a value for display, masking sensitive fields unless --full."""
    if val is None:
        return dim("<empty>")
    if isinstance(val, list):
        if not val:
            return dim("<empty list>")
        parts = []
        for item in val:
            if isinstance(item, dict):
                parts.append(str(item))
            else:
                parts.append(str(item))
        return "\n            ".join(parts)
    if field in SENSITIVE_FIELDS and not show_full:
        return yellow(mask_value(val))
    return str(val)


def format_change_category(changes):
    """Categorize changes for quick scanning."""
    categories = []
    if "login.password" in changes:
        categories.append(red("🔑 Password"))
    if "login.totp" in changes:
        categories.append(magenta("🔐 2FA/TOTP"))
    if "name" in changes:
        categories.append(cyan("📝 Name"))
    if "type" in changes:
        categories.append(yellow("🔄 Type"))
    if "login.username" in changes:
        categories.append(cyan("👤 Username"))
    if any(k.startswith("login.uri") for k in changes):
        categories.append(dim("🔗 URIs"))
    if "notes" in changes:
        categories.append(dim("📋 Notes"))
    if "folder" in changes:
        categories.append(dim("📁 Folder"))
    if "favorite" in changes:
        categories.append(dim("⭐ Favorite"))
    if any(k.startswith("card.") for k in changes):
        categories.append(yellow("💳 Card"))
    if any(k.startswith("identity.") for k in changes):
        categories.append(cyan("🪪 Identity"))
    if "fields" in changes:
        categories.append(dim("🔧 Custom Fields"))
    if "passwordHistory" in changes:
        categories.append(dim("📜 Password History"))
    # catch anything else
    known = {
        "login.password", "login.totp", "name", "type", "login.username",
        "login.uris", "notes", "folder", "favorite", "fields",
        "passwordHistory", "reprompt", "deletedDate",
        "secureNote.type", "login.fido2Credentials",
    }
    card_identity = {k for k in changes if k.startswith("card.") or k.startswith("identity.")}
    other = set(changes.keys()) - known - card_identity
    if other:
        categories.append(dim(f"📦 {', '.join(other)}"))
    return " | ".join(categories) if categories else "Minor changes"

# ──────────────────────────────────────────────────────────────────────
# Console report
# ──────────────────────────────────────────────────────────────────────

def print_report(
    file_a, file_b,
    items_a, items_b,
    folders_a, folders_b,
    duplicates_a, duplicates_b,
    true_only_a, true_only_b,
    id_matches_changed, id_matches_unchanged_count,
    fuzzy_matches, fuzzy_changes,
    cross_type_matches,
    folder_only_a, folder_only_b, folder_renamed,
    show_full,
):
    """Print the full comparison report to stdout."""
    sep = bold("═" * 76)
    thin = "─" * 76

    print(sep)
    print(bold("  BITWARDEN VAULT COMPARISON REPORT"))
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(sep)
    print(f"  File A (baseline): {cyan(file_a)}  ({len(items_a)} items)")
    print(f"  File B (compare) : {cyan(file_b)}  ({len(items_b)} items)")
    print(sep)

    # ── Duplicates warning ──
    dupes_a = find_duplicates(items_a)
    dupes_b = find_duplicates(items_b)
    if dupes_a or dupes_b:
        print(f"\n{yellow('⚠  DUPLICATE ITEMS DETECTED')}")
        print(thin)
        if dupes_a:
            print(f"  In File A:")
            for key, ids in dupes_a.items():
                print(f"    {key[0]} / {key[1] or '<no user>'} [{type_label(key[2])}] × {len(ids)}")
        if dupes_b:
            print(f"  In File B:")
            for key, ids in dupes_b.items():
                print(f"    {key[0]} / {key[1] or '<no user>'} [{type_label(key[2])}] × {len(ids)}")

    # ── Folder changes ──
    if folder_only_a or folder_only_b or folder_renamed:
        print(f"\n{bold('📁 FOLDER CHANGES')}")
        print(thin)
        if folder_renamed:
            for fid, names in folder_renamed.items():
                print(f"  Renamed: {yellow(names['A'])} → {green(names['B'])}  (id={dim(fid)})")
        if folder_only_a:
            for fid, name in folder_only_a.items():
                print(f"  {red('Removed')}: {name}  (id={dim(fid)})")
        if folder_only_b:
            for fid, name in folder_only_b.items():
                print(f"  {green('Added')}  : {name}  (id={dim(fid)})")

    # ── Only in A ──
    print(f"\n{bold(red(f'❌ ONLY IN FILE A (removed / missing from B): {len(true_only_a)}'))}")
    print(thin)
    if true_only_a:
        for iid in sorted(true_only_a, key=lambda x: (items_a[x].get("name") or "").lower()):
            it = items_a[iid]
            login = it.get("login") or {}
            user = login.get("username") or ""
            folder = folders_a.get(it.get("folderId"), "")
            folder_str = f" 📁{folder}" if folder else ""
            totp_str = " 🔐2FA" if login.get("totp") else ""
            print(f"  [{type_label(it.get('type'))}] {it.get('name')}"
                  f"{' (' + user + ')' if user else ''}"
                  f"{folder_str}{totp_str}")
            print(f"         {dim('id=' + iid)}")
    else:
        print(f"  {dim('(none)')}")

    # ── Only in B ──
    print(f"\n{bold(green(f'✅ ONLY IN FILE B (added / new): {len(true_only_b)}'))}")
    print(thin)
    if true_only_b:
        for iid in sorted(true_only_b, key=lambda x: (items_b[x].get("name") or "").lower()):
            it = items_b[iid]
            login = it.get("login") or {}
            user = login.get("username") or ""
            folder = folders_b.get(it.get("folderId"), "")
            folder_str = f" 📁{folder}" if folder else ""
            totp_str = " 🔐2FA" if login.get("totp") else ""
            print(f"  [{type_label(it.get('type'))}] {it.get('name')}"
                  f"{' (' + user + ')' if user else ''}"
                  f"{folder_str}{totp_str}")
            print(f"         {dim('id=' + iid)}")
    else:
        print(f"  {dim('(none)')}")

    # ── Cross-type matches ──
    if cross_type_matches:
        print(f"\n{bold(magenta(f'🔄 CROSS-TYPE MATCHES (Login ↔ SecureNote): {len(cross_type_matches)}'))}")
        print(thin)
        for ct in cross_type_matches:
            print(f"  A: [{ct['a_type']}] \"{ct['a_name']}\" (id={dim(ct['a_id'])})")
            print(f"  B: [{ct['b_type']}] \"{ct['b_name']}\" (id={dim(ct['b_id'])})")
            print(f"     Name similarity: {ct['name_sim']:.0%} | Notes similarity: {ct['notes_sim']:.0%}")
            print()

    # ── Fuzzy matches (different IDs, similar content) ──
    if fuzzy_matches:
        print(f"\n{bold(yellow(f'🔍 FUZZY MATCHES (same item, different ID): {len(fuzzy_matches)}'))}")
        print(thin)
        for a_id, b_id, score in fuzzy_matches:
            it_a = items_a[a_id]
            it_b = items_b[b_id]
            name_a = it_a.get("name", "")
            name_b = it_b.get("name", "")
            print(f"\n  Match confidence: {yellow(f'{score:.0%}')}")
            if name_a == name_b:
                print(f"  Name: {bold(name_a)}")
            else:
                print(f"  A name: {name_a} → B name: {name_b}")
            print(f"  A.id={dim(a_id)}  →  B.id={dim(b_id)}")

            # Show changes between fuzzy-matched items
            changes = fuzzy_changes.get((a_id, b_id), {})
            if changes:
                cats = format_change_category(changes)
                print(f"  Changes: {cats}")
                for field, vals in changes.items():
                    va_str = format_value(vals["A"], field, show_full)
                    vb_str = format_value(vals["B"], field, show_full)
                    print(f"    {cyan(field)}:")
                    print(f"        A: {va_str}")
                    print(f"        B: {vb_str}")
            else:
                print(f"  {dim('No field-level differences (ID changed only)')}")

    # ── Items with same ID but changed content ──
    print(f"\n{bold(cyan(f'📊 MATCHED BY ID — CHANGED: {len(id_matches_changed)}'))}")
    print(thin)
    if id_matches_changed:
        # Group by change category for better overview
        pw_changed = []
        totp_changed = []
        other_changed = []
        for iid, changes in id_matches_changed:
            if "login.password" in changes:
                pw_changed.append((iid, changes))
            if "login.totp" in changes:
                totp_changed.append((iid, changes))
            if "login.password" not in changes and "login.totp" not in changes:
                other_changed.append((iid, changes))

        if pw_changed:
            print(f"\n  {red('🔑 Password changed')} ({len(pw_changed)} items):")
            for iid, changes in pw_changed:
                name = items_b[iid].get("name", "")
                other_cats = {k for k in changes if k != "login.password"}
                also = f"  (also: {', '.join(sorted(other_cats))})" if other_cats else ""
                print(f"    • {name}{dim(also)}")

        if totp_changed:
            print(f"\n  {magenta('🔐 2FA/TOTP changed')} ({len(totp_changed)} items):")
            for iid, changes in totp_changed:
                name = items_b[iid].get("name", "")
                totp_a = changes["login.totp"]["A"]
                totp_b = changes["login.totp"]["B"]
                if totp_a and not totp_b:
                    status = red("REMOVED")
                elif not totp_a and totp_b:
                    status = green("ADDED")
                else:
                    status = yellow("CHANGED")
                print(f"    • {name}  [{status}]")

        # Detailed per-item diff
        print(f"\n  {bold('Detail:')}  ({dim('use --full to show sensitive values')})" if not show_full else "")
        for iid, changes in id_matches_changed:
            name = items_b[iid].get("name", "")
            cats = format_change_category(changes)
            print(f"\n  {bold(name)}  {dim('id=' + iid)}")
            print(f"  {cats}")
            for field, vals in changes.items():
                va_str = format_value(vals["A"], field, show_full)
                vb_str = format_value(vals["B"], field, show_full)
                print(f"    {cyan(field)}:")
                print(f"        A: {va_str}")
                print(f"        B: {vb_str}")
    else:
        print(f"  {dim('(none)')}")

    print(f"\n  {dim(f'Matched by ID — unchanged: {id_matches_unchanged_count}')}")

    # ── Summary ──
    print(f"\n{sep}")
    print(bold("  SUMMARY"))
    print(sep)
    total_diffs = (
        len(true_only_a) + len(true_only_b) + len(id_matches_changed)
        + len(fuzzy_matches) + len(cross_type_matches)
    )
    print(f"  Total items in A         : {len(items_a)}")
    print(f"  Total items in B         : {len(items_b)}")
    print(f"  Net change               : {len(items_b) - len(items_a):+d}")
    print(thin)
    print(f"  {red('Only in A (removed)')}      : {len(true_only_a)}")
    print(f"  {green('Only in B (added)')}       : {len(true_only_b)}")
    print(f"  {yellow('Fuzzy matches (ID changed)')}: {len(fuzzy_matches)}")
    print(f"  {magenta('Cross-type matches')}       : {len(cross_type_matches)}")
    print(f"  {cyan('Same ID, changed')}         : {len(id_matches_changed)}")
    print(f"  Same ID, unchanged       : {id_matches_unchanged_count}")
    print(thin)

    # Change breakdown
    if id_matches_changed or fuzzy_matches:
        all_changes = [c for _, c in id_matches_changed]
        all_changes.extend(fuzzy_changes.values())
        pw_count = sum(1 for c in all_changes if "login.password" in c)
        totp_count = sum(1 for c in all_changes if "login.totp" in c)
        name_count = sum(1 for c in all_changes if "name" in c)
        uri_count = sum(1 for c in all_changes if "login.uris" in c)
        notes_count = sum(1 for c in all_changes if "notes" in c)
        folder_count = sum(1 for c in all_changes if "folder" in c)
        user_count = sum(1 for c in all_changes if "login.username" in c)
        print(f"  Change breakdown:")
        if pw_count:    print(f"    🔑 Password changes    : {pw_count}")
        if totp_count:  print(f"    🔐 2FA/TOTP changes    : {totp_count}")
        if name_count:  print(f"    📝 Name changes        : {name_count}")
        if user_count:  print(f"    👤 Username changes     : {user_count}")
        if uri_count:   print(f"    🔗 URI changes          : {uri_count}")
        if notes_count: print(f"    📋 Notes changes        : {notes_count}")
        if folder_count:print(f"    📁 Folder changes       : {folder_count}")
        print(thin)

    if total_diffs == 0:
        print(f"\n  {green(bold('✅ Vaults are IDENTICAL'))}")
    else:
        print(f"\n  {yellow(bold(f'⚠  {total_diffs} total differences detected'))}")
    print(sep)
    return total_diffs

# ──────────────────────────────────────────────────────────────────────
# HTML report
# ──────────────────────────────────────────────────────────────────────

def generate_html_report(
    file_a, file_b,
    items_a, items_b,
    folders_a, folders_b,
    true_only_a, true_only_b,
    id_matches_changed, id_matches_unchanged_count,
    fuzzy_matches, fuzzy_changes,
    cross_type_matches,
    folder_only_a, folder_only_b, folder_renamed,
    show_full,
    output_path,
):
    """Generate an HTML report of the comparison."""
    h = html_module.escape

    css = """
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
               background: #0d1117; color: #c9d1d9; padding: 20px; line-height: 1.5; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #58a6ff; margin-bottom: 10px; font-size: 1.8em; }
        h2 { color: #79c0ff; margin: 25px 0 10px 0; padding: 8px 12px;
             background: #161b22; border-left: 4px solid #58a6ff; border-radius: 4px; }
        h3 { color: #d2a8ff; margin: 15px 0 8px 0; font-size: 1.1em; }
        .meta { color: #8b949e; margin-bottom: 20px; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                     gap: 10px; margin: 15px 0; }
        .stat { background: #161b22; padding: 15px; border-radius: 8px; border: 1px solid #30363d; }
        .stat .num { font-size: 2em; font-weight: bold; }
        .stat .label { color: #8b949e; font-size: 0.85em; }
        .stat.removed .num { color: #f85149; }
        .stat.added .num { color: #3fb950; }
        .stat.changed .num { color: #d29922; }
        .stat.matched .num { color: #58a6ff; }
        .stat.neutral .num { color: #8b949e; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th { background: #161b22; color: #79c0ff; text-align: left; padding: 10px 12px;
             border-bottom: 2px solid #30363d; font-weight: 600; }
        td { padding: 8px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }
        tr:hover { background: #161b22; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 12px;
               font-size: 0.8em; font-weight: 600; margin: 2px; }
        .tag-pw { background: #f8514922; color: #f85149; border: 1px solid #f8514944; }
        .tag-totp { background: #d2a8ff22; color: #d2a8ff; border: 1px solid #d2a8ff44; }
        .tag-name { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; }
        .tag-uri { background: #3fb95022; color: #3fb950; border: 1px solid #3fb95044; }
        .tag-other { background: #8b949e22; color: #8b949e; border: 1px solid #8b949e44; }
        .diff-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 5px 0; }
        .diff-a { background: #f8514911; padding: 6px 10px; border-radius: 4px;
                  border-left: 3px solid #f85149; font-family: monospace; font-size: 0.9em;
                  word-break: break-all; }
        .diff-b { background: #3fb95011; padding: 6px 10px; border-radius: 4px;
                  border-left: 3px solid #3fb950; font-family: monospace; font-size: 0.9em;
                  word-break: break-all; }
        .dim { color: #484f58; }
        .badge { display: inline-block; padding: 1px 6px; border-radius: 4px;
                 font-size: 0.75em; font-weight: 600; }
        .badge-removed { background: #da363422; color: #f85149; }
        .badge-added { background: #23863622; color: #3fb950; }
        .badge-changed { background: #9e6a0322; color: #d29922; }
        details { margin: 5px 0; }
        summary { cursor: pointer; padding: 6px; border-radius: 4px; }
        summary:hover { background: #161b22; }
        .confidence { display: inline-block; padding: 2px 8px; border-radius: 4px;
                      font-weight: 600; font-size: 0.85em; }
        .conf-high { background: #3fb95022; color: #3fb950; }
        .conf-med { background: #d2992222; color: #d29922; }
        .conf-low { background: #f8514922; color: #f85149; }
        .empty { color: #484f58; font-style: italic; }
        .section-count { color: #8b949e; font-weight: normal; font-size: 0.85em; }
    </style>
    """

    lines = [
        "<!DOCTYPE html>",
        f"<html><head><meta charset='utf-8'><title>Bitwarden Vault Comparison</title>{css}</head>",
        "<body><div class='container'>",
        "<h1>🔐 Bitwarden Vault Comparison Report</h1>",
        f"<p class='meta'>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>",
        f"File A: <code>{h(file_a)}</code> ({len(items_a)} items)<br>",
        f"File B: <code>{h(file_b)}</code> ({len(items_b)} items)</p>",
    ]

    # Summary stats
    lines.append("<div class='stat-grid'>")
    lines.append(f"<div class='stat removed'><div class='num'>{len(true_only_a)}</div><div class='label'>Only in A (Removed)</div></div>")
    lines.append(f"<div class='stat added'><div class='num'>{len(true_only_b)}</div><div class='label'>Only in B (Added)</div></div>")
    lines.append(f"<div class='stat changed'><div class='num'>{len(id_matches_changed)}</div><div class='label'>Changed (Same ID)</div></div>")
    lines.append(f"<div class='stat matched'><div class='num'>{len(fuzzy_matches)}</div><div class='label'>Fuzzy Matches</div></div>")
    lines.append(f"<div class='stat neutral'><div class='num'>{id_matches_unchanged_count}</div><div class='label'>Unchanged</div></div>")
    lines.append(f"<div class='stat neutral'><div class='num'>{len(cross_type_matches)}</div><div class='label'>Cross-Type</div></div>")
    lines.append("</div>")

    def _html_field_val(val, field, full):
        if val is None:
            return "<span class='empty'>&lt;empty&gt;</span>"
        if isinstance(val, list):
            if not val:
                return "<span class='empty'>&lt;empty list&gt;</span>"
            return "<br>".join(h(str(v)) for v in val)
        if field in SENSITIVE_FIELDS and not full:
            return f"<code>{h(mask_value(val))}</code>"
        return f"<code>{h(str(val))}</code>"

    def _change_tags(changes):
        tags = []
        if "login.password" in changes: tags.append("<span class='tag tag-pw'>🔑 Password</span>")
        if "login.totp" in changes: tags.append("<span class='tag tag-totp'>🔐 2FA</span>")
        if "name" in changes: tags.append("<span class='tag tag-name'>📝 Name</span>")
        if "login.username" in changes: tags.append("<span class='tag tag-name'>👤 Username</span>")
        if "login.uris" in changes: tags.append("<span class='tag tag-uri'>🔗 URIs</span>")
        remaining = set(changes.keys()) - {"login.password", "login.totp", "name", "login.username", "login.uris"}
        if remaining: tags.append(f"<span class='tag tag-other'>+{len(remaining)} more</span>")
        return " ".join(tags)

    # Only in A
    lines.append(f"<h2>❌ Only in File A <span class='section-count'>({len(true_only_a)})</span></h2>")
    if true_only_a:
        lines.append("<table><tr><th>Type</th><th>Name</th><th>Username</th><th>Folder</th><th>2FA</th></tr>")
        for iid in sorted(true_only_a, key=lambda x: (items_a[x].get("name") or "").lower()):
            it = items_a[iid]
            login = it.get("login") or {}
            folder = folders_a.get(it.get("folderId"), "")
            totp = "✅" if login.get("totp") else ""
            lines.append(f"<tr><td>{h(type_label(it.get('type')))}</td><td>{h(it.get('name',''))}</td>"
                         f"<td>{h(login.get('username',''))}</td><td>{h(folder)}</td><td>{totp}</td></tr>")
        lines.append("</table>")
    else:
        lines.append("<p class='empty'>(none)</p>")

    # Only in B
    lines.append(f"<h2>✅ Only in File B <span class='section-count'>({len(true_only_b)})</span></h2>")
    if true_only_b:
        lines.append("<table><tr><th>Type</th><th>Name</th><th>Username</th><th>Folder</th><th>2FA</th></tr>")
        for iid in sorted(true_only_b, key=lambda x: (items_b[x].get("name") or "").lower()):
            it = items_b[iid]
            login = it.get("login") or {}
            folder = folders_b.get(it.get("folderId"), "")
            totp = "✅" if login.get("totp") else ""
            lines.append(f"<tr><td>{h(type_label(it.get('type')))}</td><td>{h(it.get('name',''))}</td>"
                         f"<td>{h(login.get('username',''))}</td><td>{h(folder)}</td><td>{totp}</td></tr>")
        lines.append("</table>")
    else:
        lines.append("<p class='empty'>(none)</p>")

    # Cross-type matches
    if cross_type_matches:
        lines.append(f"<h2>🔄 Cross-Type Matches <span class='section-count'>({len(cross_type_matches)})</span></h2>")
        lines.append("<table><tr><th>A Type</th><th>A Name</th><th>B Type</th><th>B Name</th><th>Similarity</th></tr>")
        for ct in cross_type_matches:
            lines.append(f"<tr><td>{h(ct['a_type'])}</td><td>{h(ct['a_name'] or '')}</td>"
                         f"<td>{h(ct['b_type'])}</td><td>{h(ct['b_name'] or '')}</td>"
                         f"<td>Name: {ct['name_sim']:.0%} Notes: {ct['notes_sim']:.0%}</td></tr>")
        lines.append("</table>")

    # Fuzzy matches
    if fuzzy_matches:
        lines.append(f"<h2>🔍 Fuzzy Matches <span class='section-count'>({len(fuzzy_matches)})</span></h2>")
        for a_id, b_id, score in fuzzy_matches:
            conf_cls = "conf-high" if score >= 0.8 else ("conf-med" if score >= 0.65 else "conf-low")
            it_a = items_a[a_id]
            it_b = items_b[b_id]
            changes = fuzzy_changes.get((a_id, b_id), {})
            lines.append(f"<details><summary>"
                         f"<span class='confidence {conf_cls}'>{score:.0%}</span> "
                         f"<b>{h(it_a.get('name',''))}</b>"
                         f"{' → <b>' + h(it_b.get('name','')) + '</b>' if it_a.get('name') != it_b.get('name') else ''}"
                         f" {_change_tags(changes)}</summary>")
            if changes:
                lines.append("<table><tr><th>Field</th><th>File A</th><th>File B</th></tr>")
                for field, vals in changes.items():
                    lines.append(f"<tr><td><code>{h(field)}</code></td>"
                                 f"<td class='diff-a'>{_html_field_val(vals['A'], field, show_full)}</td>"
                                 f"<td class='diff-b'>{_html_field_val(vals['B'], field, show_full)}</td></tr>")
                lines.append("</table>")
            else:
                lines.append("<p class='empty'>ID changed only, no field differences</p>")
            lines.append("</details>")

    # Changed items
    lines.append(f"<h2>📊 Changed Items (Same ID) <span class='section-count'>({len(id_matches_changed)})</span></h2>")
    if id_matches_changed:
        for iid, changes in id_matches_changed:
            name = items_b[iid].get("name", "")
            lines.append(f"<details><summary><b>{h(name)}</b> {_change_tags(changes)}</summary>")
            lines.append("<table><tr><th>Field</th><th>File A</th><th>File B</th></tr>")
            for field, vals in changes.items():
                lines.append(f"<tr><td><code>{h(field)}</code></td>"
                             f"<td class='diff-a'>{_html_field_val(vals['A'], field, show_full)}</td>"
                             f"<td class='diff-b'>{_html_field_val(vals['B'], field, show_full)}</td></tr>")
            lines.append("</table></details>")
    else:
        lines.append("<p class='empty'>(none)</p>")

    lines.append("</div></body></html>")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Compare two unencrypted Bitwarden JSON exports with intelligent matching.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python compare_bw_exports.py old.json new.json
  python compare_bw_exports.py old.json new.json --full
  python compare_bw_exports.py old.json new.json --html report.html
  python compare_bw_exports.py old.json new.json --full --html report.html --threshold 0.5
        """,
    )
    ap.add_argument("file_a", help="Older / baseline Bitwarden JSON export")
    ap.add_argument("file_b", help="Newer Bitwarden JSON export to compare")
    ap.add_argument("--full", action="store_true",
                    help="Show full sensitive values (passwords, TOTP secrets, card numbers)")
    ap.add_argument("--html", metavar="FILE",
                    help="Generate an HTML report at the specified path")
    ap.add_argument("--threshold", type=float, default=0.55,
                    help="Fuzzy match similarity threshold (0.0–1.0, default: 0.55)")
    args = ap.parse_args()

    # ── Load exports ──
    data_a, items_a, folders_a, dupes_a = load_export(args.file_a)
    data_b, items_b, folders_b, dupes_b = load_export(args.file_b)

    if dupes_a:
        print(yellow(f"⚠  File A has {len(dupes_a)} duplicate ID(s) — last occurrence kept"), file=sys.stderr)
    if dupes_b:
        print(yellow(f"⚠  File B has {len(dupes_b)} duplicate ID(s) — last occurrence kept"), file=sys.stderr)

    # ── Phase 1: ID-based matching ──
    ids_a = set(items_a.keys())
    ids_b = set(items_b.keys())
    common_ids = ids_a & ids_b
    only_a_ids = ids_a - ids_b
    only_b_ids = ids_b - ids_a

    # Diff items that share the same ID
    id_matches_changed = []
    id_matches_unchanged = 0
    for iid in sorted(common_ids, key=lambda x: (items_b[x].get("name") or "").lower()):
        changes = diff_items(items_a[iid], items_b[iid], folders_a, folders_b)
        if changes:
            id_matches_changed.append((iid, changes))
        else:
            id_matches_unchanged += 1

    # ── Phase 2: Fuzzy matching for unmatched items ──
    fuzzy_matches = find_fuzzy_matches(only_a_ids, only_b_ids, items_a, items_b, args.threshold)
    fuzzy_matched_a = {a for a, b, s in fuzzy_matches}
    fuzzy_matched_b = {b for a, b, s in fuzzy_matches}

    remaining_a = only_a_ids - fuzzy_matched_a
    remaining_b = only_b_ids - fuzzy_matched_b

    # Diff fuzzy-matched pairs
    fuzzy_changes = {}
    for a_id, b_id, score in fuzzy_matches:
        changes = diff_items(items_a[a_id], items_b[b_id], folders_a, folders_b)
        fuzzy_changes[(a_id, b_id)] = changes

    # ── Phase 3: Cross-type detection ──
    cross_type_matches = detect_cross_type_matches(remaining_a, remaining_b, items_a, items_b)
    cross_a = {ct["a_id"] for ct in cross_type_matches}
    cross_b = {ct["b_id"] for ct in cross_type_matches}

    true_only_a = remaining_a - cross_a
    true_only_b = remaining_b - cross_b

    # ── Phase 4: Folder comparison ──
    folder_only_a, folder_only_b, folder_renamed = diff_folders(folders_a, folders_b)

    # ── Print report ──
    total_diffs = print_report(
        args.file_a, args.file_b,
        items_a, items_b,
        folders_a, folders_b,
        dupes_a, dupes_b,
        true_only_a, true_only_b,
        id_matches_changed, id_matches_unchanged,
        fuzzy_matches, fuzzy_changes,
        cross_type_matches,
        folder_only_a, folder_only_b, folder_renamed,
        args.full,
    )

    # ── Optional HTML report ──
    if args.html:
        generate_html_report(
            args.file_a, args.file_b,
            items_a, items_b,
            folders_a, folders_b,
            true_only_a, true_only_b,
            id_matches_changed, id_matches_unchanged,
            fuzzy_matches, fuzzy_changes,
            cross_type_matches,
            folder_only_a, folder_only_b, folder_renamed,
            args.full,
            args.html,
        )
        print(f"\n{green('📄 HTML report saved to:')} {args.html}")

    sys.exit(0 if total_diffs == 0 else 1)


if __name__ == "__main__":
    main()
