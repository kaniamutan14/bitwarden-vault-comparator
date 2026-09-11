#!/usr/bin/env python3
"""Generate a read-only HTML report from a Bitwarden JSON export.

The input JSON is only read and is never modified. Passwords, TOTP secrets,
card numbers/CVVs, notes, custom-field values and other secret values are not
included in the report.

Usage:
  python bitwarden_vault_report.py bitwarden_export.json
  python bitwarden_vault_report.py bitwarden_export.json report.html
"""
from __future__ import annotations

import argparse
import html
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

TYPE_NAMES = {1: "Login", 2: "Secure Note", 3: "Card", 4: "Identity"}
MIN_DATE = datetime.min.replace(tzinfo=timezone.utc)


def esc(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


def parse_dt(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        return MIN_DATE
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return MIN_DATE


def fmt_dt(value: Any) -> str:
    dt = parse_dt(value)
    return "Unknown" if dt == MIN_DATE else dt.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def item_type(value: Any) -> str:
    try:
        return TYPE_NAMES.get(int(value), f"Unknown ({value})")
    except (TypeError, ValueError):
        return "Unknown"


def username(item: dict) -> str:
    login = item.get("login")
    return str(login.get("username") or "") if isinstance(login, dict) else ""


def urls(item: dict) -> list[str]:
    login = item.get("login")
    if not isinstance(login, dict) or not isinstance(login.get("uris"), list):
        return []
    out = []
    for entry in login["uris"]:
        if isinstance(entry, dict) and isinstance(entry.get("uri"), str):
            value = entry["uri"].strip()
            if value:
                out.append(value)
    return out


def domain(url: str) -> str:
    try:
        candidate = url if "://" in url else "https://" + url
        return (urlparse(candidate).hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


def href(url: str) -> str | None:
    try:
        p = urlparse(url)
        if p.scheme.lower() in {"http", "https"} and p.netloc:
            return esc(url)
    except ValueError:
        pass
    return None


def enrich(raw: list[dict], folder_map: dict[str, str]) -> list[dict]:
    out = []
    for x in raw:
        us = username(x)
        usls = urls(x)
        folder_id = x.get("folderId")
        folder = folder_map.get(str(folder_id), "(Unknown folder)") if folder_id else "(No folder)"
        out.append({
            "name": str(x.get("name") or "(Unnamed)"),
            "type": item_type(x.get("type")),
            "username": us,
            "urls": usls,
            "domain": domain(usls[0]) if usls else "",
            "folder": folder,
            "favorite": bool(x.get("favorite")),
            "revision": parse_dt(x.get("revisionDate")),
            "creation": parse_dt(x.get("creationDate")),
            "revision_display": fmt_dt(x.get("revisionDate")),
            "creation_display": fmt_dt(x.get("creationDate")),
        })
    return out


def duplicate_groups(items: list[dict]) -> list[list[dict]]:
    groups = defaultdict(list)
    for x in items:
        u, d = norm(x["username"]), norm(x["domain"])
        if u and d:
            groups[f"{u}|{d}"].append(x)
    return [g for g in groups.values() if len(g) > 1]


CSS = r'''\
:root{--bg:#f4f7fb;--surface:#fff;--surface2:#f8fafc;--border:#e2e8f0;--text:#0f172a;--muted:#64748b;--accent:#2563eb;--soft:#dbeafe;--shadow:0 10px 30px rgba(15,23,42,.08)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.45}.container{width:min(1500px,calc(100% - 32px));margin:28px auto 48px}
.header{background:linear-gradient(135deg,#0f172a,#1e3a8a);color:#fff;border-radius:18px;padding:28px 30px;box-shadow:var(--shadow);margin-bottom:18px}.header h1{margin:0 0 6px;font-size:clamp(24px,4vw,36px);letter-spacing:-.025em}.header p{margin:0;color:rgba(255,255,255,.78)}.notice{margin-top:16px;padding:11px 13px;border-radius:10px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.17);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:18px}.card,.panel{background:var(--surface);border:1px solid var(--border);box-shadow:var(--shadow)}.card{border-radius:14px;padding:16px}.card .value{font-size:27px;font-weight:750}.card .label{color:var(--muted);font-size:13px}
.panel{border-radius:16px;margin-bottom:18px;overflow:hidden}.panel-head{padding:17px 20px;border-bottom:1px solid var(--border)}.panel-head h2{margin:0;font-size:18px}.panel-body{padding:18px 20px}
.controls{display:grid;grid-template-columns:minmax(220px,2fr) repeat(5,minmax(140px,1fr));gap:10px;align-items:end}.field label{display:block;margin-bottom:6px;color:var(--muted);font-size:12px;font-weight:650;text-transform:uppercase;letter-spacing:.04em}.field input,.field select{width:100%;min-height:40px;border:1px solid var(--border);border-radius:9px;background:#fff;color:var(--text);padding:9px 11px;font:inherit}.button-row{display:flex;gap:10px;margin-top:11px;align-items:center}.button-row button{min-height:40px;border:1px solid var(--accent);border-radius:9px;background:var(--accent);color:#fff;padding:8px 12px;font-weight:700;cursor:pointer}
.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:980px}th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--border);padding:12px 14px}th{position:sticky;top:0;background:var(--surface2);color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.045em;z-index:1}tbody tr:hover{background:#f8fbff}.name{font-weight:700}.subtle{color:var(--muted);font-size:12px;margin-top:2px}.badge{display:inline-block;padding:3px 8px;border-radius:999px;background:var(--soft);color:#1e40af;font-size:12px;font-weight:700}.favorite{background:#fef3c7;color:#92400e;margin-left:5px}.url{display:block;max-width:390px;overflow-wrap:anywhere;color:var(--accent);text-decoration:none}.url:hover{text-decoration:underline}
.audit-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}.audit{border:1px solid var(--border);background:var(--surface2);border-radius:11px;padding:13px}.audit strong{display:block;font-size:21px}.audit span{color:var(--muted);font-size:12px}.duplicates{display:grid;gap:10px}.duplicate{border:1px solid var(--border);border-radius:11px;padding:12px 14px}.duplicate-title{font-weight:700;margin-bottom:4px}.empty{padding:28px 18px;text-align:center;color:var(--muted)}.footer{color:var(--muted);font-size:12px;text-align:center;margin-top:18px}
@media(max-width:1100px){.controls{grid-template-columns:repeat(2,minmax(150px,1fr))}.search{grid-column:1/-1}}@media(max-width:640px){.container{width:calc(100% - 18px);margin-top:10px}.header{padding:21px}.panel-body,.panel-head{padding:14px}.controls{grid-template-columns:1fr}.search{grid-column:auto}}
'''

JS = r'''\
const rows=[...document.querySelectorAll("#items tbody tr")];
const search=document.querySelector("#search"),type=document.querySelector("#type"),folder=document.querySelector("#folder"),recent=document.querySelector("#recent"),sort=document.querySelector("#sort"),order=document.querySelector("#order"),count=document.querySelector("#count"),reset=document.querySelector("#reset");
const n=v=>(v||"").toLowerCase().trim();
const date=row=>{const t=Date.parse(row.dataset.revision||"");return Number.isNaN(t)?-Infinity:t};
function sortRows(){const mode=sort.value,rev=order.value==="desc",tbody=document.querySelector("#items tbody");rows.sort((a,b)=>{if(mode==="modified")return(date(a)-date(b))*(rev?-1:1);const r=n(a.dataset[mode]||"").localeCompare(n(b.dataset[mode]||""),undefined,{numeric:true});return rev?-r:r});rows.forEach(r=>tbody.appendChild(r))}
function filterRows(){const q=n(search.value),t=type.value,f=folder.value,r=Number(recent.value||0),cutoff=r?Date.now()-r*86400000:0;let shown=0;rows.forEach(row=>{const ok=(!q||n(row.dataset.search).includes(q))&&(!t||row.dataset.type===t)&&(!f||row.dataset.folder===f)&&(!r||date(row)>=cutoff);row.style.display=ok?"":"none";if(ok)shown++});count.textContent=`${shown.toLocaleString()} of ${rows.length.toLocaleString()} items shown`}
[search,type,folder,recent].forEach(x=>x.addEventListener("input",filterRows));[sort,order].forEach(x=>x.addEventListener("change",()=>{sortRows();filterRows()}));reset.addEventListener("click",()=>{search.value="";type.value="";folder.value="";recent.value="";sort.value="modified";order.value="desc";sortRows();filterRows()});sortRows();filterRows();
'''


def row_html(x: dict) -> str:
    links=[]
    for u in x["urls"]:
        h=href(u); s=esc(u)
        links.append(f'<a class="url" href="{h}" target="_blank" rel="noopener noreferrer">{s}</a>' if h else f'<span class="url">{s}</span>')
    url_html="".join(links) or '<span class="subtle">—</span>'
    fav='<span class="badge favorite">★ Favorite</span>' if x["favorite"] else ''
    blob=" ".join([x["name"],x["username"],x["folder"],x["type"]," ".join(x["urls"]),x["domain"]])
    rd=x["revision"].isoformat() if x["revision"]!=MIN_DATE else ''
    cd=x["creation"].isoformat() if x["creation"]!=MIN_DATE else ''
    return f'''<tr data-name="{esc(x['name'])}" data-username="{esc(x['username'])}" data-folder="{esc(x['folder'])}" data-type="{esc(x['type'])}" data-created="{esc(cd)}" data-revision="{esc(rd)}" data-search="{esc(blob)}"><td class="name">{esc(x['name'])}{fav}</td><td><span class="badge">{esc(x['type'])}</span></td><td>{esc(x['username']) or '<span class="subtle">—</span>'}</td><td>{url_html}</td><td>{esc(x['folder'])}</td><td>{esc(x['revision_display'])}<div class="subtle">Created: {esc(x['creation_display'])}</div></td></tr>'''


def make_html(items: list[dict], dupes: list[list[dict]], source_name: str) -> str:
    counts=Counter(x["type"] for x in items); domains=Counter(x["domain"] for x in items if x["domain"])
    folders=sorted({x["folder"] for x in items},key=str.casefold)
    favorites=sum(x["favorite"] for x in items); no_user=sum(not x["username"] for x in items); no_url=sum(not x["urls"] for x in items); no_folder=sum(x["folder"]=="(No folder)" for x in items); no_revision=sum(x["revision"]==MIN_DATE for x in items)
    recent30=sum(x["revision"]!=MIN_DATE and x["revision"]>=datetime.now(timezone.utc)-timedelta(days=30) for x in items)
    type_opts=''.join(f'<option value="{esc(t)}">{esc(t)} ({counts[t]})</option>' for t in sorted(counts,key=str.casefold))
    folder_opts=''.join(f'<option value="{esc(f)}">{esc(f)}</option>' for f in folders)
    rows=''.join(row_html(x) for x in items)
    dup_html=''
    for g in dupes:
        first=g[0]; title=f"{first['username']} @ {first['domain']}"; members=''.join(f'<div>{esc(x["name"])}<span class="subtle"> — {esc(x["revision_display"])}</span></div>' for x in g)
        dup_html+=f'<div class="duplicate"><div class="duplicate-title">{esc(title)}</div>{members}</div>'
    if not dup_html: dup_html='<div class="empty">No likely duplicates detected.</div>'
    domain_cards=''.join(f'<div class="audit"><strong>{c}</strong><span>{esc(d)}</span></div>' for d,c in domains.most_common(12)) or '<div class="empty">No website domains found.</div>'
    summary=' · '.join(f'{esc(k)}: {v}' for k,v in sorted(counts.items(),key=lambda z:z[0].casefold()))
    generated=datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Bitwarden Vault Report</title><style>{CSS}</style></head><body><div class="container">
<header class="header"><h1>Bitwarden Vault Report</h1><p>Read-only report from <strong>{esc(source_name)}</strong></p><div class="notice">Passwords, TOTP secrets, card numbers, security codes, notes, custom-field values and other secret values are intentionally excluded.</div></header>
<section class="cards"><div class="card"><div class="value">{len(items):,}</div><div class="label">Total items</div></div><div class="card"><div class="value">{favorites:,}</div><div class="label">Favorites</div></div><div class="card"><div class="value">{recent30:,}</div><div class="label">Modified in last 30 days</div></div><div class="card"><div class="value">{len(dupes):,}</div><div class="label">Possible duplicate groups</div></div><div class="card"><div class="value">{len(domains):,}</div><div class="label">Unique domains</div></div><div class="card"><div class="value">{no_revision:,}</div><div class="label">Missing modification date</div></div></section>
<section class="panel"><div class="panel-head"><h2>Vault items</h2></div><div class="panel-body"><div class="controls">
<div class="field search"><label for="search">Search</label><input id="search" type="search" placeholder="Name, username, URL, folder..."></div>
<div class="field"><label for="type">Type</label><select id="type"><option value="">All types</option>{type_opts}</select></div>
<div class="field"><label for="folder">Folder</label><select id="folder"><option value="">All folders</option>{folder_opts}</select></div>
<div class="field"><label for="recent">Modified</label><select id="recent"><option value="">Any date</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="90">Last 90 days</option><option value="365">Last year</option></select></div>
<div class="field"><label for="sort">Sort by</label><select id="sort"><option value="modified">Modified date</option><option value="created">Creation date</option><option value="name">Name</option><option value="username">Username</option><option value="type">Type</option></select></div>
<div class="field"><label for="order">Order</label><select id="order"><option value="desc">Newest / Z → A</option><option value="asc">Oldest / A → Z</option></select></div>
</div><div class="button-row"><button id="reset">Reset filters</button><span id="count" class="subtle"></span></div></div>
<div class="table-wrap"><table id="items"><thead><tr><th>Name</th><th>Type</th><th>Username</th><th>URL</th><th>Folder</th><th>Modified</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section class="panel"><div class="panel-head"><h2>Vault audit</h2></div><div class="panel-body"><div class="audit-grid"><div class="audit"><strong>{no_user:,}</strong><span>Items missing username</span></div><div class="audit"><strong>{no_url:,}</strong><span>Items missing URL</span></div><div class="audit"><strong>{no_folder:,}</strong><span>Items without a folder</span></div><div class="audit"><strong>{no_revision:,}</strong><span>Items missing modification date</span></div></div></div></section>
<section class="panel"><div class="panel-head"><h2>Possible duplicates</h2></div><div class="panel-body"><p class="subtle">Heuristic: multiple items sharing the same username and website domain. Some matches may be intentional.</p><div class="duplicates">{dup_html}</div></div></section>
<section class="panel"><div class="panel-head"><h2>Top domains</h2></div><div class="panel-body"><div class="audit-grid">{domain_cards}</div></div></section>
<section class="panel"><div class="panel-head"><h2>Item summary</h2></div><div class="panel-body"><span class="subtle">{summary}</span></div></section>
<div class="footer">Generated {esc(generated)} · This HTML contains vault metadata only and never displays passwords.</div></div><script>{JS}</script></body></html>'''


def main() -> None:
    parser=argparse.ArgumentParser(description="Generate a read-only HTML report from a Bitwarden JSON export.")
    parser.add_argument("input",type=Path,help="Bitwarden JSON export")
    parser.add_argument("output",type=Path,nargs="?",help="HTML output (default: <input>_report.html)")
    args=parser.parse_args()
    source=args.input.expanduser().resolve()
    if not source.is_file(): raise SystemExit(f"Error: file does not exist: {source}")
    output=args.output.expanduser().resolve() if args.output else source.with_name(source.stem+"_report.html")
    if output==source: raise SystemExit("Error: output HTML path must be different from the original JSON export.")
    try:
        with source.open("r",encoding="utf-8") as f: data=json.load(f)
    except json.JSONDecodeError as e: raise SystemExit(f"Error: invalid JSON: {e}")
    if not isinstance(data,dict) or not isinstance(data.get("items"),list): raise SystemExit('Error: top-level "items" array not found; this may not be a Bitwarden JSON export.')
    folder_map={str(x.get("id")):str(x.get("name") or "(Unnamed folder)") for x in (data.get("folders") or []) if isinstance(x,dict) and x.get("id")}
    items=enrich([x for x in data["items"] if isinstance(x,dict)],folder_map)
    # Newest modification first by default.
    items.sort(key=lambda x:x["revision"],reverse=True)
    dupes=duplicate_groups(items)
    output.write_text(make_html(items,dupes,source.name),encoding="utf-8")
    counts=Counter(x["type"] for x in items)
    print(f"\nBitwarden HTML report created\n{'='*34}")
    print(f"Source : {source}\nOutput : {output}\nItems  : {len(items):,}\nPossible duplicate groups: {len(dupes):,}")
    print("\n"+"\n".join(f"{k:16} {v:,}" for k,v in sorted(counts.items(),key=lambda z:z[0].casefold())))
    print("\nThe original JSON was not modified. Secret values were not included.")


if __name__ == "__main__":
    main()
