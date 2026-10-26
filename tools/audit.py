#!/usr/bin/env python3
"""Static audits for the AutoTrack WinUI shell — the gate that runs BEFORE
the smoke launch (tools/release.ps1). Catches, at rest, the two shipped
regression classes:

  1. resource-key mismatches: every {StaticResource X}/{ThemeResource X}
     referenced by any XAML in App/ must be defined in the app's resource
     dictionaries, AND appear in SelfTest.Keys (so the runtime sweep covers
     it). v2026.10.26.4 shipped a deleted definition past `dotnet build`.
  2. parse-time-firing XAML attributes (IsChecked="True", SelectedIndex,
     IsExpanded, IsDropDownOpen): these fire handlers DURING
     InitializeComponent while later-declared elements are still null.
     Allowed only when the wired handler null-guards (v2026.10.26.2).

Exit 0 = clean; nonzero prints findings. Stdlib only.
"""
import re
import sys
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "App"
import sys as _sys
if len(_sys.argv) > 1:            # audit another repo: audit.py <app-root>
    APP = Path(_sys.argv[1]).resolve()

# keys provided by WinUI/XamlControlsResources — not ours to define
BUILTIN_KEYS = set()

def xaml_files():
    return [p for p in APP.rglob("*.xaml") if "obj" not in p.parts and "bin" not in p.parts]

def main():
    problems = []

    used = {}      # key -> [file:line]
    defined = set()
    for p in xaml_files():
        text = p.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            for m in re.finditer(r"\{(?:StaticResource|ThemeResource)\s+([A-Za-z0-9_]+)\}", line):
                used.setdefault(m.group(1), []).append(f"{p.name}:{i}")
        for m in re.finditer(r'x:Key="([A-Za-z0-9_]+)"', text):
            defined.add(m.group(1))

    for key, sites in sorted(used.items()):
        if key in BUILTIN_KEYS:
            continue
        if key not in defined:
            problems.append(f"undefined resource key '{key}' used at {', '.join(sites)}")

    # SelfTest coverage: every app-defined key we USE must be in SelfTest.Keys
    # (repos without a SelfTest yet report a finding per key instead of crashing)
    st_path = APP / "SelfTest.cs"
    selftest = st_path.read_text(encoding="utf-8") if st_path.exists() else ""
    for key in sorted(used):
        if key in BUILTIN_KEYS or key not in defined:
            continue
        if not selftest:
            problems.append(f"key '{key}': no SelfTest.cs in this app — runtime sweep unavailable")
        elif f'"{key}"' not in selftest:
            problems.append(f"key '{key}' used in XAML but missing from SelfTest.Keys (runtime sweep gap)")

    # parse-time-firing attributes: allowed only with a null-guarded handler
    parse_attr = re.compile(r'\b(IsChecked|IsSelected|SelectedIndex|IsExpanded|IsDropDownOpen)="(?:True|true|[1-9])"')
    event_attr = re.compile(r'\b(Checked|Unchecked|SelectionChanged|Expanded)="([A-Za-z0-9_]+)"')
    for p in xaml_files():
        text = p.read_text(encoding="utf-8")
        lines = text.splitlines()
        hits = [(i, parse_attr.search(l).group(1)) for i, l in enumerate(lines, 1) if parse_attr.search(l)]
        if not hits:
            continue
        handlers = {m.group(2) for m in event_attr.finditer(text)}
        cs = p.with_suffix(".xaml.cs")
        cs_text = cs.read_text(encoding="utf-8") if cs.exists() else ""
        for h in handlers:
            m = re.search(r"void\s+" + h + r"\s*\([^)]*\)\s*\{(.*?)\n        \}", cs_text, re.S)
            body = m.group(1) if m else ""
            if "== null" not in body and "is null" not in body:
                for i, attr in hits:
                    problems.append(
                        f"{p.name}:{i} '{attr}=True' fires at parse time but handler "
                        f"{h} has no null guard (see v2026.10.26.2)")

    if problems:
        print("AUDIT FAIL")
        for pr in problems:
            print("  -", pr)
        return 1
    print(f"AUDIT PASS ({len(used)} resource keys checked, parse-time attributes clean)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
