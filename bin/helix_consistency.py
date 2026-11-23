"""Helix UI consistency module: runtime fingerprints (rendered pages), static code scan (Svelte/React/Vue),
design contract (design-contract.yaml) + baseline/ratchet gate. Reports in Polish.
Used by bin/helix: `helix consistency scan|code|all|report|propose|baseline`, `helix gate consistency [cpN]`.
`H` is the helix module (set by bin/helix)."""
import colorsys, datetime as dt, hashlib, html, json, math, os, re, subprocess, sys
from collections import Counter, defaultdict
from pathlib import Path
from helix_paths import normalize, relative as relative_path, within, summarize

H = None                                    # injected by bin/helix
BIN = Path(__file__).resolve().parent
CS_JS = BIN / "consistency.cjs"

DEFAULT_CS = {
    "base_url": None,                       # default: ux.base_url
    "storage_state": None,                  # default: ux.storage_state
    "allow_hosts": [],
    "pages": None,                          # default: ux.pages. Extra keys: area, state, actions, probe_details, row_selector, base_url, targets
    "targets": [{"id": "desktop", "kind": "desktop", "viewport": [1440, 900]},
                {"id": "telefon", "kind": "phone", "pw_device": "iPhone 13"}],
    "settle_ms": None,                      # None: scanner defaults (700 ms scan / 900 ms probe)
    "contract": "design-contract.yaml",
    "baseline": "design-baseline.json",
    "static": {"paths": None,                # auto: nested src/app/pages roots, including monorepos
               "extensions": [".svelte", ".tsx", ".jsx", ".vue"],
               "component_dirs": None,       # default: auto (**/components/ui, **/components/common, **/components/shared)
               "backend_paths": [],          # e.g. ["apps/api"]: English user-facing error strings (HTTPException detail=...)
               "exclude": ["node_modules", ".svelte-kit", "dist", "build", ".next", "coverage", "tests", "test", "__tests__", "e2e"]},
    "tolerances": {"fs": 2.0, "fw": 200, "radius": 4.0, "pad": 4.0, "h": 6.0, "lh": 4.0, "ls": 0.6, "bw": 1.0, "de": 12.0, "icon": 4.0},
    "min_token_share": 0.04,                 # values used by < 4% of instances (and not in contract) are off-scale candidates
    "gate": {"fail_on": ["high", "medium"]}, # severities of NEW findings that fail `helix gate consistency`
    "top": 10,
}
def cfg(ctx):
    c = H.deep_merge(DEFAULT_CS, ctx.cfg.get("consistency") or {})
    ux = ctx.cfg.get("ux") or {}
    for k in ("base_url", "storage_state", "pages"):
        if c.get(k) is None: c[k] = ux.get(k)
    if not c.get("allow_hosts"): c["allow_hosts"] = ux.get("allow_hosts") or []
    return c

# ---------------------------------------------------------------- YAML (PyYAML or js-yaml; tiny emitter for writing)
def load_yaml(path):
    path = Path(path); t = path.read_text()
    if path.suffix == ".json": return json.loads(t)
    from helix_dependencies import load_yaml as parse
    return parse(path)

def _yscalar(v):
    if v is None: return "null"
    if isinstance(v, bool): return "true" if v else "false"
    if isinstance(v, (int, float)): return str(v)
    s = str(v)
    if s == "" or re.search(r"[:#\[\]{},&*!|>'\"%@`]|^\s|\s$|^[-?]|^(true|false|null|yes|no|on|off|~)$|^[\d.+-]+$", s, re.I): return json.dumps(s, ensure_ascii=False)
    return s
def dump_yaml(d, ind=0, comments=None):
    """Minimal YAML emitter (dict/list/scalars). comments: {key: '# ...'} appended to top-level keys."""
    sp = "  " * ind; out = []
    if isinstance(d, dict):
        for k, v in d.items():
            c = f"  # {comments[k]}" if comments and k in comments else ""
            if isinstance(v, (dict, list)) and v:
                if isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v) and len(json.dumps(v, ensure_ascii=False)) < 110:
                    out.append(f"{sp}{_yscalar(k)}: [{', '.join(_yscalar(x) for x in v)}]{c}")
                else: out.append(f"{sp}{_yscalar(k)}:{c}"); out.append(dump_yaml(v, ind + 1))
            else: out.append(f"{sp}{_yscalar(k)}: {_yscalar(v) if not isinstance(v, (dict, list)) else ('{}' if isinstance(v, dict) else '[]')}{c}")
    elif isinstance(d, list):
        for v in d:
            if isinstance(v, dict) and v:
                sub = dump_yaml(v, ind + 1).split("\n"); out.append(f"{sp}- {sub[0].lstrip()}"); out += sub[1:]
            elif isinstance(v, list) and v: out.append(f"{sp}-"); out.append(dump_yaml(v, ind + 1))
            else: out.append(f"{sp}- {_yscalar(v)}")
    return "\n".join(x for x in out if x != "")

# ---------------------------------------------------------------- colours
def parse_color(c):
    if not c: return None
    c = c.strip().lower()
    m = re.match(r"rgba?\(([^)]+)\)", c)
    if m:
        p = [x for x in re.split(r"[\s,/]+", m.group(1)) if x]
        v = [float(x.rstrip('%')) * (2.55 if x.endswith('%') else 1) for x in p[:3]]; a = float(p[3]) if len(p) > 3 else 1.0
        return (v[0], v[1], v[2], a)
    m = re.match(r"#([0-9a-f]{3,8})$", c)
    if m:
        h = m.group(1)
        if len(h) in (3, 4): h = "".join(ch * 2 for ch in h)
        a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), a)
    if c in ("white",): return (255, 255, 255, 1.0)
    if c in ("black",): return (0, 0, 0, 1.0)
    if c == "transparent": return (0, 0, 0, 0.0)
    return None
def _lab(rgb):
    def lin(u): u /= 255; return u / 12.92 if u <= 0.04045 else ((u + 0.055) / 1.055) ** 2.4
    r, g, b = (lin(x) for x in rgb[:3])
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047; y = 0.2126 * r + 0.7152 * g + 0.0722 * b; z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883
    f = lambda t: t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116
    return (116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z)))
def blend(c, bg=(255, 255, 255)):
    if not c: return None
    a = c[3]; return tuple(c[i] * a + bg[i] * (1 - a) for i in range(3)) + (1.0,)
def delta_e(a, b):
    """CIE76 ΔE on colours composited over white (alpha matters). None if unparsable."""
    ca, cb = parse_color(a) if isinstance(a, str) else a, parse_color(b) if isinstance(b, str) else b
    if ca is None or cb is None: return None
    if ca[3] < 0.04 and cb[3] < 0.04: return 0.0
    la, lb = _lab(blend(ca)), _lab(blend(cb)); return math.sqrt(sum((x - y) ** 2 for x, y in zip(la, lb)))
def hexof(c):
    p = parse_color(c) if isinstance(c, str) else c
    if not p: return str(c)
    if p[3] < 0.04: return "transparent"
    s = "#%02x%02x%02x" % tuple(int(round(x)) for x in p[:3]); return s + ("" if p[3] > 0.99 else f"/{p[3]:.2f}")

# ---------------------------------------------------------------- fingerprints
ROLE_PROPS = {
    "button":   ["fs", "fw", "ff", "radius", "h", "pt", "pr", "pb", "pl", "bg", "color", "bw", "bc", "tt", "ls", "shadow"],
    "input":    ["fs", "fw", "ff", "radius", "h", "pl", "pr", "bg", "color", "bw", "bc", "shadow"],
    "select":   ["fs", "fw", "ff", "radius", "h", "pl", "pr", "bg", "color", "bw", "bc", "shadow"],
    "checkbox": ["radius", "h", "w", "bw", "bc", "bg"],
    "badge":    ["fs", "fw", "radius", "h", "pt", "pr", "pb", "pl", "bg", "color", "bw", "bc", "tt", "ls"],
    "heading":  ["fs", "fw", "ff", "lh", "color", "tt", "ls"],
    "alert":    ["fs", "radius", "pt", "pl", "bw", "bg", "color"],
    "card":     ["radius", "bw", "bc", "shadow", "bg", "pt", "pl"],
    "table":    ["th.fs", "th.fw", "th.tt", "th.color", "th.bg", "th.ls", "td.fs", "td.pl", "td.pt", "row_h"],
    "icon":     ["w", "h", "set"],
    "state":    ["fs", "fw", "color", "icon"],
}
COLOR_PROPS = {"bg", "color", "bc", "th.color", "th.bg"}
CATEGORICAL = {"ff", "tt", "shadow", "set", "icon", "th.tt"}
PROP_PL = {"fs": "rozmiar tekstu", "fw": "grubość tekstu", "ff": "krój", "radius": "zaokrąglenie", "h": "wysokość", "w": "szerokość",
           "pt": "padding góra", "pr": "padding prawo", "pb": "padding dół", "pl": "padding lewo", "bg": "tło", "color": "kolor tekstu",
           "bw": "grubość ramki", "bc": "kolor ramki", "tt": "wielkość liter", "ls": "odstęp liter", "shadow": "cień", "lh": "interlinia",
           "set": "zestaw ikon", "icon": "ikona", "th.fs": "nagłówek tabeli: rozmiar", "th.fw": "nagłówek tabeli: grubość", "th.tt": "nagłówek tabeli: wielkość liter",
           "th.color": "nagłówek tabeli: kolor", "th.bg": "nagłówek tabeli: tło", "th.ls": "nagłówek tabeli: odstęp liter", "td.fs": "komórka: rozmiar",
           "td.pl": "komórka: padding", "td.pt": "komórka: padding góra", "row_h": "wysokość wiersza"}
ROLE_PL = {"button": "przycisk", "input": "pole tekstowe", "select": "lista wyboru", "checkbox": "checkbox/przełącznik", "badge": "plakietka/status",
           "heading": "nagłówek", "alert": "komunikat", "card": "karta", "table": "tabela", "icon": "ikona", "state": "stan pusty/ładowanie/błąd",
           "dialog": "okno/szuflada", "link": "link"}

def getp(c, p):
    if p.startswith("th.") or p.startswith("td."):
        s = c.get(p[:2]) or {}; v = s.get(p[3:])
    elif p == "row_h": v = c.get("row_h")
    elif p == "set": v = (c.get("icon") or {}).get("set") if c["role"] != "icon" else _icon_self(c).get("set")
    elif p == "icon": v = bool(c.get("icon"))
    elif p in ("w", "h") and c["role"] == "icon": v = _icon_self(c).get(p)
    else: v = (c.get("style") or {}).get(p)
    if p in COLOR_PROPS and isinstance(v, str): v = hexof(v)
    if p == "ls" and isinstance(v, str): v = 0.0 if v == "normal" else float(re.sub(r"[^\d.-]", "", v) or 0)
    if p == "radius" and isinstance(v, (int, float)) and v >= 999: v = "pill"
    if isinstance(v, float): v = round(v * 2) / 2
    return v
def _icon_self(c): return c.get("icon") or {"w": c["style"].get("w"), "h": c["style"].get("h"), "set": None}

def fingerprint(c):
    return tuple((p, getp(c, p)) for p in ROLE_PROPS.get(c["role"], []))
def fp_hash(role, variant, fp): return hashlib.sha1(json.dumps([role, variant, fp], ensure_ascii=False, default=str).encode()).hexdigest()[:10]

def prop_delta(p, a, b, tol):
    """returns (equal, near, text) for one property."""
    if a == b: return True, True, ""
    if a is None or b is None: return False, False, f"{a} ↔ {b}"
    if p in COLOR_PROPS:
        d = delta_e(a, b)
        if d is None: return False, False, f"{a} ↔ {b}"
        if d < 2.0: return True, True, ""
        return False, d <= tol["de"], f"{a} ↔ {b} (ΔE {d:.1f})"
    if p in CATEGORICAL or isinstance(a, str) or isinstance(b, str): return False, True, f"{a} ↔ {b}"
    d = abs(float(a) - float(b))
    lim = {"fs": tol["fs"], "th.fs": tol["fs"], "td.fs": tol["fs"], "fw": tol["fw"], "th.fw": tol["fw"], "radius": tol["radius"], "h": tol["h"], "w": tol["h"], "row_h": tol["h"],
           "lh": tol["lh"], "ls": tol["ls"], "th.ls": tol["ls"], "bw": tol["bw"]}.get(p, tol["pad"])
    eq = d < (0.26 if p.endswith("fs") or p.endswith("ls") else 1.01 if p in ("h", "w", "row_h") else 0.51)
    if eq: return True, True, ""
    unit = "" if p.endswith("fw") else "px"
    return False, d <= lim, f"{a:g}{unit} ↔ {b:g}{unit}"

def compare(fa, fb, tol, role=None):
    """near-duplicate test of two fingerprints: returns (near, diffs[(prop, text)]). near = >=1 diff and all diffs tiny."""
    diffs, near, cat = [], True, 0
    for (p, a), (_, b) in zip(fa, fb):
        eq, nr, t = prop_delta(p, a, b, tol)
        if eq: continue
        diffs.append((p, t)); near = near and nr; cat += p in CATEGORICAL
    # heights follow padding/font: do not count h alone as a second difference
    core = [d for d in diffs if d[0] not in ("h", "w")]
    if not core and diffs: core = diffs
    return (bool(diffs) and near and cat <= 1 and len(core) <= 4), diffs

# ---------------------------------------------------------------- findings
SEV_W = {"high": 3, "medium": 2, "low": 1}
def finding(rule, severity, title, key, *, layer="runtime", detail="", where=None, examples=None, canonical=None, observed=None,
            suggestion=None, area=None, count=None, confidence="VERIFIED"):
    return {"rule": rule, "severity": severity, "title": title, "key": key, "layer": layer, "detail": detail, "where": where or [],
            "examples": examples or [], "canonical": canonical, "observed": observed, "suggestion": suggestion, "area": area,
            "count": count, "confidence": confidence, "status": "open"}
def ex(r, c, lab=None):
    return {"label": lab or f"{r['page']}{'#' + r['state'] if r.get('state', 'base') != 'base' else ''} @ {r['target']}", "shot": r.get("shot"),
            "rect": c.get("rect"), "dpr": r.get("dpr", 1), "page": r["page"], "state": r.get("state"), "target": r["target"], "sel": c.get("sel"), "text": c.get("label"), "src": c.get("src")}
def pages_of(items): return sorted({f"{r['page']}{'#' + r['state'] if r.get('state', 'base') != 'base' else ''}" for r, _ in items})
def norm_label(s): return re.sub(r"\s+", " ", re.sub(r"[^\w\sąćęłńóśźż]", " ", (s or "").lower())).strip()
def where_s(items, n=4): return ", ".join(pages_of(items)[:n]) + (" …" if len(pages_of(items)) > n else "")

SHARED_SRC = re.compile(r"(^|/)components/(ui|common|shared|primitives|design-system)/")
def shared_share(items): return sum(1 for _, c in items if SHARED_SRC.search(c.get("src") or "")) / max(1, len(items))
def srcs(items, n=3):
    v = sorted({(c.get("src") or "").rsplit(":", 1)[0] for _, c in items if c.get("src")}); return v[:n]
def ident(items):
    """stable identity of an outlier for the ratchet: its source files (dev build) or pages+label; never raw CSS values."""
    s = srcs(items, 6)
    return "src=" + "|".join(s) if s else "pages=" + "|".join(pages_of(items)) + "/" + norm_label(items[0][1].get("label"))[:30]
def src_note(items):
    s = sorted({c.get("src") for _, c in items if c.get("src")})
    return f" Źródło odstępstwa: {', '.join(s[:4])}." if s else ""
def ctx_bucket(c): return {"header": "nav", "footer": "nav", "nav": "nav"}.get(c.get("ctx"), c.get("ctx") or "main")
def canon_key(fps):
    """pattern choice: rendered by a shared component first (contract anchor), then spread over pages, then count. Majority only as fallback."""
    return lambda f: (-shared_share(fps[f]), -len(pages_of(fps[f])), -len(fps[f]))
def results_ok(raw): return [r for r in raw["results"] if r.get("ok") and r.get("components") is not None]

def analyze_components(raw, tol):
    F, res = [], results_ok(raw)
    groups = defaultdict(list)
    for r in res:
        for c in r["components"]:
            if c["role"] in ROLE_PROPS and c["role"] != "icon":
                v = c.get("variant") if c["role"] != "heading" else f"{c.get('variant')}/{c.get('ctx')}"
                groups[(c["role"], v, r["kind"])].append((r, c))
    pair_done = set()
    # 1) same label, different look (strongest signal: one action, two renderings)
    by_label = defaultdict(list)
    for r in res:
        for c in r["components"]:
            if c["role"] == "button" and len(norm_label(c.get("label"))) >= 3 and not re.search(r"[↕↑↓]", c.get("label") or ""):
                by_label[(norm_label(c["label"]), c.get("variant"), r["kind"] + ("" if ctx_bucket(c) == "main" else "/" + ctx_bucket(c)))].append((r, c))
    for (lab, var, kind), items in by_label.items():
        fps = defaultdict(list)
        for r, c in items: fps[fingerprint(c)].append((r, c))
        if len(fps) < 2: continue
        ranked = sorted(fps, key=canon_key(fps))
        for f in ranked[1:]:
            g = ranked[0]; near, diffs = compare(f, g, tol)
            if not diffs: continue
            if kind.endswith("/nav") and {p for p, _ in diffs} <= {"fw", "color", "bg", "bc"}: continue   # active/current nav item styling, not drift
            pair_done.add((f, g))
            dtext = "; ".join(f"{PROP_PL.get(p, p)}: {t}" for p, t in diffs[:6])
            F.append(finding("same-label-different-style", "high" if near else "medium",
                             f"Przycisk „{items[0][1]['label'][:40]}” wygląda inaczej ({kind})", f"rt:label:{lab}:{var}:{kind}:{ident(fps[f])}",
                             detail=f"Wzorzec: {where_s(fps[g])} ({len(fps[g])}×{', wspólny komponent' if shared_share(fps[g]) > 0.5 else ''}). Odstępstwo: {where_s(fps[f])} ({len(fps[f])}×). Różnice: {dtext}.{src_note(fps[f])}",
                             examples=[ex(*fps[g][0], "wzorzec: " + ex(*fps[g][0])["label"]), ex(*fps[f][0], "odstępstwo: " + ex(*fps[f][0])["label"])],
                             canonical={p: v for p, v in g}, observed={p: v for p, v in f}, area=fps[f][0][0].get("area"), count=len(fps[f]),
                             suggestion="Ten sam przycisk = ten sam komponent i wariant (Button variant/size)."))
    # 2) near-duplicates within role+variant (tiny deltas = accident, not a design decision)
    for (role, var, kind), items in groups.items():
        fps = defaultdict(list)
        for r, c in items: fps[fingerprint(c)].append((r, c))
        if len(fps) < 2: continue
        ranked = sorted(fps, key=canon_key(fps))
        for i, f in enumerate(ranked[1:], 1):
            for g in ranked[:i]:
                if (f, g) in pair_done: break
                near, diffs = compare(f, g, tol, role)
                if not near: continue
                ps = {p for p, _ in diffs}
                size_variant = role in ("button", "input", "select", "badge") and any(p == "h" and abs(float(dict(f)["h"] or 0) - float(dict(g)["h"] or 0)) >= 4 for p, _ in diffs) and ps <= {"h", "w", "pt", "pb", "pl", "pr", "fs", "fw"}
                dtext = "; ".join(f"{PROP_PL.get(p, p)}: {t}" for p, t in diffs[:6])
                derived_only = ps <= {"h", "w", "row_h"}
                sev = "low" if size_variant or derived_only else "medium"
                title = (f"{ROLE_PL.get(role, role).capitalize()} ({var}, {kind}): prawie taki sam jak wzorzec" if not size_variant else
                         f"{ROLE_PL.get(role, role).capitalize()} ({var}, {kind}): możliwy osobny rozmiar")
                F.append(finding("near-duplicate" if not size_variant else "size-variant", sev, title, f"rt:{'near' if not size_variant else 'size'}:{role}:{var}:{kind}:{ident(fps[f])}",
                                 detail=f"Różnice: {dtext}. Wzorzec: {where_s(fps[g])} ({len(fps[g])}×, np. „{fps[g][0][1].get('label', '')[:30]}”). "
                                        f"Odstępstwo: {where_s(fps[f])} ({len(fps[f])}×, np. „{fps[f][0][1].get('label', '')[:30]}”).{src_note(fps[f])}",
                                 examples=[ex(*fps[g][0], "wzorzec: " + ex(*fps[g][0])["label"]), ex(*fps[f][0], "odstępstwo: " + ex(*fps[f][0])["label"])],
                                 canonical={p: v for p, v in g}, observed={p: v for p, v in f}, area=fps[f][0][0].get("area"), count=len(fps[f]),
                                 suggestion=("Zadeklaruj rozmiary w design-contract.yaml (components.%s.sizes) albo ujednolić." % role) if size_variant else
                                            "Ujednolić do wzorca (najczęstszy wariant) albo zadeklarować jako wyjątek w kontrakcie."))
                break
    # 3) icon present / absent and icon size for the same label
    lab_icons = defaultdict(list)
    for r in res:
        for c in r["components"]:
            if c["role"] in ("button", "link") and len(norm_label(c.get("label"))) >= 3 and not re.search(r"\d{3,}", c.get("label") or ""):
                lab_icons[(norm_label(c["label"]), r["kind"], "nav" if c.get("ctx") in ("nav", "header", "footer") else c.get("ctx"))].append((r, c))
    for (lab, kind, _ctx), items in lab_icons.items():
        w = [x for x in items if x[1].get("icon")]; wo = [x for x in items if not x[1].get("icon")]
        if w and wo and len(pages_of(items)) >= 1 and (len(pages_of(w)) + len(pages_of(wo)) >= 2 or len(items) >= 2):
            maj, mino = (w, wo) if len(pages_of(w)) >= len(pages_of(wo)) else (wo, w)
            F.append(finding("icon-presence", "medium", f"„{items[0][1]['label'][:40]}”: raz z ikoną, raz bez ({kind})", f"rt:icon:{lab}:{kind}:{_ctx}:{'with' if mino is w else 'without'}",
                             detail=f"Z ikoną: {where_s(w)} ({len(w)}×). Bez ikony: {where_s(wo)} ({len(wo)}×).",
                             examples=[ex(*maj[0], "wzorzec: " + ex(*maj[0])["label"]), ex(*mino[0], "odstępstwo: " + ex(*mino[0])["label"])], count=len(mino),
                             suggestion="Ta sama akcja: ta sama ikona (albo wszędzie bez)."))
        sizes = Counter((x[1]["icon"]["w"], x[1]["icon"]["h"]) for x in w)
        if len(sizes) > 1 and max(abs(a[0] - b[0]) for a in sizes for b in sizes) >= 2:
            F.append(finding("icon-size", "low", f"„{items[0][1]['label'][:40]}”: różne rozmiary ikony ({kind})", f"rt:iconsize:{lab}:{kind}:{_ctx}:{sorted(sizes)}",
                             detail="Rozmiary: " + ", ".join(f"{a}×{b}px ({n}×)" for (a, b), n in sizes.most_common()),
                             examples=[ex(*w[0]), ex(*next(x for x in w if (x[1]['icon']['w'], x[1]['icon']['h']) != (w[0][1]['icon']['w'], w[0][1]['icon']['h'])))]))
    # 4) icon set: stroke/fill/stroke-width/viewBox mix
    sets = defaultdict(list)
    for r in res:
        for c in r["components"]:
            if c["role"] == "icon" and (c.get("icon") or {}).get("set"): sets[c["icon"]["set"]].append((r, c))
    if len(sets) > 1:
        tot = sum(len(v) for v in sets.values()); dom = max(sets, key=lambda k: len(sets[k]))
        for s_, items in sets.items():
            if s_ == dom or len(items) / tot > 0.25: continue
            F.append(finding("icon-set", "low", f"Inny zestaw/styl ikon: {s_}", f"rt:iconset:{s_}", detail=f"Dominujący: {dom} ({len(sets[dom])}×). Ten: {len(items)}× na {where_s(items)}.",
                             examples=[ex(*sets[dom][0], "wzorzec"), ex(*items[0], "odstępstwo")], count=len(items),
                             suggestion="Jeden zestaw ikon (ten sam viewBox, stroke/fill, grubość) przez wspólny komponent Icon."))
    return F

def analyze_tokens(raw, contract, tokens_from_code, share):
    F, res = [], results_ok(raw)
    dims = {"font-size": ("fs", None), "radius": ("radius", None), "padding": ("pad", None)}
    vals = defaultdict(lambda: defaultdict(list))
    for r in res:
        for c in r["components"]:
            if c["role"] in ("icon", "link"): continue
            s = c.get("style") or {}
            if s.get("fs"): vals["font-size"][round(s["fs"] * 2) / 2].append((r, c))
            if c["role"] in ("button", "badge", "input", "select", "card", "alert") and s.get("radius") not in (None, 0) and s.get("radius", 0) < 999: vals["radius"][round(s["radius"] * 2) / 2].append((r, c))
            if c["role"] in ("button", "badge", "input", "select", "card", "alert"):
                for p in (("pt", "pb") if c["role"] in ("input", "select") else ("pt", "pr", "pb", "pl")):
                    if s.get(p): vals["padding"][round(s[p] * 2) / 2].append((r, c))
    ct = (contract or {}).get("tokens") or {}
    cmap = {"font-size": "font_size", "radius": "radius", "padding": "spacing"}
    for dim, vv in vals.items():
        tot = sum(len(x) for x in vv.values()) or 1
        declared = ct.get(cmap[dim])
        if declared: scale = sorted(float(x) for x in declared)
        elif dim == "padding": scale = sorted(v for v in vv if (v <= 12 and v % 2 == 0) or v % 4 == 0)      # 4px grid (2px steps up to 12)
        else: scale = sorted(v for v, it in vv.items() if len(it) / tot >= share or (len(it) >= 5 and len(pages_of(it)) >= 2))
        if not scale: continue
        off = [(v, it) for v, it in vv.items() if all(abs(v - s) > 0.26 for s in scale)]
        for v, it in sorted(off, key=lambda x: -len(x[1])):
            near = min(scale, key=lambda s: abs(s - v))
            sev = "medium" if abs(near - v) <= 2 else "low"
            F.append(finding("token-drift", sev, f"{dim} {v:g}px spoza skali", f"rt:token:{dim}:{v:g}",
                             detail=f"Skala ({'kontrakt' if declared else 'siatka 4px' if dim == 'padding' else 'dominujące wartości'}): {', '.join(f'{s:g}' for s in scale)}. {v:g}px użyte {len(it)}× ({where_s(it)}), "
                                    f"najbliższy token {near:g}px. Role: {', '.join(sorted({c['role'] for _, c in it}))}.",
                             examples=[ex(*it[0])], observed=v, canonical=near, count=len(it), confidence="VERIFIED" if declared else "ASSUMPTION",
                             suggestion=f"Użyj tokenu {near:g}px (albo dopisz {v:g}px do tokens.{cmap[dim]}, jeśli zamierzone)."))
    # colours vs palette (contract tokens.colors or CSS custom properties found in code)
    pal = [parse_color(x) for x in (ct.get("colors") or tokens_from_code or [])]; pal = [p for p in pal if p and p[3] > 0.04]
    if pal:
        pal += [(255, 255, 255, 1.0), (0, 0, 0, 1.0)]
        cols = defaultdict(list)
        for r in res:
            for c in r["components"]:
                if c["role"] in ("icon", "link", "state"): continue
                for p in ("color", "bg", "bc"):
                    v = (c.get("style") or {}).get(p)
                    pc = parse_color(v) if v else None
                    if pc and pc[3] > 0.04: cols[hexof(v)].append((r, c, p))
        for hx, it in sorted(cols.items(), key=lambda x: -len(x[1])):
            pc = parse_color(hx.split("/")[0]); a = float(hx.split("/")[1]) if "/" in hx else 1.0
            pc = (pc[0], pc[1], pc[2], a)
            d = min(delta_e(pc, q) for q in pal + [(q[0], q[1], q[2], a) for q in pal])
            if d <= 3: continue
            F.append(finding("color-off-token", "medium" if d <= 10 else "low", f"Kolor {hx} spoza palety tokenów", f"rt:color:{hx}",
                             detail=f"Najbliższy token ΔE {d:.1f}. Użyty {len(it)}× ({', '.join(sorted({p for *_, p in it}))}) na {where_s([(r, c) for r, c, _ in it])}.",
                             examples=[ex(it[0][0], it[0][1])], observed=hx, count=len(it), confidence="ASSUMPTION" if not ct.get("colors") else "VERIFIED",
                             suggestion="Zamień na kolor z tokenów (zmienną CSS) albo dopisz do tokens.colors."))
    return F

SHOP_RE = r"koszyk|ulubione|\d[\d\s]*,\d\d\s?zł|^cart$|wishlist"
def _items_norm(items): return [re.sub(r"\d", "#", x) for x in items]
def analyze_chrome(raw, contract, out):
    F, res = [], results_ok(raw)
    areas = (contract or {}).get("areas") or {}
    by, by_user = defaultdict(list), defaultdict(list)
    for r in res:
        if r.get("state", "base") != "base": continue          # open drawers/overlays dim the chrome: compare base states only
        for ch in r.get("chrome") or []:
            if ch["kind"] == "filters": continue
            by[(r.get("area"), r["kind"], ch["kind"])].append((r, ch)); by_user[(r.get("area"), r["kind"], ch["kind"], r.get("user"))].append((r, ch))
    # forbidden items (shop chrome in admin)
    for (area, kind, ck), items in by.items():
        forb = (areas.get(area) or {}).get("chrome_forbidden") if area in areas else (SHOP_RE if area == "admin" else None)
        if not forb: continue
        if isinstance(forb, list): forb = "|".join(forb)
        hits = sorted({x for _, ch in items for x in ch["items"] if re.search(forb, x, re.I)})
        if hits:
            ck_pl = {"header": "nagłówek", "bottom-nav": "dolny pasek", "sidebar": "menu boczne", "footer": "stopka", "nav": "nawigacja"}.get(ck, ck)
            F.append(finding("chrome-foreign", "high", f"{area}: {ck_pl} ze sklepu: {', '.join(hits[:4])} ({kind})", f"rt:chrome-foreign:{area}:{kind}:{ck}",
                             detail=f"Elementy sklepu w obszarze {area}: {', '.join(hits)}. Strony: {where_s(items)}.",
                             examples=[dict(ex(items[0][0], items[0][1]), label=f"{ck_pl}: {items[0][0]['page']} @ {kind}")], area=area, count=len(items),
                             suggestion=f"Osobny {ck_pl} dla obszaru {area} (wspólny komponent AppShell z wariantem per obszar)."))
    # same area & same user: chrome differs between pages (items / skeleton); other roles legitimately see other menus
    for (area, kind, ck, _u), items in by_user.items():
        sig = defaultdict(list)
        for r, ch in items: sig[(tuple(_items_norm(ch["items"])), ch["skeleton"][:600])].append((r, ch))
        if len(sig) > 1 and len({r['page'] for r, _ in items}) > 1:
            ranked = sorted(sig.values(), key=len, reverse=True)
            a, b = ranked[0][0][1], ranked[1][0][1]
            only_a = [x for x in a["items"] if x not in b["items"]][:5]; only_b = [x for x in b["items"] if x not in a["items"]][:5]
            if not only_a and not only_b and a["skeleton"] == b["skeleton"]: continue
            F.append(finding("chrome-drift", "medium", f"{area}: {ck} różni się między stronami ({kind})", f"rt:chrome-drift:{area}:{kind}:{ck}",
                             detail=f"{ranked[0][0][0]['page']} vs {ranked[1][0][0]['page']}. Tylko w pierwszym: {only_a or '-'}; tylko w drugim: {only_b or '-'}"
                                    + ("" if only_a or only_b else "; inna struktura DOM"),
                             examples=[ex(ranked[0][0][0], a), ex(ranked[1][0][0], b)], area=area))
    # cross-area: sidebar / header look & structure
    shared_pairs = defaultdict(list); foreign = {(f["area"], f["key"].split(":")[3], f["key"].split(":")[4]) for f in F if f["rule"] == "chrome-foreign"}
    for ck in ("sidebar", "header", "bottom-nav"):
        for kind in {k for (_, k, c) in by if c == ck}:
            per_area = {a: items[0] for (a, k, c), items in by.items() if c == ck and k == kind}
            if len(per_area) < 2: continue
            al = sorted(per_area)
            for i in range(len(al)):
                for j in range(i + 1, len(al)):
                    (ra, a), (rb, b) = per_area[al[i]], per_area[al[j]]
                    shared = [s for s in ((contract or {}).get("chrome") or {}).get("shared", [])]
                    if any(set([al[i], al[j]]) <= set(s) for s in shared): continue
                    ja = set(_items_norm(a["items"])); jb = set(_items_norm(b["items"]))
                    jac = len(ja & jb) / max(1, len(ja | jb))
                    if ck in ("header", "bottom-nav") and jac >= 0.6: shared_pairs[(ck, kind)].append((al[i], al[j], jac, ra, a, rb, b))
                    if ck == "sidebar":
                        diffs = []
                        if a["card"] != b["card"]: diffs.append(f"karta: {al[i]}={'tak' if a['card'] else 'nie'}, {al[j]}={'tak' if b['card'] else 'nie'}")
                        if bool(a.get("heading")) != bool(b.get("heading")): diffs.append(f"tytuł menu: {al[i]}={a.get('heading') or '-'}, {al[j]}={b.get('heading') or '-'}")
                        for nm, sa, sb in (("pozycja", a.get("item_style"), b.get("item_style")), ("aktywna pozycja", a.get("active_style"), b.get("active_style")), ("ramka", a.get("inner_card"), b.get("inner_card"))):
                            if sa and sb:
                                fa = tuple((p, getp({"role": "button", "style": sa}, p)) for p in ("fs", "fw", "radius", "pt", "pl", "bg", "color"))
                                fb = tuple((p, getp({"role": "button", "style": sb}, p)) for p in ("fs", "fw", "radius", "pt", "pl", "bg", "color"))
                                _, d = compare(fa, fb, DEFAULT_CS["tolerances"])
                                if d: diffs.append(f"{nm}: " + "; ".join(f"{PROP_PL.get(p, p)} {t}" for p, t in d[:4]))
                            elif bool(sa) != bool(sb): diffs.append(f"{nm}: jest tylko w {al[i] if sa else al[j]}")
                        if diffs:
                            F.append(finding("sidebar-style", "high" if a["card"] != b["card"] else "medium", f"Menu boczne wygląda inaczej: {al[i]} vs {al[j]} ({kind})",
                                             f"rt:sidebar:{kind}:{al[i]}:{al[j]}", detail=" | ".join(diffs), examples=[ex(ra, a), ex(rb, b)],
                                             suggestion="Jeden komponent SidebarNav dla wszystkich paneli (wariant per obszar tylko w kontrakcie)."))
    for (ck, kind), prs in shared_pairs.items():
        prs = [p for p in prs if (p[0], kind, ck) not in foreign and (p[1], kind, ck) not in foreign]
        if not prs: continue
        ar = sorted({p[0] for p in prs} | {p[1] for p in prs})
        F.append(finding("chrome-shared", "medium", f"{ck}: ten sam w obszarach {', '.join(ar)} ({kind})", f"rt:chrome-shared:{ck}:{kind}:{'|'.join(ar)}",
                         detail="Pary: " + "; ".join(f"{p[0]}–{p[1]} ({p[2]:.0%} wspólnych pozycji)" for p in prs) + ". Zamierzone? Jeśli tak, dopisz chrome.shared w kontrakcie.",
                         examples=[ex(prs[0][3], prs[0][4]), ex(prs[0][5], prs[0][6])], confidence="ASSUMPTION"))
    # pixel diff of the same chrome inside one area (catches 1px/colour/icon changes invisible in DOM items)
    try:
        from PIL import Image, ImageChops
        for (area, kind, ck, _u), items in by_user.items():
            if ck not in ("header", "sidebar", "bottom-nav") or len(items) < 2: continue
            crops = []
            for r, ch in items:
                p = Path(out) / r["shot"] if r.get("shot") else None
                if not p or not p.exists(): continue
                x, y, w, h = ch["rect"]; d = r.get("dpr", 1)
                if ch.get("fixed"): y = y - 0  # fixed chrome is captured at its scroll position in full-page shots
                crops.append((r, ch, Image.open(p).convert("RGB").crop((int(x * d), int(y * d), int((x + w) * d), int((y + h) * d)))))
            if len(crops) < 2: continue
            r0, c0, im0 = crops[0]
            for r1, c1, im1 in crops[1:]:
                if im0.size != im1.size:
                    if abs(im0.size[1] - im1.size[1]) > 2 * r0.get("dpr", 1) and ck != "sidebar":
                        F.append(finding("chrome-pixel", "low", f"{area}: {ck} ma inną wysokość na {r1['page']} ({kind})", f"rt:chrome-size:{area}:{kind}:{ck}:{r1['page']}",
                                         detail=f"{r0['page']}: {c0['rect'][2]}×{c0['rect'][3]}px, {r1['page']}: {c1['rect'][2]}×{c1['rect'][3]}px", examples=[ex(r0, c0), ex(r1, c1)], area=area))
                    continue
                diff = ImageChops.difference(im0, im1).convert("L").point(lambda v: 255 if v > 24 else 0)
                ratio = sum(diff.histogram()[255:]) / max(1, im0.size[0] * im0.size[1])
                if ratio > 0.004 and _items_norm(c0["items"]) == _items_norm(c1["items"]):
                    F.append(finding("chrome-pixel", "low", f"{area}: {ck} różni się w pikselach na {r1['page']} ({kind})", f"rt:chrome-pixel:{area}:{kind}:{ck}:{r1['page']}",
                                     detail=f"{ratio:.1%} pikseli inaczej niż na {r0['page']} przy tych samych pozycjach menu (np. aktywna pozycja, ikona, odstęp).",
                                     examples=[ex(r0, c0), ex(r1, c1)], area=area, confidence="ASSUMPTION"))
    except ImportError: pass
    return F

DETAILS_PL = {"drawer-right": "szuflada z prawej", "drawer-left": "szuflada z lewej", "modal": "okno na środku", "fullscreen": "pełny ekran",
              "sheet-bottom": "panel od dołu", "page": "osobna strona", "inline-expand": "rozwinięcie w miejscu", "none": "brak („Szczegóły” nie ma)", "no-op": "nic się nie dzieje"}
def analyze_patterns(raw, contract):
    F, res = [], results_ok(raw); pat = (contract or {}).get("patterns") or {}
    # details
    for kind in ("desktop", "phone", "tablet"):
        dd = [(r, r["details"]) for r in res if r["kind"] == kind and r.get("details") and r["details"].get("pattern") not in ("error",)]
        if not dd: continue
        kinds = Counter(d["pattern"] for _, d in dd)
        canon = (pat.get("details") or {}).get("canonical") if isinstance(pat.get("details"), dict) else pat.get("details")
        trig = Counter((d.get("trigger") and re.sub(r"\d", "#", d["trigger"])) or "-" for _, d in dd)
        if len(kinds) > 1 or (canon and any(k != canon for k in kinds)) or len(trig) > 1:
            ttl = (f"„Szczegóły” otwierają się na {len(kinds)} sposob{'y' if len(kinds) < 5 else 'ów'} ({kind})" if len(kinds) > 1 else
                   f"„Szczegóły”: różne wyzwalacze ({', '.join(t for t in trig)}) ({kind})" if len(trig) > 1 else f"„Szczegóły”: {DETAILS_PL.get(next(iter(kinds)), '')} zamiast {canon} ({kind})")
            F.append(finding("pattern-details", "high" if len(kinds) > 1 else "medium", ttl,
                             f"rt:pattern:details:{kind}:" + "|".join(sorted({f"{r.get('area')}={d['pattern']}/{d.get('how') or '-'}" for r, d in dd})),
                             detail="; ".join(f"{r['area'] or '-'}/{r['page']}: {DETAILS_PL.get(d['pattern'], d['pattern'])} (wyzwalacz: {d.get('trigger') or 'brak'}{', ' + d['how'] if d.get('how') else ''})" for r, d in dd),
                             examples=[dict(ex(r, {"rect": None, "label": d.get("trigger")}), shot=d.get("shot") or r.get("shot"), label=f"{r['page']}: {DETAILS_PL.get(d['pattern'], d['pattern'])} (po kliknięciu „{(d.get('trigger') or 'brak')[:18]}”)" if d.get("shot") else f"{r['page']}: {DETAILS_PL.get(d['pattern'], d['pattern'])}") for r, d in dd],
                             canonical=canon or kinds.most_common(1)[0][0], observed=dict(kinds),
                             suggestion="Jeden wzorzec szczegółów (np. zawsze szuflada z prawej na desktopie i pełny ekran na telefonie) i ten sam wyzwalacz („Szczegóły”) na każdej liście."))
    # dialogs on phone vs desktop are fine; dialogs of different kinds within one kind of device are not
    # notifications: toast vs inline for transient feedback
    al, seen_t = [], {}
    pref = {"toast": 0, "inline": 1, "banner-fixed": 2}
    for r in res:
        for c in r["components"]:
            if c["role"] != "alert" or c["rect"][2] <= 2 or c["rect"][3] <= 2: continue
            k = (id(r), (c.get("text") or "")[:80])
            if k in seen_t:   # same message rendered twice (e.g. live-region copy): keep the most specific kind
                if pref.get(c.get("kind"), 9) < pref.get(seen_t[k][1].get("kind"), 9): al.remove(seen_t[k]); al.append((r, c)); seen_t[k] = (r, c)
                continue
            seen_t[k] = (r, c); al.append((r, c))
    SUBMIT = re.compile(r"Zapisz|Potwierdź|Złóż|Usuń|Wyślij|Dodaj|Aktywuj|Zatwierdź|Save|Submit|Delete", re.I)
    submitted = lambda r: any(st.startswith("ok ") and SUBMIT.search(st) for st in r.get("steps", []))
    static_txt = {(r["page"], (c.get("text") or "")[:80]) for r, c in al if not submitted(r)}
    for r, c in al: c["trigger"] = "action" if submitted(r) and (r["page"], (c.get("text") or "")[:80]) not in static_txt else "static"
    kinds = defaultdict(list)
    for r, c in al: kinds[c.get("kind")].append((r, c))
    act = defaultdict(list)
    for r, c in al:
        if c["trigger"] == "action": act[c.get("kind")].append((r, c))
    canon = (pat.get("notification") or {}).get("canonical") if isinstance(pat.get("notification"), dict) else pat.get("notification")
    mixed_action = len(act) > 1
    if len(kinds) > 1 or (canon and any(k != canon for k in kinds)):
        F.append(finding("pattern-notification", "medium" if mixed_action or canon else "low", "Komunikaty: " + " vs ".join(f"{k} ({len(v)}×)" for k, v in kinds.items())
                         + ("" if mixed_action else " (trwały stan vs informacja po akcji)"),
                         f"rt:pattern:notification:{'|'.join(sorted(kinds))}",
                         detail="; ".join(f"{k}: " + ", ".join(f"„{c.get('text', '')[:50]}” ({r['page']}, {'po akcji' if c['trigger'] == 'action' else 'stan strony'})" for r, c in v[:3]) for k, v in kinds.items())
                                + ("" if mixed_action else ". Ten sam typ komunikatu NIE jest pokazywany na dwa sposoby; różnica może być zamierzona (trwały stan = inline, wynik akcji = toast): zapisz to w kontrakcie."),
                         examples=[ex(*v[0], f"{k}: {v[0][0]['page']}") for k, v in kinds.items()], observed={k: len(v) for k, v in kinds.items()},
                         canonical=canon, confidence="ASSUMPTION",
                         suggestion="Ustal w kontrakcie: informacja zwrotna po akcji = toast (Toaster), stan trwały strony = Alert w treści; jeden komponent na każdy."))
    # tone styling of alerts with the same tone but different look is covered by near-duplicate (role alert)
    # list on phone: table vs cards vs cut table
    lp = []
    for r in res:
        if r["kind"] != "phone" or r.get("state", "base") != "base": continue
        tabs = [c for c in r["components"] if c["role"] == "table" and c["rect"][0] > -5 and c.get("ctx") != "dialog"]
        if tabs:
            t = max(tabs, key=lambda c: c["rect"][2] * c["rect"][3])
            cards = (t.get("display") not in (None, "table", "inline-table")) or (t.get("row_display") not in (None, "table-row")) or (t.get("thead_visible") is False and t.get("cols", 0) > 0)
            k = "cards/list" if cards else "table-cut" if t.get("overflow_x", 0) > 4 and not t.get("scroll_container") else "table-scroll" if t.get("scroll_container") and t.get("overflow_x", 0) > 4 else "table"
            lp.append((r, k, t))
        elif r.get("details"): lp.append((r, "cards/list", None))
    if lp:
        kk = Counter(k for _, k, _ in lp)
        canon = (pat.get("list_phone") or {}).get("canonical") if isinstance(pat.get("list_phone"), dict) else pat.get("list_phone")
        if len(kk) > 1 or "table-cut" in kk or (canon and any(k != canon for k in kk)):
            F.append(finding("pattern-list-phone", "high" if "table-cut" in kk else "medium", "Listy na telefonie: " + ", ".join(f"{k} ({n})" for k, n in kk.items()),
                             f"rt:pattern:list-phone:{'|'.join(sorted(kk))}",
                             detail="; ".join(f"{r['page']}: {k}" + (f" (ucięte {t['overflow_x']}px z prawej)" if t and k == 'table-cut' else '') for r, k, t in lp),
                             examples=[ex(r, t or {"rect": None}, f"{r['page']}: {k}") for r, k, t in lp], observed=dict(kk), canonical=canon,
                             suggestion="Na telefonie jedna forma listy (karty albo przewijana tabela z przypiętą kolumną) przez wspólny DataTable z trybem mobile."))
    return F

SYNONYMS = [
    ("details", ["szczegóły", "podgląd", "zobacz", "pokaż", "otwórz", "detale", "details", "view"]),
    ("save", ["zapisz", "zachowaj", "zapisz zmiany", "save"]),
    ("delete", ["usuń", "skasuj", "delete", "remove"]),
    ("cancel", ["anuluj", "zamknij", "rezygnuj", "cancel", "close"]),
    ("search", ["szukaj", "wyszukaj", "search"]),
    ("add", ["dodaj", "nowy", "nowa", "utwórz", "add", "create"]),
    ("export", ["eksport", "eksportuj", "pobierz", "export", "download"]),
    ("edit", ["edytuj", "zmień", "edit"]),
    ("back", ["wróć", "powrót", "cofnij", "back"]),
]
EN_WORDS = set("""insufficient permission permissions required error errors failed failure invalid not found unauthorized forbidden denied unknown internal server request
submit cancel save delete edit details view loading search settings login logout password back next previous close add remove update create new user users order orders
status total price quantity checkout success warning please try again something went wrong the is are must be cannot field value you your this that has have was
missing access allowed only already exists does exist no yes of to for and with on in at""".split())
EN_STRONG = set("insufficient permission permissions required unauthorized forbidden denied invalid failed please something went wrong cannot must already exists missing".split())
def is_english(s):
    w = re.findall(r"[a-ząćęłńóśźż]+", (s or "").lower())
    if not w or re.search(r"[ąćęłńóśźż]", s.lower()): return False
    hits = [x for x in w if x in EN_WORDS]; strong = [x for x in w if x in EN_STRONG]
    return (len(hits) >= 2 and len(hits) / len(w) >= 0.5 and strong) or (len(strong) >= 2)

def date_kind(d):
    if re.match(r"\d{4}-\d{2}-\d{2}", d): return "RRRR-MM-DD"
    if re.match(r"\d{1,2}\.\d{1,2}\.\d{4}$", d): return "DD.MM.RRRR"
    if re.match(r"\d{1,2}\.\d{1,2}\.\d{2}$", d): return "DD.MM.RR"
    if re.match(r"\d{1,2}/\d{1,2}/\d{2,4}$", d): return "DD/MM/RRRR"
    if re.match(r"\d{1,2}-\d{1,2}-\d{2,4}$", d): return "DD-MM-RRRR"
    if re.match(r"\d{1,2} \D+ \d{4}", d): return "D miesiąc RRRR"
    return "inny"
def money_kind(m):
    cur = "PLN" if "PLN" in m else "zł"; before = m.strip().startswith(("PLN", "zł")); num = re.sub(r"(zł|PLN)", "", m).strip()
    dec = "," if re.search(r",\d{2}$", num) else "." if re.search(r"\.\d{2}$", num) else "bez groszy"
    return f"{num_example(cur, before, dec)}"
def num_example(cur, before, dec):
    n = "1234" + ("" if dec == "bez groszy" else dec + "56"); return (f"{cur} {n}" if before else f"{n} {cur}")
def thousands_kind(m):
    num = re.sub(r"(zł|PLN)", "", m).strip(); ip = re.split(r"[.,]\d{2}$", num)[0]
    if len(re.sub(r"\D", "", ip)) < 4: return None
    return "spacja" if re.search(r"\d[ \u00a0]\d{3}", ip) else "kropka" if re.search(r"\d\.\d{3}", ip) else "bez separatora"
def _old_money_kind(m):
    cur = "PLN" if "PLN" in m else "zł"; before = m.strip().startswith(("PLN", "zł"))
    num = re.sub(r"(zł|PLN)", "", m).strip()
    dec = "," if re.search(r",\d{2}$", num) else "." if re.search(r"\.\d{2}$", num) else "brak"
    th = " " if re.search(r"\d \d{3}", num) else "." if re.search(r"\d\.\d{3}(?!$)", num) and dec == "," else "brak" if re.search(r"\d{4}", num.replace(" ", "")) and not re.search(r"\d[ .]\d{3}", num) and len(re.sub(r'\D', '', num.split(dec)[0] if dec != 'brak' else num)) > 3 else "?"
    return f"{'przed' if before else 'po'}:{cur}, dziesiętne '{dec}'" + (f", tysiące '{th}'" if th != "?" else "")

def analyze_copy(raw, contract):
    F, res = [], results_ok(raw); cc = (contract or {}).get("copy") or {}
    labels = defaultdict(list)
    for r in res:
        for c in r["components"]:
            if c["role"] in ("button", "link"): labels[norm_label(c.get("label"))].append((r, c))
        if r.get("details") and r["details"].get("trigger"): labels[norm_label(r["details"]["trigger"])].append((r, {"label": r["details"]["trigger"], "rect": None}))
    for act, syn in SYNONYMS:
        used = {s: labels[s] for s in syn if labels.get(s)}
        if len(used) > 1:
            canon = (cc.get("actions") or {}).get(act) or max(used, key=lambda s: len(pages_of(used[s])))
            F.append(finding("copy-synonym", "medium", f"Ta sama akcja, różne etykiety: {' / '.join(used)}", f"rt:copy:syn:{act}:{'|'.join(sorted(used))}",
                             detail="; ".join(f"„{s}”: {where_s(v)} ({len(v)}×)" for s, v in used.items()), canonical=canon,
                             examples=[ex(*v[0], f"„{s}”: {v[0][0]['page']}") for s, v in used.items()],
                             suggestion=f"Jedna etykieta „{canon}” (kontrakt copy.actions.{act}).", confidence="ASSUMPTION"))
    # capitalisation of button labels
    caps = defaultdict(list)
    for r in res:
        for c in r["components"]:
            if c["role"] != "button" or c.get("ctx") == "table" and re.search(r"[↕↑↓]", c.get("label") or ""): continue
            l = re.sub(r"[^\wąćęłńóśźżĄĆĘŁŃÓŚŹŻ ]", "", c.get("label") or "").strip()
            if len(l) < 3 or not re.search(r"[a-ząćęłńóśźż]", l, re.I) or re.search(r"\d", l): continue
            if (c.get("style") or {}).get("tt") == "uppercase" or l.isupper(): k = "WIELKIE"
            elif len([w for w in l.split() if len(w) > 3 and not w.isupper()]) >= 2 and all(w[0].isupper() for w in l.split() if len(w) > 3 and not w.isupper()): k = "Każde Słowo"
            elif l[0].islower(): k = "mała litera"
            else: k = "Zdanie"
            caps[k].append((r, c))
    if len(caps) > 1:
        dom = max(caps, key=lambda k: len(caps[k]))
        for k, v in caps.items():
            if k == dom: continue
            F.append(finding("copy-case", "low", f"Wielkość liter na przyciskach: {k} zamiast {dom}", f"rt:copy:case:{k}",
                             detail=f"{dom}: {len(caps[dom])}×; {k}: {len(v)}× (np. " + ", ".join(f"„{c['label'][:25]}” ({r['page']})" for r, c in v[:4]) + ")",
                             examples=[ex(*caps[dom][0], "wzorzec"), ex(*v[0], "odstępstwo")], count=len(v)))
    # dates / money
    dk = defaultdict(list); mk = defaultdict(list)
    for r in res:
        for d in (r.get("copy") or {}).get("dates", []): dk[date_kind(d)].append((r, d))
        for m in (r.get("copy") or {}).get("money", []): mk[money_kind(m)].append((r, m))
    tk = defaultdict(list)
    for r in res:
        for m in (r.get("copy") or {}).get("money", []):
            t = thousands_kind(m)
            if t: tk[t].append((r, m))
    for nm, kk, rule in (("Daty", dk, "copy-date"), ("Kwoty", mk, "copy-money"), ("Separator tysięcy w kwotach", tk, "copy-thousands")):
        kk.pop("inny", None)
        if len(kk) > 1:
            F.append(finding(rule, "medium", f"{nm} w {len(kk)} formatach", f"rt:{rule}:{'|'.join(sorted(kk))}",
                             detail="; ".join(f"{k}: " + ", ".join(sorted({f'„{x}” ({r["page"]})' for r, x in v})[:3]) for k, v in kk.items()),
                             observed={k: len(v) for k, v in kk.items()}, canonical=max(kk, key=lambda k: len(kk[k])),
                             suggestion="Jeden formatter (np. lib/format.ts: formatDate/formatMoney z Intl pl-PL) używany wszędzie."))
    # PL/EN mixing in UI strings and API errors
    en = defaultdict(list)
    for r in res:
        strings = [(w, s) for w, s in (r.get("copy") or {}).get("ui", [])] + [(c["role"], c.get("text") or c.get("label")) for c in r["components"] if c["role"] in ("button", "alert", "heading", "state")]
        for w, s in strings:
            if is_english(s): en[s].append((r, w))
    for s, v in en.items():
        F.append(finding("copy-english", "high", f"Tekst po angielsku w UI: „{s[:60]}”", f"rt:copy:en:{norm_label(s)[:60]}",
                         detail=f"Gdzie: {', '.join(sorted({r['page'] + '#' + r.get('state', 'base') + '@' + r['target'] for r, _ in v}))[:300]}",
                         examples=[dict(ex(v[0][0], next((c for c in v[0][0]["components"] if (c.get("text") or c.get("label")) == s), {"rect": None})), label=f"EN: {v[0][0]['page']}")],
                         suggestion="Tłumaczenie po stronie UI (mapa kodów błędów → tekst PL), nie pokazywać surowego detail z API."))
    api = defaultdict(list)
    for r in res:
        for e in r.get("api_errors") or []:
            if is_english(e.get("detail")): api[e["detail"]].append((r, e))
    for d, v in api.items():
        shown = any(d[:30].lower() in " ".join((c.get("text") or c.get("label") or "") for c in r["components"]).lower() for r, _ in v)
        if shown and norm_label(d)[:60] in {norm_label(s)[:60] for s in en}: continue
        F.append(finding("api-english", "high" if shown else "medium", f"API zwraca błąd po angielsku{' (widoczny w UI)' if shown else ''}: „{d[:60]}”", f"rt:api:en:{norm_label(d)[:60]}",
                         detail=f"{v[0][1]['status']} {v[0][1]['url']} na {', '.join(sorted({r['page'] for r, _ in v}))}",
                         suggestion="Kody błędów w API + tłumaczenie w UI; nie przepychać detail z backendu do toastów."))
    return F

# ---------------------------------------------------------------- static layer (Svelte / React / Vue source)
SHARED_NAMES = {  # component file stem -> role
    "button": "button", "iconbutton": "button", "input": "input", "textfield": "input", "textarea": "textarea", "select": "select",
    "checkbox": "checkbox", "switch": "checkbox", "dialog": "dialog", "modal": "dialog", "drawer": "drawer", "sheet": "drawer", "bottomsheet": "drawer",
    "badge": "badge", "pill": "badge", "tag": "badge", "statusbadge": "badge", "alert": "alert", "toast": "toast", "toaster": "toast",
    "datatable": "table", "table": "table", "card": "card", "icon": "icon", "tabs": "tabs", "pagination": "pagination",
}
RAW_TAGS = {"button": r"<button\b", "input": r"<input\b(?![^>]*type=[\"'](?:hidden|file|checkbox|radio)[\"'])", "textarea": r"<textarea\b", "select": r"<select\b",
            "checkbox": r"<input\b[^>]*type=[\"'](?:checkbox|radio)[\"']", "table": r"<table\b",
            "dialog": r"<dialog\b|role=[\"'](?:dialog|alertdialog)[\"']|aria-modal=", "drawer": r"\bfixed\b[^\"'>]*\b(?:right-0|inset-y-0)\b[^\"'>]*\bh-(?:full|screen|dvh)\b|\bfixed\b[^\"'>]*\bh-(?:full|screen|dvh)\b[^\"'>]*\bright-0\b"}
TOKEN_ARB = re.compile(r"(?<![\w-])(?:[a-z0-9]+:)*(?:text|font|leading|tracking|rounded(?:-[trbl]{1,2})?|p[trblxy]?|m[trblxy]?|gap(?:-[xy])?|space-[xy]|bg|border(?:-[trblxy])?|ring|shadow|outline|fill|stroke|from|to|via|size)-\[(?!var\()(?:-?\d+(?:\.\d+)?(?:px|rem|em)|#[0-9a-fA-F]{3,8}|rgba?\([^\]]+\))\]")
HEX_RE = re.compile(r"(?<![\w&])#[0-9a-fA-F]{6}\b|(?<![\w&])#[0-9a-fA-F]{3}\b(?![\w-])")
PX_STYLE = re.compile(r"style=[\"'{][^\"'}]*?\b\d+(?:\.\d+)?px")
PALETTE = re.compile(r"\b(?:bg|text|border|ring|from|to|via|fill|stroke|outline|divide)-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}\b")
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr", "path", "circle", "rect", "line", "polyline", "polygon", "ellipse", "stop", "use"}

def scan_tags(src):
    """Tiny tolerant tag scanner for Svelte/JSX/Vue templates: yields (pos, closing, name, attrs, selfclosing). Skips quotes and {...}."""
    i, n = 0, len(src)
    while i < n:
        j = src.find("<", i)
        if j < 0 or j + 1 >= n: return
        if not (src[j + 1].isalpha() or src[j + 1] == "/"): i = j + 1; continue
        k, q, br = j + 1, None, 0
        while k < n:
            ch = src[k]
            if q:
                if ch == q and src[k - 1] != "\\": q = None
            elif ch in "\"'`": q = ch
            elif ch == "{": br += 1
            elif ch == "}": br = max(0, br - 1)
            elif ch == ">" and br == 0: break
            elif ch == "<" and br == 0 and k > j + 1: break
            k += 1
        tag = src[j + 1:k]; m = re.match(r"(/?)([A-Za-z][\w.:-]*)", tag)
        if m: yield j, bool(m.group(1)), m.group(2), tag[m.end():], tag.rstrip().endswith("/")
        i = k + 1

def classes_of(attrs):
    out = []
    for m in re.finditer(r"\b(?:class|className)\s*=\s*(\"[^\"]*\"|'[^']*'|\{`[^`]*`\}|\{[^}]*\})", attrs):
        v = m.group(1)
        v = re.sub(r"\$\{[^}]*\}", " ", v); v = re.sub(r"\{[^{}]*\}", " ", v[1:-1] if v[0] in "\"'" else v)
        out += [c for c in re.split(r"\s+", v.strip("{}`'\" ")) if c and re.match(r"^[\w\[\]\-:/.%#()!,]+$", c)]
    out += [m.group(1) for m in re.finditer(r"\bclass:([\w-]+)", attrs)]
    return out

def strip_blocks(src):
    """remove <script>/<style> bodies (keep line count) so only markup is scanned."""
    return re.sub(r"(<(script|style)\b[^>]*>)(.*?)(</\2>)", lambda m: m.group(1) + re.sub(r"[^\n]", " ", m.group(3)) + m.group(4), src, flags=re.S)

def build_tree(src):
    """-> list of nodes {tag, classes, line, children:[], parent, start}. JSX/Svelte components (Capitalised) kept as nodes."""
    root = {"tag": "#root", "classes": [], "children": [], "line": 1}; stack = [root]
    for pos, closing, name, attrs, selfc in scan_tags(src):
        if name.lower() in ("script", "style"): continue
        if closing:
            for k in range(len(stack) - 1, 0, -1):
                if stack[k]["tag"] == name: del stack[k:]; break
            continue
        node = {"tag": name, "classes": classes_of(attrs), "children": [], "line": src.count("\n", 0, pos) + 1, "attrs": attrs[:300]}
        stack[-1]["children"].append(node)
        if not selfc and name.lower() not in VOID and not name.startswith(("svelte:", "#", "@", ":")): stack.append(node)
    return root

def walk(n):
    yield n
    for c in n["children"]: yield from walk(c)
def tok(n): return n["tag"] + "." + ".".join(sorted(set(re.sub(r"^(?:[a-z0-9]+:)+", "", c) for c in n["classes"])))
def subtree_tokens(n, depth=0, cap=80, acc=None):
    acc = [] if acc is None else acc
    if len(acc) >= cap or depth > 6: return acc
    acc.append(f"{depth}:{tok(n)}")
    for c in n["children"]: subtree_tokens(c, depth + 1, cap, acc)
    return acc

def guess_name(n):
    cl = set(n["classes"]); t = n["tag"].lower(); s = " ".join(cl)
    if "animate-pulse" in cl: return "Skeleton"
    if "border-dashed" in cl and "text-center" in cl: return "EmptyState"
    if "uppercase" in cl and re.search(r"\btracking-", s) and re.search(r"text-\[1[01]px\]|text-xs", s): return "Eyebrow/Label (mały nagłówek sekcji)"
    if "nums" in cl and re.search(r"font-(bold|semibold)", s) and re.search(r"text-\[(2\d|1[89])px\]|text-(xl|2xl)", s): return "StatValue (KPI)"
    if t == "input" or ("relative" in cl and any(c["tag"] == "input" for c in walk(n))): return "SearchField/Input" if any("pl-9" in c["classes"] or "pl-8" in c["classes"] for c in walk(n)) else "Input"
    if t == "button" or "cursor-pointer" in cl: return "Button"
    if t in ("input", "select", "textarea"): return t.capitalize()
    if "rounded-full" in cl and re.search(r"\btext-(xs|\[1[01]px\])", s) and re.search(r"\bpx-", s): return "Badge (StatusPill)"
    if re.search(r"\bfixed\b", s) and re.search(r"inset-0", s): return "Modal/Overlay"
    if t in ("table", "tr", "thead"): return "DataTable/Row"
    if t in ("li", "tr") or "flex" in cl and "justify-between" in cl and n["children"]: return "ListRow"
    if re.search(r"\b(border|shadow)", s) and re.search(r"\brounded", s) and re.search(r"\bp[xy]?-\d", s): return "Card/Panel"
    if t in ("label",) or any(c["tag"].lower() in ("input", "select") for c in n["children"]): return "FormField"
    if t in ("h1", "h2", "h3"): return "PageHeading/SectionTitle"
    return "Komponent"

def static_paths(repo, sc):
    """Discover source roots without traversing dependencies or linked directories."""
    if sc.get("paths") is not None:
        return list(sc["paths"])
    excluded = set(sc["exclude"]) | {"vendor", "venv", "docs", "documentation", "examples", "archive", "archives", "legacy"}
    paths = []
    for root, dirs, _ in os.walk(repo, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in excluded and not d.startswith(".") and not (Path(root) / d).is_symlink())
        if Path(root) != repo and Path(root).name in {"src", "app", "pages"}:
            paths.append(Path(root).relative_to(repo).as_posix())
            dirs[:] = []
    return sorted(paths)


def static_scan(repo, sc):
    repo = normalize(repo); excl = set(sc["exclude"]); problems = []
    paths = static_paths(repo, sc)
    def source_files(roots, extensions):
        files = set()
        for p in roots:
            base = repo / p
            if not within(base, repo) or base.is_symlink() or not base.is_dir():
                problems.append(f"Nie można skanować ścieżki źródłowej: {p}")
                continue
            def onerror(error):
                problems.append(f"Nie można odczytać katalogu: {type(error).__name__}")
            for root, dirs, names in os.walk(base, followlinks=False, onerror=onerror):
                dirs[:] = sorted(d for d in dirs if d not in excl and not d.startswith(".") and not (Path(root) / d).is_symlink())
                for name in sorted(names):
                    f = Path(root) / name
                    if f.suffix not in extensions:
                        continue
                    if f.is_symlink() or not within(f, repo):
                        problems.append(f"Pominięto dowiązanie źródłowe: {f.relative_to(repo).as_posix()}")
                        continue
                    if f.is_file(): files.add(f)
        return sorted(files)
    def read_source(path):
        try:
            from helix_audit_context import safe_read
            return safe_read(path, errors="strict")
        except (OSError, UnicodeError) as error:
            problems.append(f"Nie można odczytać {path.relative_to(repo).as_posix()}: {type(error).__name__}")
            return None
    files = source_files(paths, sc["extensions"])
    comp_dirs = sc.get("component_dirs")
    def is_shared(f):
        rel = str(relative_path(f, repo))
        if comp_dirs: return any(rel.startswith(d.rstrip("/") + "/") for d in comp_dirs)
        return bool(re.search(r"(^|/)components/(ui|common|shared|primitives|design-system)/", rel))
    shared = {}
    for f in files:
        if is_shared(f) and f.stem.lower() in SHARED_NAMES: shared.setdefault(SHARED_NAMES[f.stem.lower()], []).append(str(relative_path(f, repo)))
    css_tokens = []
    for c in source_files(paths, [".css"]):
        text = read_source(c)
        if text is None: continue
        for m in re.finditer(r"--color-[\w-]+\s*:\s*([^;]+);", text):
            v = m.group(1).strip()
            if parse_color(v): css_tokens.append(v)
    out = {"files": 0, "paths": paths, "shared": shared, "raw": defaultdict(list), "usage": Counter(), "hardcoded": defaultdict(list),
           "impl": defaultdict(list), "dups": [], "css_color_tokens": sorted(set(css_tokens)), "backend_en": []}
    nodes = []
    for f in files:
        rel = str(relative_path(f, repo)); src = read_source(f)
        if src is None: continue
        out["files"] += 1
        mk = strip_blocks(src)
        own_role = SHARED_NAMES.get(f.stem.lower()) if is_shared(f) else None
        for role, rx in RAW_TAGS.items():
            if role == own_role or (role == "drawer" and own_role == "dialog") or (role == "dialog" and own_role == "drawer"): continue
            for m in re.finditer(rx, mk):
                line = mk.count("\n", 0, m.start()) + 1
                if role in ("dialog", "drawer"): out["impl"][role].append((rel, line))
                else: out["raw"][role].append((rel, line))
        for stem, role in SHARED_NAMES.items():
            out["usage"][role] += len(re.findall(rf"<{stem}\b", mk, re.I)) if stem[0] else 0
        for name in {Path(x).stem for v in shared.values() for x in v}:
            out["usage"]["<" + name] += len(re.findall(rf"<{name}\b", mk))
        if not is_shared(f):
            for m in TOKEN_ARB.finditer(mk): out["hardcoded"]["arbitrary"].append((rel, mk.count("\n", 0, m.start()) + 1, m.group(0)))
            for m in HEX_RE.finditer(mk):
                ln = mk.count("\n", 0, m.start()) + 1
                if not re.search(r"&#|href=|#[0-9a-fA-F]{3,6}-", mk[max(0, m.start() - 6):m.end() + 1]): out["hardcoded"]["hex"].append((rel, ln, m.group(0)))
            for m in PX_STYLE.finditer(mk): out["hardcoded"]["style-px"].append((rel, mk.count("\n", 0, m.start()) + 1, m.group(0)[-30:]))
            if out["css_color_tokens"]:
                for m in PALETTE.finditer(mk): out["hardcoded"]["palette"].append((rel, mk.count("\n", 0, m.start()) + 1, m.group(0)))
        if is_shared(f): continue
        tree = build_tree(mk)
        for n in walk(tree):
            if n["tag"] == "#root": continue
            n["file"] = rel; nodes.append(n)
    out["dups"] = find_duplicates(nodes)
    for f in source_files(sc.get("backend_paths") or [], [".py"]):
        t = read_source(f)
        if t is None: continue
        for m in re.finditer(r"detail\s*=\s*(?:f)?([\"'])(.{6,160}?)\1", t):
            if is_english(m.group(2)): out["backend_en"].append((str(relative_path(f, repo)), t.count("\n", 0, m.start()) + 1, m.group(2)))
    if not out["files"]:
        problems.append("Nie przeskanowano żadnego pliku UI; sprawdź consistency.static.paths i extensions.")
    out["status"] = "INCOMPLETE" if problems else "COMPLETE"
    out["problems"] = list(dict.fromkeys(problems))
    from helix_environment import provenance
    out["provenance"] = provenance(repo, models=[])
    return out

VISUAL_CLS = re.compile(r"^(?:[a-z0-9]+:)*(?:bg-|border|rounded|shadow|text-(?:\[|xs|sm|base|lg|xl|\d|white|black|\[var)|font-|tracking-|leading-|uppercase|italic|underline|ring|opacity-|animate-|p[xytrbl]?-\d|p[xytrbl]?-\[)")
def visual_count(classes): return sum(1 for c in classes if VISUAL_CLS.match(c))
def find_duplicates(nodes, min_nodes=4, max_nodes=70, jac=0.8):
    """(a) single elements with the same class bundle (>=4 classes) in >=3 places / >=2 files; (b) near-identical subtrees (token-shingle Jaccard)."""
    dups = []
    # (a) class bundles
    bundles = defaultdict(list)
    for n in nodes:
        cl = frozenset(re.sub(r"^(?:[a-z0-9]+:)+", "", c) for c in n["classes"])
        if len(cl) >= 4 and n["tag"][0].islower() and visual_count(cl) >= 3: bundles[(n["tag"].lower(), cl)].append(n)
    keys = sorted(bundles, key=lambda k: -len(bundles[k])); used = set(); groups = []
    for i, k in enumerate(keys):
        if k in used: continue
        grp = list(bundles[k]); used.add(k)
        for k2 in keys[i + 1:]:
            if k2 in used or k2[0] != k[0]: continue
            if len(k[1] & k2[1]) / len(k[1] | k2[1]) >= 0.8: grp += bundles[k2]; used.add(k2)
        files = {n["file"] for n in grp}
        if len(grp) >= 3 and len(files) >= 2: groups.append(("element", grp, k))
    for kind, grp, k in groups:
        variants = len({frozenset(n["classes"]) for n in grp})
        dups.append({"kind": "element", "name": guess_name(grp[0]), "tag": k[0], "classes": sorted(k[1]), "count": len(grp), "variants": variants,
                     "files": sorted({n["file"] for n in grp}), "where": [f"{n['file']}:{n['line']}" for n in grp]})
    # (b) subtrees: multiset Jaccard of depth-tagged node tokens, same root token, similar size
    cands = []
    for n in nodes:
        if not n["children"] or n["tag"][0].isupper(): continue
        t = subtree_tokens(n)
        if max(min_nodes, 6) <= len(t) <= max_nodes and len(n["classes"]) >= 1 and sum(visual_count(x["classes"]) for x in walk(n)) >= 4: cands.append((n, t, Counter(t)))
    inv = defaultdict(list); cand_idx = {id(c[0]): k for k, c in enumerate(cands)}
    parent_of = {id(c): n for n in nodes for c in n["children"]}
    for idx, (_, t, _) in enumerate(cands): inv[t[0]].append(idx)
    def bag_j(a, b):
        inter = sum((a & b).values()); return inter / max(1, sum((a | b).values()))
    seen, clusters = set(), []
    order = sorted(range(len(cands)), key=lambda i: -len(cands[i][1]))
    for i in order:
        if i in seen: continue
        n, t, bag = cands[i]; grp = [i]
        for j in inv[t[0]]:
            if j == i or j in seen: continue
            t2 = cands[j][1]
            if min(len(t), len(t2)) / max(len(t), len(t2)) < 0.7: continue
            if bag_j(bag, cands[j][2]) >= 0.75 and not _ancestor(cands[j][0], n, parent_of) and not _ancestor(n, cands[j][0], parent_of): grp.append(j)
        if len(grp) >= 2 and (len({cands[g][0]["file"] for g in grp}) >= 2 or len(grp) >= 3):
            for g in grp:
                seen.add(g)
                for d in walk(cands[g][0]):
                    k2 = cand_idx.get(id(d))
                    if k2 is not None: seen.add(k2)
            clusters.append(grp)
    for grp in clusters[:60]:
        ns = [cands[g][0] for g in grp]
        dups.append({"kind": "subtree", "name": guess_name(ns[0]), "tag": ns[0]["tag"], "classes": sorted(set(ns[0]["classes"]))[:12], "count": len(ns),
                     "nodes": len(cands[grp[0]][1]), "files": sorted({n["file"] for n in ns}), "where": [f"{n['file']}:{n['line']}" for n in ns]})
    dups.sort(key=lambda d: (-(len(d["files"]) * d["count"] * (d.get("nodes") or 1) ** 0.5)))
    return dups
def _ancestor(a, b, parent_of):
    p = parent_of.get(id(b))
    while p is not None:
        if p is a: return True
        p = parent_of.get(id(p))
    return False

def analyze_static(st, contract):
    F = []; comps = (contract or {}).get("components") or {}
    for role, hits in st["raw"].items():
        comp = st["shared"].get(role) or ([comps[role]["component"]] if isinstance(comps.get(role), dict) and comps[role].get("component") else None)
        if not comp: continue
        declared = comps.get(role) if isinstance(comps.get(role), dict) else {}
        req = declared.get("require") is True
        approved = req and declared.get("status", (contract or {}).get("status")) == "approved"
        per = Counter(f for f, _ in hits)
        for f, n in per.most_common():
            F.append(finding("raw-element", "medium" if approved else "low", f"Surowy <{role}> obok {Path(comp[0]).stem} ({n}×) w {f}",
                             f"st:raw:{role}:{f}", layer="static", count=n, where=[f"{f}:{l}" for ff, l in hits if ff == f],
                             confidence="VERIFIED" if approved else "ASSUMPTION",
                             detail=f"Wspólny komponent: {', '.join(comp)}. Linie: {', '.join([str(l) for ff, l in hits if ff == f][:12])}",
                             suggestion=(f"Zastosuj zatwierdzony komponent <{Path(comp[0]).stem}> zgodnie z kontraktem."
                                         if approved else "Sprawdź typ pola i zachowanie; obecność wspólnego komponentu nie dowodzi usterki. Uzgodnij kontrakt przed zamianą.")))
    for role, hits in st["impl"].items():
        files = Counter(f for f, _ in hits)
        shared = st["shared"].get(role) or st["shared"].get("dialog" if role == "drawer" else "drawer")
        if not files: continue
        F.append(finding("multi-impl", "medium", f"{len(files)} własnych implementacji wzorca „{role}” poza wspólnym komponentem",
                         f"st:impl:{role}", layer="static", count=len(files), where=[f"{f}:{l}" for f, l in hits],
                         confidence="ASSUMPTION",
                         detail="Pliki: " + summarize((f"{f} ({n}×)" for f, n in files.most_common()), "findings.json/where") + (f". Wspólne: {', '.join(shared)}" if shared else ". Brak wspólnego komponentu."),
                         suggestion=(f"Użyj {', '.join(Path(x).stem for x in shared)}" if shared else f"Wydziel jeden komponent {role.capitalize()}")))
    for kind, hits in st["hardcoded"].items():
        per = Counter(f for f, *_ in hits)
        nm = {"arbitrary": "dowolne wartości Tailwind (px/hex)", "hex": "kolory hex w markupie", "style-px": "px w style=", "palette": "kolory z palety Tailwind zamiast tokenów"}[kind]
        for f, n in per.most_common():
            vals = Counter(v for ff, _, v in hits if ff == f)
            F.append(finding("hardcoded", "low" if kind == "palette" else "medium", f"{nm}: {n}× w {f}", f"st:hard:{kind}:{f}", layer="static", count=n,
                             where=[f"{f}:{l}" for ff, l, _ in hits if ff == f], detail="Najczęstsze: " + ", ".join(f"{v} ({c}×)" for v, c in vals.most_common(6)),
                             suggestion="Zamień na token (zmienna CSS / klasa z @theme) albo dopisz token do kontraktu."))
    for d in st["dups"][:40]:
        existing = {"Button": "button", "Badge (StatusPill)": "badge", "Modal/Overlay": "dialog", "DataTable/Row": "table", "Card/Panel": "card", "Input": "input", "SearchField/Input": "input", "Select": "select"}.get(d["name"])
        has = st["shared"].get(existing) if existing else None
        sev = "medium" if (len(d["files"]) >= 3 or d["count"] >= 5) and not (d["name"] == "Komponent" and d["kind"] == "element") else "low"
        F.append(finding("extract-component", sev, f"{'Użyj ' + Path(has[0]).stem if has else 'Wydziel komponent ' + d['name']}: {d['count']}× w {len(d['files'])} plikach",
                         f"st:dup:{d['kind']}:{d['tag']}:{hashlib.sha1(' '.join(d['classes']).encode()).hexdigest()[:8]}", layer="static", count=d["count"], where=d["where"],
                         detail=f"<{d['tag']} class=\"{' '.join(d['classes'][:10])}\">{' (' + str(d.get('nodes')) + ' węzłów)' if d.get('nodes') else ''}"
                                + (f", {d['variants']} wariantów klas" if d.get("variants", 1) > 1 else "") + ". Pliki: " + summarize(d["files"], "static.json/dups/files"),
                         suggestion=(f"Ten blok to już {', '.join(has)}; zamień kopie na komponent." if has else f"Wydziel {d['name']} i użyj w {len(d['files'])} plikach.")))
    if st["backend_en"]:
        per = Counter(f for f, *_ in st["backend_en"])
        F.append(finding("backend-english", "medium", f"Backend: {len(st['backend_en'])} komunikatów błędów po angielsku (mogą trafić do UI)", "st:backend-en", layer="static",
                         count=len(st["backend_en"]), where=[f"{f}:{l}" for f, l, _ in st["backend_en"]],
                         detail="Np.: " + "; ".join(f"„{t[:50]}” ({f}:{l})" for f, l, t in st["backend_en"][:6]) + ". Pliki: " + ", ".join(f"{f} ({n})" for f, n in per.most_common(6)),
                         suggestion="Kody błędów (np. code=insufficient_permissions) + tłumaczenie PL w UI."))
    return F

# ---------------------------------------------------------------- contract: exceptions, proposal
def load_contract(ctx, c, path=None):
    p = Path(path) if path else ctx.repo / c["contract"]
    if not p.exists(): return None, p
    return load_yaml(p), p

def apply_contract(F, contract):
    today = dt.date.today().isoformat(); expired = []
    for e in (contract or {}).get("exceptions") or []:
        if e.get("until") and str(e["until"]) < today: expired.append(e)
    for f in F:
        for e in (contract or {}).get("exceptions") or []:
            if e in expired: continue
            if e.get("rule") not in (None, "*", f["rule"]): continue
            if e.get("area") and e["area"] != f.get("area") and e["area"] not in f["key"]: continue
            if e.get("match") and not re.search(e["match"], f["key"] + " " + f["title"], re.I): continue
            if e.get("file") and not any(re.search(e["file"], w) for w in f["where"] + [f["key"]]): continue
            f["status"] = "exception"; f["exception_reason"] = e.get("reason", "(brak uzasadnienia)") + (f" [właściciel: {e['owner']}]" if e.get("owner") else ""); break
    for e in expired:
        F.append(finding("exception-expired", "medium", f"Wyjątek z kontraktu wygasł {e['until']}: {e.get('rule')} {e.get('match') or e.get('file') or ''}", f"ct:expired:{e.get('rule')}:{e.get('match') or e.get('file')}",
                         layer="contract", detail=f"Powód: {e.get('reason')}; właściciel: {e.get('owner') or 'brak'}. Odnów (nowa data) albo napraw."))
    for e in (contract or {}).get("exceptions") or []:
        if not e.get("reason") or not e.get("owner"):
            F.append(finding("exception-incomplete", "low", f"Wyjątek bez {'uzasadnienia' if not e.get('reason') else 'właściciela'}: {e.get('rule')} {e.get('match') or e.get('file') or ''}",
                             f"ct:incomplete:{e.get('rule')}:{e.get('match') or e.get('file')}", layer="contract", detail="Każdy wyjątek: reason, owner, until."))
    return F

def propose_contract(raw, st, F, pages):
    res = results_ok(raw) if raw else []
    def scale(prop, roles, share=0.04):
        cnt = Counter()
        for r in res:
            for c in r["components"]:
                if c["role"] in roles:
                    for p in prop:
                        v = (c.get("style") or {}).get(p)
                        if v and v < 999: cnt[round(v * 2) / 2] += 1
        tot = sum(cnt.values()) or 1
        return sorted(v for v, n in cnt.items() if n / tot >= share)
    areas = defaultdict(list)
    for p in pages or []: areas[p.get("area") or "app"].append(p["path"])
    det = Counter(r["details"]["pattern"] for r in res if r.get("details") and r["kind"] == "desktop" and r["details"]["pattern"] not in ("none", "error", "no-op"))
    detp = Counter(r["details"]["pattern"] for r in res if r.get("details") and r["kind"] == "phone" and r["details"]["pattern"] not in ("none", "error", "no-op"))
    notif = Counter(c.get("kind") for r in res for c in r["components"] if c["role"] == "alert")
    dk = Counter(date_kind(d) for r in res for d in (r.get("copy") or {}).get("dates", [])); dk.pop("inny", None)
    mk = Counter(money_kind(m) for r in res for m in (r.get("copy") or {}).get("money", []))
    labels = Counter(norm_label(c.get("label")) for r in res for c in r["components"] if c["role"] in ("button", "link"))
    actions = {}
    for act, syn in SYNONYMS:
        used = [(labels[s], s) for s in syn if labels.get(s)]
        if used: actions[act] = max(used)[1].capitalize()
    comps = {role: {"component": v[0], "require": True} for role, v in sorted((st or {}).get("shared", {}).items())}
    P = "proposal"
    return {
        "version": 1,
        "status": "PROPOZYCJA — wygenerowana z najczęstszego użycia; każdą pozycję zatwierdza człowiek (zmień status na approved)",
        "areas": {a: ({"routes": sorted(set(r)), **({"chrome_forbidden": ["Koszyk", "Ulubione", "\\d+,\\d\\d zł"]} if a == "admin" else {})}) for a, r in areas.items()},
        "chrome": {"shared": [], "note": "obszary, które CELOWO mają wspólny nagłówek/menu, np. [shop, company]"},
        "tokens": {"status": P, "font_size": scale(["fs"], ("button", "badge", "input", "select", "heading", "table", "alert", "card")),
                   "radius": [x for x in scale(["radius"], ("button", "badge", "input", "select", "card", "alert")) if x > 0],
                   "spacing": scale(["pt", "pr", "pb", "pl"], ("button", "badge", "input", "select", "card", "alert")),
                   "colors": (st or {}).get("css_color_tokens", [])[:60]},
        "components": comps,
        "patterns": {"details": {"canonical": det.most_common(1)[0][0] if det else None, "phone": detp.most_common(1)[0][0] if detp else None, "status": P},
                     "notification": {"canonical": notif.most_common(1)[0][0] if notif else None, "status": P,
                                      "note": "propozycja: toast = informacja zwrotna po akcji, inline = trwały stan strony; decyzja człowieka"},
                     "list_phone": {"canonical": "cards/list", "status": P, "note": "tabela ucięta na telefonie nigdy nie jest OK"},
                     "sidebar": {"canonical": "jeden komponent SidebarNav dla wszystkich paneli", "status": P}},
        "copy": {"language": "pl", "actions": actions, "date_format": dk.most_common(1)[0][0] if dk else "DD.MM.RRRR",
                 "money_format": mk.most_common(1)[0][0] if mk else "po:zł, dziesiętne ','", "status": P},
        "exceptions": [{"rule": "chrome-shared", "area": "company", "match": "shop", "reason": "PRZYKŁAD (usuń/zmień): panel firmy celowo w ramie sklepu", "status": P}],
    }

# ---------------------------------------------------------------- coverage (a skipped page must never look like an improvement)
def coverage(raw):
    out = []
    for r in (raw or {}).get("results", []):
        pid = f"{r['page']}#{r.get('state', 'base')}@{r['target']}"; probs = []
        if not r.get("ok"): probs.append(f"błąd: {r.get('error')}")
        probs += [st for st in r.get("steps", []) if st.startswith(("FAIL", "wait_for"))]
        if (r.get("details") or {}).get("pattern") == "error": probs.append(f"sonda szczegółów: {r['details'].get('note')}")
        if r.get("ok") and len(r.get("components") or []) < 5: probs.append("prawie pusta strona (<5 komponentów): sesja wygasła albo brak danych?")
        out.append({"id": pid, "ok": not probs, "problems": probs})
    return out

def measurement_coverage(raw, st):
    """Keep a failed/empty static scan visible to the same ratchet as runtime."""
    rows = coverage(raw)
    if st is not None:
        rows.append({"id": "static", "layer": "static", "ok": st.get("status") == "COMPLETE" and st.get("files", 0) > 0,
                     "files": st.get("files", 0), "paths": st.get("paths", []), "problems": st.get("problems", [])})
    return rows
def route_coverage(repo, st, pages):
    """static routes (SvelteKit +page.svelte, Next app/page.tsx, pages/*.tsx) vs runtime-visited paths. Info, not blocking."""
    if not st: return None
    routes = []
    for p in st.get("paths", []):
        base = Path(repo) / p
        for f in list(base.rglob("+page.svelte")) + list(base.rglob("page.tsx")) + list(base.rglob("page.jsx")):
            rel = str(relative_path(f.parent, base)); rel = re.sub(r"^routes/?", "", rel); rel = re.sub(r"^app/?", "", rel)
            routes.append("/" + re.sub(r"\([^)]*\)/?", "", rel).strip("/"))
    routes = sorted(set(routes))
    rx = [(r, re.compile("^" + re.sub(r"\\\[[^/]+?\\\]", "[^/]+", re.escape(r)) + "/?$")) for r in routes]
    visited = {p["path"].split("?")[0] for p in pages or []}
    hit = sorted({r for r, x in rx for v in visited if x.match(v)})
    return {"routes": len(routes), "visited": len(hit), "missing": [r for r in routes if r not in hit]}

# ---------------------------------------------------------------- baseline / gate
def baseline_path(ctx, c): return ctx.repo / c["baseline"]
def write_baseline(path, F, cov=None):
    keys = {}
    for f in F:
        if f["status"] == "exception": continue
        keys[f["key"]] = {"severity": f["severity"], "count": f.get("count"), "title": f["title"], "layer": f["layer"]}
    Path(path).write_text(json.dumps({"created": H.now() if H else dt.datetime.now().isoformat(), "keys": keys,
                                      "coverage": sorted(c["id"] for c in cov or [] if c["ok"])}, indent=1, ensure_ascii=False, sort_keys=True))
    return len(keys)
def compare_baseline(F, base, fail_on, cov=None, block_assumptions=False):
    """ratchet: FAIL on NEW (or grown) findings of blocking severity; ASSUMPTION (heuristic) findings only warn unless block_assumptions.
    INCOMPLETE (= FAIL) when a page/state measured in the baseline was not measured now, or a measurement failed."""
    bk = (base or {}).get("keys", {}); new, worse, fixed, known, advisory = [], [], [], [], []
    cur = {f["key"]: f for f in F if f["status"] != "exception"}
    blocks = lambda f: f["severity"] in fail_on and (block_assumptions or f["confidence"] == "VERIFIED")
    for k, f in cur.items():
        if k not in bk: (new if blocks(f) else advisory if f["severity"] in fail_on else known).append(f)
        elif f.get("count") and bk[k].get("count") and f["count"] > bk[k]["count"]:
            f["baseline_count"] = bk[k]["count"]; (worse if blocks(f) else advisory).append(f)
        else: known.append(f)
    covered = {c["id"] for c in cov or [] if c["ok"]}
    incomplete = [c for c in cov or [] if not c["ok"]] + [{"id": i, "ok": False, "problems": ["zmierzone w baseline, teraz brak pomiaru"]}
                                                          for i in (base or {}).get("coverage", []) if i not in covered and i not in {c["id"] for c in cov or []}]
    # fixed only counts where we actually measured again (runtime keys from pages that are now incomplete are not 'fixed')
    incomplete_layers = {c.get("layer", "runtime") for c in incomplete}
    fixed = [dict(v, key=k) for k, v in bk.items() if k not in cur and v.get("layer", "runtime") not in incomplete_layers]
    return {"new": new, "worse": worse, "fixed": fixed, "known": known, "advisory": advisory, "incomplete": incomplete,
            "pass": not new and not worse and not incomplete}

# ---------------------------------------------------------------- report
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
def _font(sz):
    from PIL import ImageFont
    try: return ImageFont.truetype(FONT, sz)
    except Exception: return ImageFont.load_default()
def crop_example(out, e, pad=10, maxw=560, maxh=220):
    from PIL import Image
    if not e.get("shot"): return None
    p = Path(out) / e["shot"]
    if not p.exists(): return None
    im = Image.open(p).convert("RGB"); d = e.get("dpr", 1) or 1
    if e.get("rect"):
        x, y, w, h = e["rect"]; h = min(h, 360)          # tall elements (sidebar, table): top part is enough to compare
        box = (max(0, int((x - pad) * d)), max(0, int((y - pad) * d)), min(im.width, int((x + w + pad) * d)), min(im.height, int((y + h + pad) * d)))
        if box[2] - box[0] < 4 or box[3] - box[1] < 4: return None
        im = im.crop(box); sc = min(maxw / im.width, maxh / im.height, 2.0 / d * 2 if d > 1 else 2.0)
    else:
        im = im.crop((0, 0, im.width, min(im.height, int(im.width * 0.75)))); sc = min(maxw / im.width, (maxh * 1.6) / im.height)
    return im.resize((max(1, int(im.width * sc)), max(1, int(im.height * sc))))

def contact_sheet(out, top, dest, n=8):
    from PIL import Image, ImageDraw
    rows, seen = [], set()
    for f in top:
        k = (f["rule"], re.sub(r" \((desktop|phone|tablet|telefon|desktop \+ telefon|telefon \+ desktop)\)$", "", f["title"]))
        if k in seen: continue
        seen.add(k); ims = []
        exs = f["examples"][:3]
        for e in exs:
            im = crop_example(out, e, maxw=1100 if len(exs) == 1 else 560 if len(exs) == 2 else 420)
            if im: ims.append((e["label"], im))
        if ims: rows.append((f, ims))
        if len(rows) >= n: break
    if not rows: return None
    W = max(40 + sum(i.width + 24 for _, i in ims) for _, ims in rows); W = max(W, 1200)
    Hs = [70 + max(i.height for _, i in ims) + 30 for _, ims in rows]
    sheet = Image.new("RGB", (W, sum(Hs) + 20), (246, 246, 244)); dr = ImageDraw.Draw(sheet); y = 10
    f1, f2 = _font(19), _font(14); col = {"high": (200, 30, 30), "medium": (190, 110, 0), "low": (90, 90, 90)}
    for (f, ims), hh in zip(rows, Hs):
        dr.rectangle((10, y, W - 10, y + hh - 8), outline=(210, 205, 196), fill=(255, 255, 255))
        dr.text((22, y + 10), f"[{f['severity'].upper()}] {f['title']}"[:140], fill=col[f["severity"]], font=f1)
        dr.text((22, y + 36), (f["detail"] or "")[:190], fill=(60, 60, 60), font=f2)
        x = 22
        for lab, im in ims:
            sheet.paste(im, (x, y + 62)); dr.rectangle((x - 1, y + 61, x + im.width, y + 62 + im.height), outline=(160, 160, 160))
            mx = max(8, int(im.width / 7.6)); dr.text((x, y + 66 + im.height), lab if len(lab) <= mx else lab[: mx - 1] + "…", fill=(40, 40, 40), font=f2); x += im.width + 24
        y += hh
    sheet.save(dest); return dest

def merge_kinds(F):
    """presentation only: one entry for the same finding seen on desktop and phone (baseline keys stay per device)."""
    out, idx = [], {}
    for f in F:
        t = re.sub(r" \((desktop|phone|tablet)\)$", "", f["title"]); k = (f["rule"], t)
        if k in idx:
            g = idx[k]; m = re.search(r"\((desktop|phone|tablet)\)$", f["title"])
            if m and m.group(1) not in g["_kinds"]: g["_kinds"].append(m.group(1))
            g["examples"] = g["examples"] + [e for e in f["examples"] if len(g["examples"]) < 4]; continue
        g = dict(f); m = re.search(r"\((desktop|phone|tablet)\)$", f["title"]); g["_kinds"] = [m.group(1)] if m else []; idx[k] = g; out.append(g)
    for g in out:
        if g["_kinds"]: g["title"] = re.sub(r" \((desktop|phone|tablet)\)$", "", g["title"]) + " (" + " + ".join({"phone": "telefon"}.get(k, k) for k in g["_kinds"]) + ")"
    return out

RULE_W = {"pattern-details": 3, "chrome-foreign": 3, "copy-english": 3, "api-english": 2.5, "sidebar-style": 2.5, "pattern-notification": 2.5, "same-label-different-style": 2,
          "pattern-list-phone": 2, "copy-synonym": 2, "copy-date": 1.5, "copy-money": 1.5, "icon-presence": 1.5, "near-duplicate": 1.5, "chrome-shared": 1.2,
          "raw-element": 2, "multi-impl": 2, "extract-component": 1.5, "backend-english": 1.5, "token-drift": 1, "color-off-token": 0.8, "hardcoded": 1}
def rank(F):
    """systemic patterns (how details open, chrome, notifications, language) outrank single-property deltas of the same severity."""
    def sc(f): return (f["status"] != "exception", SEV_W[f["severity"]] + RULE_W.get(f["rule"], 1), f["confidence"] == "VERIFIED", len(f["examples"]), f.get("count") or 0)
    return sorted(F, key=sc, reverse=True)

ADOPTION = {}
def aggregate_static(F):
    """collapse per-file static findings into one per rule/role for the top list."""
    agg, rest = defaultdict(list), []
    for f in F:
        if f["layer"] == "static" and f["rule"] in ("raw-element", "hardcoded"):
            agg[(f["rule"], f["key"].split(":")[2], f["status"], f["confidence"], f.get("exception_reason", ""))].append(f)
        else: rest.append(f)
    for (rule, kind, status, confidence, exception_reason), fs in agg.items():
        tot = sum(f.get("count") or 0 for f in fs); sev = max((f["severity"] for f in fs), key=lambda s: SEV_W[s])
        files = summarize((f"{f['where'][0].split(':')[0] if f['where'] else '?'} ({f['count']})" for f in sorted(fs, key=lambda f: -(f['count'] or 0))), "findings.json")
        used = ADOPTION.get(kind)
        if rule == "raw-element":
            title = f"Surowe <{kind}> obok wspólnego komponentu: {tot}× w {len(fs)} plikach" + (f" (komponent użyty {used}×, adopcja {used / max(1, used + tot):.0%})" if used is not None else "")
        else: title = f"Wartości poza tokenami ({kind}): {tot}× w {len(fs)} plikach"
        rest.append(dict(finding(rule, sev, title, f"agg:{rule}:{kind}", layer="static", detail="Najwięcej: " + files, count=tot,
                                 confidence=confidence, where=list(dict.fromkeys(w for f in fs for w in f["where"])),
                                 examples=[e for f in fs for e in f["examples"]], suggestion=fs[0]["suggestion"]),
                         aggregated=len(fs), status=status, exception_reason=exception_reason, source_keys=[f["key"] for f in fs]))
    return rest

def render_md(rep):
    from helix_paths import summarize
    L = [f"# Spójność UI: {rep['repo_name']}", "", f"Wygenerowano: {rep['created']} (czas Europe/Warsaw). Strony: {len(rep['pages'])}, urządzenia: {', '.join(rep['targets'])}. "
         f"Pliki źródłowe: {rep['static_files']}.", "",
         "Oznaczenia: **VERIFIED** = zmierzone w przeglądarce / znalezione w kodzie; **ASSUMPTION** = heurystyka, wymaga oceny człowieka.", ""]
    L += [f"Pokrycie: **{rep.get('status', 'INCOMPLETE')}**."]
    origin = rep.get('provenance', {})
    L += [f"Pochodzenie: Helix {origin.get('helix_version', 'unknown')}; rewizja celu {origin.get('target_head') or 'unknown'}. Pełne metadane: provenance w report.json."]
    for problem in rep.get("problems", []): L.append("- " + problem)
    if rep.get("gate"):
        g = rep["gate"]; L += [f"## Bramka (ratchet względem baseline)", f"- Wynik: **{'PASS' if g['pass'] else 'INCOMPLETE' if g.get('incomplete') and not g['new'] and not g['worse'] else 'FAIL'}**; nowe: {len(g['new'])}, gorsze: {len(g['worse'])}, "
                               f"naprawione: {len(g['fixed'])}, znane: {len(g['known'])}, tylko ostrzeżenia (ASSUMPTION): {len(g.get('advisory', []))}, niepełny pomiar: {len(g.get('incomplete', []))}", ""]
        for f in g["new"] + g["worse"]: L.append(f"- NOWE [{f['severity']}] {f['title']} (`{f['key']}`)")
        for f in g.get("advisory", []): L.append(f"- ostrzeżenie (ASSUMPTION, nie blokuje) [{f['severity']}] {f['title']}")
        for x in g.get("incomplete", []): L.append(f"- NIEPEŁNY POMIAR {x['id']}: {'; '.join(x['problems'])[:200]}")
        L.append("")
    sev = Counter(f["severity"] for f in rep["findings"] if f["status"] != "exception")
    L += ["## Podsumowanie", f"- Ustalenia: {sum(sev.values())} (wysokie {sev['high']}, średnie {sev['medium']}, niskie {sev['low']}); wyjątki z kontraktu: {sum(1 for f in rep['findings'] if f['status'] == 'exception')}",
          f"- Kontrakt: {rep['contract'] or 'brak (użyto propozycji z najczęstszego użycia)'}"]
    cv = rep.get("coverage") or []
    if cv: L.append(f"- Pomiary runtime: {sum(1 for x in cv if x['ok'])}/{len(cv)} OK" + "".join(f"; problem {x['id']}: {x['problems'][0][:100]}" for x in cv if not x["ok"]))
    rc = rep.get("routes")
    if rc: L.append(f"- Pokrycie tras: runtime odwiedził {rc['visited']} z {rc['routes']} tras z kodu (reszta tylko w warstwie statycznej). Brakujące np.: {summarize(rc['missing'], 'report.json/routes/missing')}")
    L += ["", f"## Top {len(rep['top'])}", ""]
    for i, f in enumerate(rep["top"], 1):
        L += [f"### {i}. [{f['severity'].upper()}] {f['title']}", f"- {f['confidence']} · {f['layer']} · reguła `{f['rule']}`", f"- {f['detail']}"]
        if f.get("suggestion"): L.append(f"- Propozycja: {f['suggestion']}")
        L.append("")
    L += ["## Proponowane wspólne komponenty", ""]
    for s in rep["components"][:25]: L.append(f"- **{s['name']}**: {s['why']} — {summarize(s['where'] if isinstance(s['where'], list) else [s['where']], 'proposed-components.json')}")
    L += ["", "## Wszystkie ustalenia", "", "| # | waga | warstwa | reguła | tytuł | pewność |", "|---|---|---|---|---|---|"]
    for i, f in enumerate(rank(rep["findings"]), 1):
        L.append(f"| {i} | {f['severity']}{' (wyjątek)' if f['status'] == 'exception' else ''} | {f['layer']} | {f['rule']} | {f['title'].replace('|', '/')} | {f['confidence']} |")
    L += ["", "## Ograniczenia", ""] + [f"- {x}" for x in rep["limitations"]]
    return "\n".join(L) + "\n"

def render_html(rep, out):
    import base64, io
    def img(e):
        try:
            im = crop_example(out, e, maxw=420, maxh=180)
            if not im: return ""
            b = io.BytesIO(); im.save(b, "JPEG", quality=78); return f'<figure><img src="data:image/jpeg;base64,{base64.b64encode(b.getvalue()).decode()}"><figcaption>{html.escape(e["label"])}</figcaption></figure>'
        except Exception: return ""
    css = "body{font:14px system-ui,sans-serif;margin:24px;max-width:1300px;color:#222}h3{margin:18px 0 4px}.high{color:#b00}.medium{color:#b60}.low{color:#666}figure{display:inline-block;margin:6px 12px 6px 0;vertical-align:top}figure img{border:1px solid #bbb;max-width:420px}figcaption{font-size:12px;color:#555}table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:3px 6px;font-size:12px}"
    H_ = [f"<!doctype html><meta charset=utf-8><title>Spójność UI</title><style>{css}</style><h1>Spójność UI: {html.escape(rep['repo_name'])}</h1>",
          f"<p>{html.escape(rep['created'])} · strony: {len(rep['pages'])} · urządzenia: {', '.join(rep['targets'])} · pliki: {rep['static_files']}</p>"]
    if rep.get("gate"): H_.append(f"<p><b>Bramka: {'PASS' if rep['gate']['pass'] else 'FAIL'}</b> (nowe {len(rep['gate']['new'])}, gorsze {len(rep['gate']['worse'])}, naprawione {len(rep['gate']['fixed'])})</p>")
    H_.append(f"<h2>Top {len(rep['top'])}</h2>")
    for i, f in enumerate(rep["top"], 1):
        H_.append(f"<h3 class={f['severity']}>{i}. [{f['severity']}] {html.escape(f['title'])}</h3><div>{f['confidence']} · {f['layer']} · <code>{f['rule']}</code></div><p>{html.escape(f['detail'] or '')}</p>"
                  + (f"<p><i>Propozycja:</i> {html.escape(f['suggestion'])}</p>" if f.get("suggestion") else "") + "".join(img(e) for e in f["examples"][:3]))
    H_.append("<h2>Proponowane wspólne komponenty</h2><ul>" + "".join(f"<li><b>{html.escape(s['name'])}</b>: {html.escape(s['why'])} — <code>{html.escape(s['where'])}</code></li>" for s in rep["components"][:25]) + "</ul>")
    H_.append("<h2>Wszystkie ustalenia</h2><table><tr><th>#</th><th>waga</th><th>warstwa</th><th>reguła</th><th>tytuł</th><th>szczegóły</th></tr>" + "".join(
        f"<tr><td>{i}</td><td class={f['severity']}>{f['severity']}{' (wyjątek)' if f['status'] == 'exception' else ''}</td><td>{f['layer']}</td><td>{f['rule']}</td><td>{html.escape(f['title'])}</td><td>{html.escape((f['detail'] or '')[:400])}</td></tr>"
        for i, f in enumerate(rank(rep["findings"]), 1)) + "</table>")
    H_.append("<h2>Ograniczenia</h2><ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in rep["limitations"]) + "</ul>")
    return "\n".join(H_)

def component_suggestions(F, st):
    out = []
    for f in rank(F):
        if f["status"] == "exception": continue
        if f["rule"] == "extract-component" and f["severity"] == "low" and (f.get("count") or 0) < 10: continue
        if f["rule"] == "extract-component": out.append({"name": f["title"].split(":")[0], "why": f["detail"][:220], "where": ", ".join(f["where"][:6]), "layer": "static", "count": f.get("count")})
        elif f["rule"] in ("multi-impl",): out.append({"name": f["suggestion"], "why": f["title"], "where": ", ".join(f["where"][:6]), "layer": "static", "count": f.get("count")})
        elif f["rule"] in ("pattern-details", "sidebar-style", "chrome-foreign", "pattern-list-phone", "pattern-notification"):
            out.append({"name": {"pattern-details": "DetailsDrawer (jeden wzorzec szczegółów)", "sidebar-style": "SidebarNav (wspólne menu paneli)",
                                 "chrome-foreign": "AppShell z wariantem per obszar (shop/company/admin)", "pattern-list-phone": "DataTable z trybem mobile (karty)",
                                 "pattern-notification": "Notify: Toaster + Alert z jedną regułą użycia"}[f["rule"]],
                        "why": f["title"], "where": f["detail"][:200], "layer": "runtime", "count": f.get("count")})
    seen, uniq = set(), []
    for s in out:
        if s["name"] in seen: continue
        seen.add(s["name"]); uniq.append(s)
    return uniq

LIMITS = [
    "Runtime mierzy tylko odwiedzone strony i stany (lista w helix.json); nie przechodzi całej aplikacji.",
    "Wszystkie urządzenia emulowane w Chromium (telefon = deskryptor Playwright), nie prawdziwy Safari/iOS.",
    "Role komponentów rozpoznawane heurystycznie po stylach i semantyce (button/a, plakietki, komunikaty) — możliwe pomyłki klasyfikacji (ASSUMPTION).",
    "Warstwa statyczna to skaner tagów i klas (nie pełny AST TypeScript/Svelte); wyrażenia warunkowe w klasach są pomijane.",
    "Kolory z color-mix()/var() w CSS tokenach nie są rozwijane w warstwie statycznej; porównanie z paletą tylko dla stałych kolorów.",
    "Toast vs komunikat w treści: heurystyka nie wie, czy to ten sam typ informacji — decyzja w kontrakcie.",
]

def run_runtime(ctx, c, out, base_url=None, only=None):
    import helix_ux as U
    base = base_url or c["base_url"]
    if not base: raise SystemExit("consistency: brak base_url (helix.json consistency.base_url albo ux.base_url, albo --base-url)")
    U.assert_safe_url(base, c["allow_hosts"])
    pages = [p for p in (c["pages"] or []) if not only or p["name"] in only]
    for p in pages:
        if p.get("base_url"): U.assert_safe_url(p["base_url"], c["allow_hosts"])
    job = {"out": str(out), "base_url": base, "allow_hosts": c["allow_hosts"], "storage_state": c["storage_state"], "pages": pages, "targets": c["targets"],
           "locale": "pl-PL", "timezone": "Europe/Warsaw", "settle_ms": c.get("settle_ms")}
    jf = Path(out) / "job-consistency.json"; jf.write_text(json.dumps(job, indent=1, ensure_ascii=False))
    env = dict(os.environ, HELIX_PLAYWRIGHT=H.PW_PATH)
    p = subprocess.run(["node", str(CS_JS), "scan", str(jf)], capture_output=True, text=True, env=env, timeout=3600)
    if p.returncode: raise SystemExit(f"consistency.cjs failed: {p.stderr[-800:]}")
    for line in p.stderr.splitlines(): H.log(line)
    raw = json.loads((Path(out) / "raw.json").read_text())
    from helix_environment import provenance
    raw['provenance'] = provenance(ctx.repo, models=[], tools={name: {'used': True, 'version': None, 'status': 'unknown'} for name in ('node', 'playwright')})
    (Path(out) / "raw.json").write_text(json.dumps(raw, indent=1, ensure_ascii=False))
    return raw

def analyze(ctx, c, out, raw, st, contract):
    tol = H.deep_merge(DEFAULT_CS["tolerances"], (contract or {}).get("tolerances") or c["tolerances"])
    F = []
    if raw:
        F += analyze_components(raw, tol)
        F += analyze_tokens(raw, contract, (st or {}).get("css_color_tokens"), c["min_token_share"])
        F += analyze_chrome(raw, contract, out)
        F += analyze_patterns(raw, contract)
        F += analyze_copy(raw, contract)
    if st: F += analyze_static(st, contract)
    return apply_contract(F, contract)

def build_report(ctx, c, out, raw, st, F, contract_path, gate=None):
    from helix_environment import provenance
    out = Path(out); pages = sorted({f"{r['page']}{'#' + r['state'] if r.get('state', 'base') != 'base' else ''}" for r in (raw or {}).get("results", [])})
    ADOPTION.clear()
    if st:
        for role, comps in st["shared"].items(): ADOPTION[role] = sum(st["usage"].get("<" + Path(x).stem, 0) for x in comps)
    F = aggregate_static(F)
    allf = rank(merge_kinds([f for f in F if f["status"] != "exception"]))
    ns = c.get("top_static", 3); rt = [f for f in allf if f["layer"] == "runtime"]; stt = [f for f in allf if f["layer"] == "static"]
    top = rank(rt[: c["top"] - min(ns, len(stt))] + stt[: max(ns, c["top"] - len(rt))])[: c["top"]]
    rep = {"repo_name": ctx.repo.name, "created": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "pages": pages, "targets": [t["id"] for t in c["targets"]] if raw else [],
           "static_files": (st or {}).get("files", 0), "findings": F, "top": top, "contract": str(contract_path) if contract_path else None,
           "components": component_suggestions(F, st), "limitations": LIMITS, "gate": gate, "coverage": measurement_coverage(raw, st),
           "routes": route_coverage(ctx.repo, st, c["pages"] if raw else [])}
    rep["status"] = "INCOMPLETE" if not rep["coverage"] or any(not r["ok"] for r in rep["coverage"]) else "COMPLETE"
    rep['provenance'] = provenance(ctx.repo, models=[], tools=(raw or {}).get('provenance', {}).get('tools', {}))
    rep['input_provenance'] = {'runtime': (raw or {}).get('provenance'), 'static': (st or {}).get('provenance')}
    rep["problems"] = [p for r in rep["coverage"] for p in r.get("problems", [])]
    (out / "report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False))
    (out / "findings.json").write_text(json.dumps(F, indent=1, ensure_ascii=False))
    (out / "consistency-report.md").write_text(render_md(rep))
    try:
        (out / "consistency-report.html").write_text(render_html(rep, out))
        contact_sheet(out, top + rank(F), out / "consistency-top.png")
    except ImportError: H.log("brak Pillow: bez HTML z wycinkami i bez consistency-top.png")
    L = ["# Proponowane wspólne komponenty (do decyzji człowieka)", ""]
    for s in rep["components"]: L.append(f"- **{s['name']}** ({s['layer']}, {s.get('count') or '-'}×): {s['why']}\n  - gdzie: {summarize(s['where'] if isinstance(s['where'], list) else [s['where']], 'proposed-components.json')}")
    (out / "proposed-components.md").write_text("\n".join(L) + "\n")
    (out / "proposed-components.json").write_text(json.dumps(rep["components"], indent=1, ensure_ascii=False))
    return rep

# ---------------------------------------------------------------- commands
def out_dir(ctx, a, prefix="consistency"):
    o = Path(a.out) if getattr(a, "out", None) else getattr(ctx, "evidence_root", ctx.repo / "helix-evidence") / f"{prefix}-{dt.datetime.now():%Y%m%d-%H%M%S}"
    o.mkdir(parents=True, exist_ok=True); return o

def run_pipeline(ctx, a, c, out, runtime=True, static=True):
    contract, cpath = load_contract(ctx, c, getattr(a, "contract", None))
    raw = None
    if runtime:
        if getattr(a, "reuse", False) and (out / "raw.json").exists(): raw = json.loads((out / "raw.json").read_text())
        else: raw = run_runtime(ctx, c, out, getattr(a, "base_url", None), [x for x in (getattr(a, "pages", None) or "").split(",") if x] or None)
    st = static_scan(ctx.repo, c["static"]) if static else None
    if st: (out / "static.json").write_text(json.dumps({k: v for k, v in st.items()}, indent=1, ensure_ascii=False, default=list))
    F = analyze(ctx, c, out, raw, st, contract)
    prop = propose_contract(raw, st, F, c["pages"] if raw else [])
    (out / "design-contract.proposed.yaml").write_text("# Helix: PROPOZYCJA kontraktu spójności (z najczęstszego użycia). Do decyzji człowieka.\n" + dump_yaml(prop) + "\n")
    return raw, st, F, cpath if contract is not None else None

def cmd_consistency(ctx, a):
    c = cfg(ctx)
    if a.action == "baseline":
        out = out_dir(ctx, a); raw, st, F, cp = run_pipeline(ctx, a, c, out, runtime=not a.static_only and bool(c["pages"]))
        rep = build_report(ctx, c, out, raw, st, F, cp)
        if rep["status"] == "INCOMPLETE": raise SystemExit(2)
        n = write_baseline(Path(a.baseline) if a.baseline else baseline_path(ctx, c), F, measurement_coverage(raw, st))
        print(f"baseline: {n} znanych ustaleń zapisane w {a.baseline or baseline_path(ctx, c)} (raport: {out})"); return
    if a.action == "propose":
        out = out_dir(ctx, a); raw, st, F, cp = run_pipeline(ctx, a, c, out, runtime=not a.static_only and bool(c["pages"]))
        rep = build_report(ctx, c, out, raw, st, F, cp)
        if rep["status"] == "INCOMPLETE": raise SystemExit(2)
        print(out / "design-contract.proposed.yaml"); return
    runtime = not a.static_only and (a.action in ("scan", "all") or (a.action == "report" and (Path(a.out or "") / "raw.json").exists()))
    if a.action == "report": a.reuse = True
    out = out_dir(ctx, a)
    raw, st, F, cp = run_pipeline(ctx, a, c, out, runtime=runtime, static=a.static_only or a.action in ("code", "all", "report"))
    rep = build_report(ctx, c, out, raw, st, F, cp)
    sev = Counter(f["severity"] for f in rep["findings"] if f["status"] != "exception")
    print(f"spójność: {sum(sev.values())} ustaleń (high {sev['high']}, medium {sev['medium']}, low {sev['low']}); raport {out / 'consistency-report.md'}")
    for i, f in enumerate(rep["top"], 1): print(f"  {i:2}. [{f['severity']}] {f['title']}")
    if rep["status"] == "INCOMPLETE":
        print("INCOMPLETE: " + "; ".join(rep["problems"]))
        raise SystemExit(2)

def gate_consistency(ctx, cp_id=None, a=None):
    c = cfg(ctx); out = ctx.ev(cp_id) / "consistency" if cp_id else getattr(ctx, 'evidence_root', ctx.repo / "helix-evidence") / f"consistency-gate-{dt.datetime.now():%Y%m%d-%H%M%S}"
    out.mkdir(parents=True, exist_ok=True)
    class A: pass
    aa = a or A(); aa.out = str(out)
    raw, st, F, cp = run_pipeline(ctx, aa, c, out, runtime=bool(c["pages"]) and bool(c["base_url"]) and not getattr(aa, "static_only", False))
    bp = baseline_path(ctx, c); base = json.loads(bp.read_text()) if bp.exists() else None
    g = compare_baseline(F, base, set(c["gate"]["fail_on"]), measurement_coverage(raw, st), c["gate"].get("block_assumptions", False))
    if base is None: g["note"] = f"brak baseline ({bp}); wszystkie ustalenia traktowane jako nowe. Uruchom `helix consistency baseline`, żeby zapisać obecny dług."
    report = build_report(ctx, c, out, raw, st, F, cp, gate=g)
    r = {"gate": "consistency", "pass": g["pass"], "counts": {k: len(g[k]) for k in ("new", "worse", "fixed", "known", "advisory", "incomplete")},
         "report": str(out / "consistency-report.md"), "provenance": report['provenance'], "note": g.get("note") or ("INCOMPLETE: " + "; ".join(f"{x['id']}: {x['problems'][0]}" for x in g["incomplete"][:5]) if g["incomplete"] else None)}
    (out.parent / "consistency.json").write_text(json.dumps(r | {"new": [f["key"] for f in g["new"]], "worse": [f["key"] for f in g["worse"]]}, indent=1, ensure_ascii=False))
    return r
