"""Helix UX quality pack: device matrix scan, persona flows, agentic explorer, vision judge, report, coverage.
Used by bin/helix (`helix ux ...`, `helix gate ux cpN`, `helix coverage`). `H` is the helix module (set by bin/helix)."""
import copy, tempfile
import concurrent.futures as cf, datetime as dt, html, json, os, re, shutil, subprocess, sys, time, urllib.parse
from pathlib import Path
from helix_paths import normalize, relative as relative_path, within

H = None                                    # injected by bin/helix
BIN = Path(__file__).resolve().parent
UX_JS = BIN / "ux.cjs"
TEMPLATES = BIN.parent / "templates"

# ---------------------------------------------------------------- device matrix
# kind: phone | foldable | tablet | desktop. pw_device = Playwright descriptor name (portrait; " landscape" added).
DEVICE_PRESETS = {
    "phone-small":   {"pw_device": "iPhone SE (3rd gen)", "kind": "phone", "label": "iPhone SE (mały telefon)"},
    "iphone":        {"pw_device": "iPhone 17 Pro", "kind": "phone", "label": "iPhone 17 Pro"},
    "iphone-max":    {"pw_device": "iPhone 17 Pro Max", "kind": "phone", "label": "iPhone 17 Pro Max"},
    "android":       {"pw_device": "Pixel 9", "kind": "phone", "label": "Pixel 9"},
    "fold-cover":    {"pw_device": "Galaxy Z Fold 7 Cover", "kind": "foldable", "label": "Galaxy Z Fold 7 (złożony)"},
    "fold-open":     {"pw_device": "Galaxy Z Fold 7", "kind": "foldable", "label": "Galaxy Z Fold 7 (rozłożony)"},
    # Surface Duo is not in Playwright's device list: custom viewports (single screen, and spanned across both screens;
    # the 34px hinge / viewport-segments API is NOT emulated).
    "surface-duo":   {"viewport": [540, 720], "deviceScaleFactor": 2.5, "isMobile": True, "hasTouch": True, "engine": "chromium",
                      "userAgent": "Mozilla/5.0 (Linux; Android 11; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
                      "kind": "foldable", "label": "Surface Duo (1 ekran)"},
    "surface-duo-spanned": {"viewport": [720, 1114], "deviceScaleFactor": 2.5, "isMobile": True, "hasTouch": True, "engine": "chromium",
                      "userAgent": "Mozilla/5.0 (Linux; Android 11; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
                      "kind": "foldable", "label": "Surface Duo (2 ekrany)"},
    "ipad-mini":     {"pw_device": "iPad Mini", "kind": "tablet", "label": "iPad mini"},
    "ipad-pro":      {"pw_device": "iPad Pro 11", "kind": "tablet", "label": "iPad Pro 11"},
    "android-tablet": {"pw_device": "Galaxy Tab S9", "kind": "tablet", "label": "Galaxy Tab S9"},
    "laptop":        {"viewport": [1366, 768], "kind": "desktop", "label": "Laptop 1366×768"},
    "desktop":       {"viewport": [1920, 1080], "kind": "desktop", "label": "Desktop 1920×1080"},
    "ultrawide":     {"viewport": [3440, 1440], "kind": "desktop", "label": "Ultrawide 3440×1440"},
}
MATRICES = {
    "full": list(DEVICE_PRESETS),
    "quick": ["phone-small", "android", "fold-open", "ipad-mini", "laptop", "desktop"],
}
VARIANTS = ["dark", "reduced-motion", "zoom200", "large-text", "text-spacing", "long-content", "slow3g", "offline", "api-error", "api-empty"]
CHROMIUM_ONLY = {"slow3g"}
DEFAULT_VARIANT_TARGETS = {
    "zoom200": ["laptop/chromium", "desktop/chromium"],
    "slow3g": ["android@portrait"],
    "*": ["phone-small@portrait", "desktop/chromium"],
}
PERSONAS = {
    "novice": "Pierwszy raz w panelu, mało techniczny, czyta etykiety dosłownie, boi się, że coś zepsuje, nie zna skrótów.",
    "power-user": "Handlowiec używający panelu codziennie; chce zrobić rzecz najszybciej, irytują go dodatkowe kliknięcia i potwierdzenia.",
    "accountant": "Księgowa: interesują ją faktury, kwoty, NIP, daty, eksport do XLSX/PDF; sprawdza, czy liczby się zgadzają.",
    "warehouse": "Magazynier na tablecie w rękawiczkach, w hałasie; szuka zamówień do wydania, duże przyciski, mało czytania.",
    "mobile": "Klient w biegu na telefonie, jedna ręka, słaby zasięg, przerwy; chce szybko złożyć zamówienie i dostać potwierdzenie.",
}
DEFAULT_UX = {
    "enabled": False,
    "start_cmd": None, "base_url": None, "ready_timeout_s": 60,
    "allow_hosts": [],                    # extra hosts besides localhost (e.g. a STAGING host). Never production.
    "block_external": True,               # abort requests to non-allowed hosts (protects prod APIs/analytics)
    "pages": [{"name": "home", "path": "/"}],
    "matrix": "full",                     # full | quick | explicit list in "devices"
    "devices": None,                      # e.g. ["phone-small", {"id": "kiosk", "viewport": [1080, 1920], "kind": "tablet"}]
    "orientations": ["portrait", "landscape"],
    "desktop_engines": ["chromium", "webkit", "firefox"],   # filtered by what actually launches
    "mobile_engine": "native",            # native = device's engine (iPhone/iPad -> webkit) if installed, else chromium
    "variants": VARIANTS,
    "variant_targets": DEFAULT_VARIANT_TARGETS,
    "api_pattern": None,                  # glob for api-error / api-empty variants, e.g. "**/api/**"
    "empty_body": "[]",
    "checks": {"axe": True, "keyboard": True},
    "thresholds": {"tap_min": 44, "min_font_px": 12, "min_font_px_desktop": 11, "min_font_fail_px": 10,
                   "fixed_cover_max": 0.3, "lcp_warn_ms": 2500, "lcp_fail_ms": 4000, "cls_warn": 0.1, "cls_fail": 0.25,
                   "transfer_warn_kb": 3000, "slow3g_load_warn_s": 10, "offline_required": False},
    "flows": None,                        # path to flows YAML/JSON (relative to repo)
    "flow_devices": ["phone-small@portrait", "ipad-mini@landscape", "desktop/chromium"],
    "explore": {"enabled": False, "provider": "gemini-flash", "max_steps": 12, "devices": ["phone-small@portrait", "desktop/chromium"]},
    "judge": {"enabled": True, "provider": None, "targets": "representative", "parallel": 3, "max_pages": 4, "resume": False},
    "gate": {"variants_block": False, "judge_blocks": True},
    "parallel": 3, "locale": "pl-PL", "timezone": "Europe/Warsaw",
    "storage_state": None,                # Playwright storageState JSON (zalogowana sesja); per strona/flow/eksplorację: "storage_state" (null = bez sesji)
}
REPRESENTATIVE = ["phone-small@portrait", "phone-small@landscape", "iphone-max@portrait", "android@portrait", "fold-cover@portrait",
                  "fold-open@portrait", "surface-duo-spanned@landscape", "ipad-mini@portrait", "ipad-pro@landscape",
                  "laptop/chromium", "desktop/chromium", "ultrawide/chromium"]

def cfg(ctx): return H.deep_merge(DEFAULT_UX, ctx.cfg.get("ux") or {})

def engines(fresh=False):
    import helix_dependencies as deps
    cache = (deps.STATE_ROOT / "cache" if deps.STATE_ROOT else Path.home() / ".cache/helix") / "engines.json"
    if cache.exists() and not fresh and time.time() - cache.stat().st_mtime < 86400: return json.loads(cache.read_text())
    p = subprocess.run(["node", str(UX_JS), "engines"], capture_output=True, text=True, timeout=120, env=node_env())
    j = json.loads(p.stdout.strip().splitlines()[-1]) if p.returncode == 0 and p.stdout.strip() else {"chromium": False, "webkit": False, "firefox": False}
    cache.parent.mkdir(parents=True, exist_ok=True); cache.write_text(json.dumps(j)); return j

def node_env(): return dict(os.environ, HELIX_PLAYWRIGHT=H.PW_PATH if H else os.environ.get("HELIX_PLAYWRIGHT", ""))

PW_DEFAULT_ENGINE = {"iPhone": "webkit", "iPad": "webkit"}
def native_engine(preset):
    if preset.get("engine"): return preset["engine"]
    name = preset.get("pw_device") or ""
    return next((e for k, e in PW_DEFAULT_ENGINE.items() if name.startswith(k)), "chromium")

def build_targets(u, avail):
    """Expand presets x orientations x engines into concrete targets."""
    names = u["devices"] or MATRICES.get(u["matrix"], MATRICES["full"])
    ok = lambda e: bool(avail.get(e))
    out = []
    for n in names:
        if isinstance(n, str) and n not in DEVICE_PRESETS: raise SystemExit(f"unknown device preset {n!r}; known: {', '.join(DEVICE_PRESETS)}")
        p = dict(DEVICE_PRESETS[n], preset=n) if isinstance(n, str) else dict(n, preset=n.get("id", "custom"))
        kind = p.get("kind", "desktop")
        if kind == "desktop":
            for e in [e for e in u["desktop_engines"] if ok(e)] or ["chromium"]:
                out.append({**p, "id": f"{p['preset']}/{e}", "engine": e, "orientation": None})
        else:
            want = native_engine(p) if u["mobile_engine"] == "native" else u["mobile_engine"]
            eng, note = (want, None) if ok(want) else ("chromium", f"{want} niedostępny na tej maszynie – emulacja w chromium")
            for o in p.get("orientations") or u["orientations"]:
                out.append({**p, "id": f"{p['preset']}@{o}", "engine": eng, "orientation": o, "engine_note": note, "mobile": True})
    vt = u["variant_targets"]
    for t in out:
        t["variants"] = [v for v in u["variants"] if t["id"] in (vt.get(v) or vt.get("*") or [])
                         and not (v in CHROMIUM_ONLY and t["engine"] != "chromium")]
    return out

LOCAL = ("localhost", "127.0.0.1", "::1", "0.0.0.0")
def assert_safe_url(url, allow):
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host in LOCAL or re.search(r"\.(localhost|local|test)$", host) or host in [a.lower() for a in allow or []]: return host
    raise SystemExit(f"UX pack refuses to run against {host!r}: only localhost/*.local/*.test or ux.allow_hosts (staging). Never production.")

def load_flows(ctx, u):
    if not u.get("flows"): return {"flows": [], "explore": [], "personas": {}}
    f = ctx.repo / u["flows"]
    if f.suffix in (".yaml", ".yml"):
        from helix_dependencies import load_yaml
        d = load_yaml(f)
    else: d = json.loads(f.read_text())
    d = d or {}; d.setdefault("flows", []); d.setdefault("explore", []); d.setdefault("personas", {})
    for fl in d["flows"]:
        if not fl.get("id") or not isinstance(fl.get("steps"), list): raise SystemExit(f"flow without id/steps in {f}: {fl}")
    return d

def job_for(ctx, u, out, targets, extra=None):
    from helix_environment import provenance
    j = {"out": str(out), "base_url": u["base_url"], "allow_hosts": u["allow_hosts"], "block_external": u["block_external"],
         "provenance": provenance(ctx.repo, models=[]),
         "pages": u["pages"], "targets": targets, "variants": u["variants"], "checks": u["checks"], "thresholds": u["thresholds"],
         "api_pattern": u["api_pattern"], "empty_body": u["empty_body"], "parallel": u["parallel"], "locale": u["locale"], "timezone": u["timezone"], "storage_state": u.get("storage_state")}
    governor = getattr(ctx, '_ux_governor', None)
    if governor:
        j['resources'] = dict(governor.policy, path=str(governor.current_path))
    j.update(extra or {}); jf = Path(out) / f"job-{(extra or {}).get('_mode', 'scan')}.json"; jf.write_text(json.dumps(j, indent=1, ensure_ascii=False))
    return jf

def node_timeout(jf):
    """Limit skanu rośnie z pracą: 128 stron × 28 urządzeń projektu B potrzebowało ok. 80 min, a stała godzina ucięła 6 urządzeń.
    6 s na komórkę urządzenie×strona (pomiar: ok. 1,25 s przy 3 zadaniach, do 4× wolniej przy presji zasobów), najmniej godzina."""
    job = json.loads(Path(jf).read_text())
    # Warianty stanów (pusty, błąd API...) to kolejne przejścia stron: na projekcie B 10 wariantów × 128 stron na 2 urządzeniach.
    renders = max(1, len(job.get('targets') or [])) + 2 * len(job.get('variants') or [])
    return max(3600, 6 * len(job.get('pages') or []) * renders)

def run_node(mode, jf, timeout=None):
    timeout = timeout or node_timeout(jf)
    p = subprocess.run(["node", str(UX_JS), mode, str(jf)], stdout=subprocess.PIPE, text=True, timeout=timeout, env=node_env())  # stderr = live progress
    result_path = Path(json.loads(Path(jf).read_text())['out']) / (mode + '.json')
    if result_path.exists() and json.loads(result_path.read_text()).get('run_status') == 'resource_paused':
        from helix_resources import ResourcePaused
        raise ResourcePaused('resource_paused: UX runner zachował wyniki i niesprawdzone jednostki')
    if p.returncode != 0: raise RuntimeError(f"ux.cjs {mode} failed (exit {p.returncode}): {(p.stdout or '')[-800:]}")
    return p.stdout

def _atomic_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=1); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def _ux_progress(ctx):
    governor = getattr(ctx, '_ux_governor', None)
    progress = getattr(ctx, '_ux_progress_state', None)
    if governor and progress is not None:
        current = governor.decision()
        progress['resources'] = dict(requested_jobs=governor.requested_jobs, max_pause_s=governor.policy['max_pause_s'],
                                     decisions=governor.history, current=current)
        _atomic_json(ctx._ux_out / 'ux-progress.json', progress)


def _ux_wait(ctx):
    governor = getattr(ctx, '_ux_governor', None)
    if not governor: return None
    if governor.decision()['effective_jobs'] == 0:
        progress = getattr(ctx, '_ux_progress_state', None)
        if progress is not None: progress['run_status'] = 'resource_wait'
        governor.wait(stop=lambda: _ux_progress(ctx))
        if progress is not None: progress['run_status'] = 'in_progress'
    _ux_progress(ctx)
    return governor.decision()


class Server:
    def __init__(self, ctx, u):
        self.p = None
        if u.get("start_cmd"):
            self.p = subprocess.Popen(u["start_cmd"], cwd=ctx.repo, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        import urllib.request
        deadline = time.time() + u.get("ready_timeout_s", 60)
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(u["base_url"], timeout=2): pass
                return
            except urllib.error.HTTPError as error:
                error.close(); time.sleep(0.5)
            except Exception: time.sleep(0.5)
        self.__exit__(); raise SystemExit(f"app not reachable at {u['base_url']} (start_cmd={u.get('start_cmd')!r})")
    def __enter__(self): return self
    def __exit__(self, *a):
        if self.p:
            import signal
            try: os.killpg(self.p.pid, signal.SIGTERM)
            except Exception: pass

# ---------------------------------------------------------------- explorer (agentic persona)
EXPLORE_SCHEMA = BIN.parent / "schemas/ux_explore.json"
def explore(ctx, u, out, targets, specs, personas):
    """A model gets screenshot + DOM summary and tries to reach a goal as a persona. Advisory (never blocks the gate)."""
    from helix_environment import provenance, normalize_models, normalize_tools
    execution = provenance(ctx.repo, models=[])
    pv = u["explore"]["provider"]; results = []
    want = u["explore"].get("devices") or []
    def save_results():
        execution['models'] = normalize_models([receipt for row in results for receipt in row['model_receipts']])
        execution['tools'].update({name: receipt for name, receipt in normalize_tools(
            _merge_tools(_runtime_tools({'results': results}, targets))).items() if receipt['used']})
        _atomic_json(Path(out) / 'explore.json', {'kind': 'explore', 'results': results, 'provenance': execution,
                                                  'run_status': 'partial' if any(x.get('status') == 'not_checked' for x in results) else 'complete'})
    save_results()
    # Zadania eksploratora (cel × urządzenie) są niezależne: idą równolegle (ux.explore.parallel, domyślnie 3).
    import threading
    from concurrent.futures import ThreadPoolExecutor
    lock = threading.Lock()
    def one(spec, t):
        persona = spec.get("persona", "novice"); pdesc = personas.get(persona) or PERSONAS.get(persona) or persona
        _ux_wait(ctx)
        d = Path(out) / "explore" / re.sub(r"[^\w.-]+", "_", f"{spec.get('id', persona)}") / re.sub(r"[^\w.-]+", "_", t["id"]); d.mkdir(parents=True, exist_ok=True)
        srv = subprocess.Popen(["node", str(UX_JS), "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=node_env(), bufsize=1)
        def cmd(o):
            srv.stdin.write(json.dumps(o) + "\n"); srv.stdin.flush(); return json.loads(srv.stdout.readline() or '{"ok":false,"error":"runner died"}')
        job = {"base_url": u["base_url"], "allow_hosts": u["allow_hosts"], "block_external": u["block_external"], "locale": u["locale"], "timezone": u["timezone"],
               "storage_state": spec.get("storage_state", u.get("storage_state"))}
        r = {"id": spec.get("id", persona), "persona": persona, "goal": spec["goal"], "target": t["id"], "steps": [], "friction": [],
             "confusing_copy": [], "model_success": False, "verified_success": None, "models": [], "model_receipts": [], "engine": t["engine"]}
        o = cmd({"cmd": "open", "target": t, "path": spec.get("start", "/"), "job": job})
        r["tools"] = o.get("tools") if "tools" in o else [
            {"tool": name, "used": True, "version": None} for name in ("node", "playwright", *([t["engine"]] if o.get("ok") else []))]
        if not o.get("ok"):
            r["error"] = o.get("error"); cmd({"cmd": "quit"})
            with lock: results.append(r)
            return
        hist = []; t0 = time.time()
        for n in range(1, int(spec.get("max_steps") or u["explore"]["max_steps"]) + 1):
            from helix_resources import ResourcePaused
            try: _ux_wait(ctx)
            except ResourcePaused:
                r.update(status='not_checked', error='resource_paused')
                results.append(r); save_results()
                cmd({'cmd': 'close'}); cmd({'cmd': 'quit'}); srv.wait(timeout=30)
                raise
            shot = d / f"{n:02d}.png"; obs = cmd({"cmd": "observe", "shot": str(shot)})
            els = "\n".join(f"[{e['i']}] {e['tag']}{'/' + e['type'] if e.get('type') else ''} text={e['text']!r} name={e['name']!r}"
                            f"{' DISABLED' if e['disabled'] else ''}{'' if e['in_view'] else ' (poza ekranem)'} box={e['box']}" for e in obs.get("elements", []))
            prompt = H.fill("ux_explore", persona=persona, persona_desc=pdesc, goal=spec["goal"], device=t.get("label", t["id"]) + f" ({t['id']})",
                            step=n, url=obs.get("url"), title=obs.get("title"), elements=els[:9000], text=(obs.get("text") or "")[:2500],
                            history="\n".join(hist[-12:]) or "(start)", reported="\n".join("- " + f.get("description", "")[:120] for f in r["friction"]) or "(nothing yet)", js_errors=json.dumps(obs.get("js_errors") or [], ensure_ascii=False))
            try: text, used = H.ask(ctx, pv, prompt, images=[shot], schema=EXPLORE_SCHEMA, out_dir=d, substitute=True)
            except H.ProviderError as ex: r["error"] = f"model: {ex}"[:300]; break
            j = H.extract_json(text) or {}; r["models"].append(f"{used['provider']}/{used['model']}")
            r["model_receipts"].append({**used, "role": "ux_explorer"})
            seen = {re.sub(r"\W+", "", f.get("description", "").lower())[:40] for f in r["friction"]}
            for f in j.get("friction", []):          # models tend to repeat the same friction every step
                k = re.sub(r"\W+", "", f.get("description", "").lower())[:40]
                if k and k not in seen: seen.add(k); r["friction"].append({**f, "step": n})
            r["confusing_copy"] += [c for c in j.get("confusing_copy", []) if c not in r["confusing_copy"]]
            act = j.get("action"); step = {"n": n, "url": obs.get("url"), "thought": j.get("thought", "")[:300], "action": act,
                                           "i": j.get("i"), "value": j.get("value"), "shot": str(relative_path(shot, out))}
            if act in ("done", "give_up"):
                r["model_success"] = act == "done" and bool(j.get("success")); r["steps"].append(step); break
            res = cmd({"cmd": "act", "action": act, "i": None if j.get("i", -1) in (None, -1) else j["i"], "value": j.get("value")})
            step["ok"] = res.get("ok"); step["error"] = res.get("error")
            target_el = next((e for e in obs.get("elements", []) if e["i"] == j.get("i")), None)
            hist.append(f"{n}. {act} [{j.get('i')}] {target_el['text'] if target_el else ''} {j.get('value') or ''} -> {'ok' if res.get('ok') else 'BŁĄD ' + str(res.get('error'))[:80]}")
            r["steps"].append(step)
        # verify the model's claim against the page (truth gate spirit: a model saying "done" is not proof)
        if spec.get("success_text"):
            obs = cmd({"cmd": "observe", "shot": str(d / "final.png")})
            r["verified_success"] = bool(re.search(spec["success_text"], obs.get("text") or "", re.I))
        r["seconds"] = round(time.time() - t0, 1); r["actions"] = len([s for s in r["steps"] if s["action"] not in ("done", "give_up")])
        r["dead_ends"] = [s for s in r["steps"] if s.get("ok") is False]
        succ = r["verified_success"] if r["verified_success"] is not None else r["model_success"]
        r["status"] = "fail" if not succ else ("warn" if any(f.get("severity") == "high" for f in r["friction"]) or r["dead_ends"] else "pass")
        # Brak modelu (limit, niedostępność) to nie porażka aplikacji: zadanie jest niesprawdzone (projekt B: 6 × „fail” bez kroku).
        if str(r.get("error", "")).startswith("model:"): r["status"] = "not_checked"
        H.log(f"explore {r['status'].upper()} {r['id']} {t['id']}: {r['actions']} akcji, model_success={r['model_success']} verified={r['verified_success']}")
        cmd({"cmd": "close"}); cmd({"cmd": "quit"}); srv.wait(timeout=30)
        with lock: results.append(r); save_results()

    pairs = []
    for spec in specs:
        pairs += [(spec, t) for t in targets if t["id"] in (spec.get("devices") or want)]
    with ThreadPoolExecutor(max_workers=max(1, int(u["explore"].get("parallel") or 3))) as pool:
        for future in [pool.submit(one, spec, t) for spec, t in pairs]: future.result()
    execution["models"] = normalize_models([receipt for row in results for receipt in row["model_receipts"]])
    execution["tools"].update({name: receipt for name, receipt in
        normalize_tools(_merge_tools(_runtime_tools({"results": results}, targets))).items() if receipt["used"]})
    (Path(out) / "explore.json").write_text(json.dumps({"kind": "explore", "results": results, "provenance": execution,
        "run_status": "partial" if any(x.get("status") == "not_checked" for x in results) else "complete"}, indent=1, ensure_ascii=False))
    return results

# ---------------------------------------------------------------- judge (vision model per device)
JUDGE_SCHEMA = BIN.parent / "schemas/ux_judge.json"
def contact_sheet(out, target_id, rows, dest):
    """rows: [(page_name, rel_png)] -> one image with pages side by side (keeps judge calls/tokens low)."""
    from PIL import Image, ImageDraw
    ims = []
    for name, rel in rows:
        p = Path(out) / rel
        if not p.exists(): continue
        im = Image.open(p).convert("RGB"); w = 520 if im.width < im.height else 1100
        im = im.resize((w, int(im.height * w / im.width))); im = im.crop((0, 0, w, min(im.height, 2600))); ims.append((name, im))
    if not ims: return None
    W = sum(i.width for _, i in ims) + 20 * (len(ims) + 1); Hh = max(i.height for _, i in ims) + 60
    sheet = Image.new("RGB", (W, Hh), (128, 128, 128)); dr = ImageDraw.Draw(sheet); x = 20
    for name, im in ims:
        dr.text((x, 15), f"PAGE: {name}", fill=(255, 255, 0)); sheet.paste(im, (x, 45)); x += im.width + 20
    sheet.save(dest); return dest

BACKEND = re.compile(r"/(?:functions|rest|rpc|graphql|api)/")
SCREEN_STATES = ("content", "redirected", "data_error", "empty")


def screen_state(r):
    """Czy zrzut pokazuje treść strony. Projekt B: 53 ze 128 zrzutów to ekran startowy po przekierowaniu, błąd funkcji
    serwerowej albo pusta strona, a sędzia oceniał je jak zwykłe strony. redirected: adres końcowy inny niż żądany;
    data_error: odpowiedź 5xx zaplecza albo błąd 4xx zaplecza z widocznym komunikatem błędu; empty: mało tekstu i kontrolek."""
    s = r.get("screen") or {}
    if s.get("redirected"): return "redirected"
    backend = [e for e in ((r.get("collect") or {}).get("http_errors") or []) if BACKEND.search(e)]
    if any(e[:1] == "5" for e in backend) or (backend and s.get("error_text")): return "data_error"
    lay = r.get("layout") or {}
    if "text_chars" in lay and lay["text_chars"] < 120 and (lay.get("interactive_count") or 0) <= 3: return "empty"
    return "content"


def judge(ctx, u, out, scan, targets):
    from helix_environment import provenance, normalize_models
    execution = provenance(ctx.repo, models=[])
    jc = u["judge"]; prov = jc.get("provider") or ctx.cfg["providers"].get("visual_judge", "gemini")
    sel = jc["targets"]; ids = [t["id"] for t in targets]
    chosen = ids if sel == "all" else [i for i in (REPRESENTATIVE if sel == "representative" else sel) if i in ids]
    jd = Path(out) / "judge"; jd.mkdir(exist_ok=True)
    base = [r for r in scan["results"] if r["variant"] == "base"]
    def one(tid):
        t = next(x for x in targets if x["id"] == tid)
        # Wszystkie strony urządzenia, w arkuszach po max_pages (jeden arkusz = jedno wywołanie modelu); żadna strona nie jest pomijana.
        listed = [(r["page"], r.get("full_shot") or r.get("shot")) for r in base if r["target"] == tid]
        every = [(name, shot) for name, shot in listed if shot and (Path(out) / shot).exists()]
        missing = sorted(name for name, shot in listed if (name, shot) not in every)   # strona bez zrzutu nie została oceniona
        # Zrzut bez treści strony (przekierowanie, błąd danych, pusty) nie idzie do sędziego: ocena dotyczyłaby innego ekranu.
        states = {r["page"]: screen_state(r) for r in base if r["target"] == tid}
        skipped = {name: states[name] for name, _ in every if states.get(name, "content") != "content"}
        every = [(name, shot) for name, shot in every if name not in skipped]
        size = max(1, int(jc["max_pages"] or 4)); merged = {"issues": [], "scores": {}, "summary": [], "valid": True, "_sheets": []}
        # Wznowienie na poziomie arkusza: ocenione arkusze poprzedniej próby zostają (ich uwagi i oceny), model dostaje
        # tylko arkusze z błędem. Projekt B: brak 1-3 arkuszy kosztował ponowną ocenę 32 arkuszy na urządzenie.
        prior = partial.get(tid) or {}
        kept = {tuple(s["pages"]) for s in prior.get("_sheets", []) if not s.get("error") and s.get("pages")}
        if kept:
            merged.update(issues=list(prior.get("issues") or []), scores=dict(prior.get("scores") or {}),
                          summary=[prior["summary"]] if prior.get("summary") else [], valid=prior.get("valid", True) is not False,
                          _sheets=[s for s in prior["_sheets"] if tuple(s.get("pages") or ()) in kept], _used=prior["_used"])
            if prior.get("_image"): merged["_image"] = prior["_image"]
        for number, start in enumerate(range(0, len(every), size), 1):
            rows = every[start:start + size]
            if tuple(sorted(n for n, _ in rows)) in kept: continue
            img = contact_sheet(out, tid, rows, jd / (re.sub(r"[^\w.-]+", "_", tid) + (f"-{number:02d}" if len(every) > size else "") + ".jpg"))
            if not img: continue
            names = {n for n, _ in rows}
            auto = [f"{r['page']}: [{f['severity']}] {f['message']}" for r in base if r["target"] == tid and r["page"] in names for f in r["findings"] if f["severity"] != "info"]
            prompt = H.fill("ux_judge", device=f"{t.get('label', tid)} ({tid}, engine {t['engine']}, viewport {t.get('viewport') or t.get('pw_device')})",
                            pages=", ".join(n for n, _ in rows), automated="\n".join(auto[:40]) or "(none)")
            try:
                text, used = H.ask(ctx, prov, prompt, images=[img], schema=JUDGE_SCHEMA, out_dir=jd, substitute=True)
            except H.ProviderError as ex:
                merged["_sheets"].append({"pages": sorted(names), "error": str(ex)[:300]}); continue
            j = H.extract_json(text) or {}
            merged["issues"] += j.get("issues") or []
            for key, value in (j.get("scores") or {}).items():   # najgorsza ocena arkusza decyduje o urządzeniu
                if isinstance(value, (int, float)): merged["scores"][key] = min(value, merged["scores"].get(key, value))
            if j.get("summary"): merged["summary"].append(j["summary"])
            merged["valid"] = merged["valid"] and j.get("valid", True) is not False
            merged["_used"] = used; merged["_image"] = str(relative_path(img, out))
            merged["_sheets"].append({"pages": sorted(names), "image": str(relative_path(img, out)), "issues": len(j.get("issues") or [])})
        if skipped: merged["skipped_pages"] = skipped
        if not merged["_sheets"]: return tid, ({"error": "no screenshots"} if not skipped else {"error": "no content screens", "skipped_pages": skipped})
        if "_used" not in merged: return tid, {"error": "; ".join(s["error"] for s in merged["_sheets"] if s.get("error"))[:300], "_sheets": merged["_sheets"], "skipped_pages": skipped}
        merged["summary"] = "\n\n".join(merged["summary"])
        failed = [s for s in merged["_sheets"] if s.get("error")]
        if failed or missing: merged["not_judged_pages"] = sorted({p for s in failed for p in s["pages"]} | set(missing))
        return tid, merged
    # judge.resume: urządzenia ocenione w całości w poprzedniej próbie (ten sam skan) zostają, ponownie idą tylko te z błędem
    # albo nieocenionymi stronami; po wyczerpaniu limitu modelu nie oceniamy od zera tego, co już ocenione.
    previous, partial = {}, {}
    if jc.get("resume") and (Path(out) / "judge.json").is_file():
        try: stored = json.loads((Path(out) / "judge.json").read_text())
        except ValueError: stored = {}
        previous = {k: v for k, v in stored.items() if k in chosen and isinstance(v, dict) and v.get("_used")
                    and not v.get("error") and not v.get("not_judged_pages")}
        partial = {k: v for k, v in stored.items() if k in chosen and k not in previous and isinstance(v, dict)
                   and v.get("_used") and isinstance(v.get("_sheets"), list)}
    res = dict(previous); pending = iter([t for t in chosen if t not in previous]); active = []; next_target = next(pending, None); paused = None
    governor = getattr(ctx, '_ux_governor', None)
    from helix_resources import ResourcePaused
    def save_results():
        execution['models'] = normalize_models([{**j['_used'], 'role': 'ux_judge'} for j in res.values() if j.get('_used')])
        _atomic_json(Path(out) / 'judge.json', {**res, '_provenance': execution,
            '_resources': dict(run_status='resource_paused' if paused else 'complete' if len(res) == len(chosen) else 'in_progress',
                               not_checked=[target for target in chosen if target not in res], decisions=governor.history if governor else [])})
    with cf.ThreadPoolExecutor(max_workers=jc['parallel']) as executor:
        while active or next_target is not None:
            try:
                while next_target is not None:
                    decision = governor.decision() if governor else {'effective_jobs': jc['parallel']}
                    if decision['effective_jobs'] == 0:
                        if active: break
                        _ux_wait(ctx); continue
                    if len(active) >= min(jc['parallel'], decision['effective_jobs']): break
                    active.append(executor.submit(one, next_target)); next_target = next(pending, None)
            except ResourcePaused as exc:
                paused = exc; next_target = None
            if active:
                # Nie czekamy na najstarsze urządzenie (32 arkusze to ok. 30 min): co 30 s odbieramy zakończone
                # i ponownie pytamy strażnika zasobów, żeby dołożyć urządzenia, gdy zasoby wrócą.
                done, _ = cf.wait(active, timeout=30, return_when=cf.FIRST_COMPLETED)
                for future in [f for f in active if f in done]:
                    active.remove(future); tid, j = future.result()
                    res[tid] = j; H.log(f"judge {tid}: " + (j.get('error') or f"scores={j.get('scores')} issues={len(j.get('issues', []))}"))
            save_results()
    save_results()
    if paused: raise paused
    return res

# ---------------------------------------------------------------- report
ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌", None: "·"}
RANK = {"pass": 0, "warn": 1, "fail": 2}
def worse(a, b): return a if RANK.get(a, -1) >= RANK.get(b, -1) else b

def judge_cell(issues, page):
    st = "pass"
    for i in issues:
        if i.get("page") not in (page, "*", "all", ""): continue
        if i.get("severity") == "high" and i.get("code_fixable"): st = worse(st, "fail")
        elif i.get("severity") in ("high", "medium"): st = worse(st, "warn")
    return st

def ran_checks(u, scan, flows, expl, jdg, targets):
    """What this run actually exercised (used by `helix coverage`)."""
    s = {"overflow", "clipped", "overlap", "fixed-covers", "small-text", "meta-viewport", "console", "requests", "broken-image", "blank", "devices"}
    res = scan["results"] if scan else []
    if not res: s = set()
    if any(r.get("touch") for r in res): s.add("tap-target")
    if any(isinstance(r.get("axe"), list) for r in res): s.add("a11y")
    if any(r.get("perf") for r in res): s.add("perf")
    if any(r.get("keyboard") for r in res): s.add("kbd")
    s |= {r["variant"] for r in res if r["variant"] != "base"}
    used_targets = [t for t in targets if t["id"] in {r.get("target") for r in res}]
    kinds = {t.get("kind") for t in used_targets}; s |= {f"devices:{k}" for k in kinds}
    s |= {f"engine:{e}" for e in {t["engine"] for t in used_targets}}
    if any(t.get("preset", "").startswith("surface-duo") or t.get("kind") == "foldable" for t in used_targets): s.add("devices:foldable")
    if flows: s.add("flows")
    if any(st["step"].get("download") for f in (flows or []) for st in f["steps"]): s.add("download")
    if any(st["step"].get("offline") is not None for f in (flows or []) for st in f["steps"]): s.add("flows:offline")
    if expl: s.add("explore")
    if jdg and any(not j.get("error") for j in jdg.values()): s.add("judge")
    if u.get("block_external") and (res or flows or expl): s.add("external-blocked")
    return sorted(s)

def _runtime_tools(payload, targets):
    """Actual runner receipts, with explicit unknown versions for older artifacts."""
    if not payload: return []
    rows = payload.get("results") or []
    tools = payload.get("tools")
    if tools is not None: return tools
    receipts = [receipt for row in rows for receipt in row.get("tools", [])]
    if rows:
        receipts += [{"tool": name, "version": None, "used": True} for name in ("node", "playwright")]
        engines_by_target = {t["id"]: t.get("engine") for t in targets}
        for row in rows:
            engine = row.get("engine") or engines_by_target.get(row.get("target"))
            if engine and "tools" not in row: receipts.append({"tool": engine, "version": None, "used": True})
    return receipts

def _merge_tools(receipts):
    # An older partial artifact must not erase an observed version from another step.
    merged = {}
    for receipt in receipts:
        name = receipt.get("tool")
        if name and (name not in merged or receipt.get("version")):
            merged[name] = receipt
    return list(merged.values())

def build_report(ctx, u, out, targets):
    from helix_environment import provenance
    out = Path(out); rd = lambda n: json.loads((out / n).read_text()) if (out / n).exists() else None
    progress = rd('ux-progress.json') or {}
    aggregation_only = progress.get('aggregation_only', False)
    inputs = {name: rd(name) for name in ('scan.json', 'flows.json', 'explore.json', 'judge.json')}
    historical_sources = {}
    for name in progress.get('stale_inputs', []):
        payload = inputs.get(name) if aggregation_only else inputs.pop(name, None)
        if payload is not None:
            historical_sources[name] = dict(artifact=name, stale=True,
                provenance=payload.get('_provenance' if name == 'judge.json' else 'provenance'))
    scan, fl, ex, jdg = (inputs.get(name) for name in ('scan.json', 'flows.json', 'explore.json', 'judge.json'))
    jdg = jdg or {}
    judge_provenance = jdg.pop("_provenance", None)
    judge_resources = jdg.pop('_resources', {})
    incomplete = (progress.get('run_status') not in (None, 'complete') or
                  any((payload or {}).get('run_status') not in (None, 'complete') for payload in (scan, fl, ex, judge_resources)))
    run_status = 'resource_paused' if progress.get('run_status') == 'resource_paused' or any(
        (payload or {}).get('run_status') == 'resource_paused' for payload in (scan, fl, ex, judge_resources)) else 'partial' if incomplete else 'complete'
    not_checked = dict(scan=(scan or {}).get('not_checked', []), flows=(fl or {}).get('not_checked', []),
                       judge=judge_resources.get('not_checked', []), stages=[name for name, value in progress.get('stages', {}).items() if value != 'complete'])
    flows = (fl or {}).get("results", []); expl = (ex or {}).get("results", [])
    res = (scan or {}).get("results", []); pages = [p["name"] for p in u["pages"]]
    models = [{**j["_used"], "role": "ux_judge"} for j in jdg.values() if j.get("_used")]
    for row in expl:
        if "model_receipts" in row: models.extend(row["model_receipts"])
        else:
            for recorded in row.get("models", []):
                if isinstance(recorded, str) and "/" in recorded:
                    provider, model = recorded.split("/", 1)
                    models.append({"provider": provider, "model": model, "role": "ux_explorer"})
    execution = provenance(ctx.repo, models=[] if aggregation_only else models, tools=[] if aggregation_only else _merge_tools([
        receipt for payload in (scan, fl, ex) for receipt in _runtime_tools(payload, targets)]))
    tids = [t["id"] for t in targets]; tmeta = {t["id"]: t for t in targets}
    matrix = {}; not_judged = []; not_content = []
    for t in tids:
        for p in pages:
            r = next((x for x in res if x["target"] == t and x["page"] == p and x["variant"] == "base"), None)
            if not r: continue
            state = screen_state(r)
            if state != "content": not_content.append({"target": t, "page": p, "state": state, "final_path": (r.get("screen") or {}).get("final_path")})
            ji = (jdg.get(t) or {}).get("issues", [])
            # Strona urządzenia, które sędzia miał ocenić, a nie ocenił (błąd modelu, brak zrzutu), nie dostaje oceny „pass”.
            unjudged = t in jdg and state == "content" and (jdg[t].get("error") or p in (jdg[t].get("not_judged_pages") or []))
            if unjudged: not_judged.append({"target": t, "page": p})
            unjudged = unjudged or (t in jdg and state != "content")
            jst = judge_cell(ji, p) if t in jdg and not unjudged else None
            st = r["status"] if not (u["gate"]["judge_blocks"] and jst) else worse(r["status"], jst)
            matrix.setdefault(t, {})[p] = {"status": st, "auto": r["status"], "judge": "not_checked" if unjudged else jst,
                "fails": sum(f["severity"] == "fail" for f in r["findings"]), "warns": sum(f["severity"] == "warn" for f in r["findings"]),
                "shot": r.get("shot"), "perf": r.get("perf"), "screen": state}
    vmatrix = {}
    for r in res:
        if r["variant"] == "base": continue
        vmatrix.setdefault(f"{r['variant']} · {r['target']}", {})[r["page"]] = {"status": r["status"], "shot": r.get("shot"),
            "findings": [f for f in r["findings"] if f["severity"] != "info"]}
    # aggregate findings by (check, message-stem) across devices
    agg = {}
    for r in res:
        for f in r["findings"]:
            key = (f["check"], re.sub(r"\d+", "N", f["message"])[:90])
            a = agg.setdefault(key, {"check": f["check"], "severity": f["severity"], "message": f["message"], "targets": set(), "pages": set(), "variants": set(), "detail": f.get("detail")})
            a["severity"] = worse(a["severity"], f["severity"]) if f["severity"] in RANK else a["severity"]
            a["targets"].add(r["target"]); a["pages"].add(r["page"]); a["variants"].add(r["variant"])
    top = sorted(agg.values(), key=lambda a: (-RANK.get(a["severity"], -1), -len(a["targets"])))
    for a in top: a["targets"], a["pages"], a["variants"] = sorted(a["targets"]), sorted(a["pages"]), sorted(a["variants"])
    jissues = [{**i, "target": t, "model": (j.get("_used") or {}).get("model")} for t, j in jdg.items() for i in j.get("issues", [])]
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for row in matrix.values():
        for c in row.values(): counts[c["status"]] += 1
    vcounts = {"pass": 0, "warn": 0, "fail": 0}
    for row in vmatrix.values():
        for c in row.values(): vcounts[c["status"]] += 1
    blocking = counts["fail"] + (vcounts["fail"] if u["gate"]["variants_block"] else 0) + sum(f["status"] == "fail" for f in flows)
    rep = {"at": H.now(), "provenance": execution, "run_status": run_status, "not_checked": not_checked,
           "resources": progress.get("resources", {}),
           "reason": progress.get("reason"), "previous_attempt": progress.get("previous_attempt"),
           "stale_inputs": progress.get("stale_inputs", []),
           "historical_sources": historical_sources,
           "evidence_scope": 'historical_artifact_aggregation' if aggregation_only else 'current_attempt',
           "input_provenance": {"scan": (scan or {}).get("provenance"), "flows": (fl or {}).get("provenance"),
                                "explore": (ex or {}).get("provenance"), "judge": judge_provenance},
           "base_url": u["base_url"], "pages": pages, "targets": [{k: tmeta[t].get(k) for k in ("id", "label", "kind", "engine", "engine_note")} for t in tids],
           "matrix": matrix, "variants": vmatrix, "counts": counts, "variant_counts": vcounts,
           "flows": [{k: f.get(k) for k in ("flow", "persona", "goal", "target", "status", "ok", "failed_step", "seconds", "interactions", "friction")} |
                     {"error": next((s.get("error") for s in f["steps"] if not s["ok"]), None)} for f in flows],
           "explore": [{k: e.get(k) for k in ("id", "persona", "goal", "target", "status", "model_success", "verified_success", "actions", "seconds", "friction", "confusing_copy", "error", "models")} for e in expl],
           "judge": {t: {k: j.get(k) for k in ("scores", "summary", "error", "_image")} | {"model": str((j.get("_used") or {}).get("provider") or "") + "/" + str((j.get("_used") or {}).get("model") or "")} for t, j in jdg.items()},
           "judge_issues": jissues, "top_findings": top[:60], "ran_checks": ran_checks(u, scan, flows, expl, jdg, targets),
           "not_judged": not_judged, "not_content": not_content,
           "screen_states": {s: sum(1 for row in matrix.values() for c in row.values() if c["screen"] == s) for s in SCREEN_STATES},
           # Ekran bez swojej treści to strona niesprawdzona: wynik nie może być PASS.
           "pass": blocking == 0 and not incomplete and not not_judged and not not_content and sum(counts.values()) > 0, "blocking": blocking, "seconds": (scan or {}).get("seconds")}
    (out / "ux-report.json").write_text(json.dumps(rep, indent=1, ensure_ascii=False))
    thumbs(out, res)
    (out / "ux-report.md").write_text(render_md(rep, tmeta))
    (out / "ux-report.html").write_text(render_html(rep, tmeta, res, flows, expl))
    latest = ctx.state_dir / "ux-latest.json"
    latest.write_text(json.dumps({"dir": str(out), "at": rep["at"], "provenance": execution, "ran_checks": rep["ran_checks"], "counts": counts, "pass": rep["pass"],
                                  "run_status": rep["run_status"], "evidence_scope": rep["evidence_scope"],
                                  "by_check": {a["check"]: a["severity"] for a in top}}, indent=1))
    return rep

def thumbs(out, res):
    from PIL import Image
    for r in res:
        if not r.get("shot") or not (out / r["shot"]).exists(): continue
        d = out / "thumbs" / Path(r["shot"]).with_suffix(".jpg"); d.parent.mkdir(parents=True, exist_ok=True)
        im = Image.open(out / r["shot"]).convert("RGB"); w = 220 if im.width < im.height else 360
        im.resize((w, int(im.height * w / im.width))).save(d, quality=70)

def thumb(rel): return "thumbs/" + str(Path(rel).with_suffix(".jpg")) if rel else None

def render_md(rep, tmeta):
    c = rep["counts"]; L = [f"# Raport UX — {rep['at']}", "",
        f"**Wynik: {rep.get('run_status', 'partial').upper() if rep.get('run_status') not in (None, 'complete') else 'PASS' if rep['pass'] else 'FAIL'}** · komórki urządzenie×strona: ✅ {c['pass']} · ⚠️ {c['warn']} · ❌ {c['fail']}"
        f" · warianty: ✅ {rep['variant_counts']['pass']} ⚠️ {rep['variant_counts']['warn']} ❌ {rep['variant_counts']['fail']}"
        f" · {len(rep['targets'])} profili, {len(rep['pages'])} stron, {rep.get('seconds')} s", "",
        "Stan zrzutów: " + ", ".join(f"{k} {v}" for k, v in (rep.get("screen_states") or {}).items()) +
        " (bez treści strony: sędzia ich nie ocenia; lista w ux-report.json/not_content)", "",
        f"Adres: `{rep['base_url']}` (tylko lokalnie/staging). Zrzuty i galeria: `ux-report.html`.", "",
        "## Macierz urządzenie × strona", "", "| Urządzenie | silnik | " + " | ".join(rep["pages"]) + " | sędzia |", "|---|---|" + "---|" * (len(rep["pages"]) + 1)]
    for t in rep["targets"]:
        row = rep["matrix"].get(t["id"], {}); j = rep["judge"].get(t["id"]) or {}
        sc = j.get("scores") or {}; js = ("/".join(str(sc.get(k, "?")) for k in ("layout", "consistency", "readability", "usability"))) if sc else ("błąd" if j.get("error") else "–")
        cells = [f"{ICON[row[p]['status']]} {row[p]['fails']}F/{row[p]['warns']}W" + (" (s)" if row[p].get('judge') in ('warn', 'fail') else "") if p in row else "·" for p in rep["pages"]]
        L.append(f"| {t['label'] or t['id']} `{t['id']}` | {t['engine']}{' *' if t.get('engine_note') else ''} | " + " | ".join(cells) + f" | {js} |")
    L += ["", "F/W = liczba problemów fail/warn z automatycznych sprawdzeń; (s) = sędzia wizualny dołożył uwagi; sędzia: układ/spójność/czytelność/użyteczność w skali 1–5; * = emulacja w innym silniku."]
    if rep["variants"]:
        L += ["", "## Warianty (ciemny motyw, zoom 200%, duży tekst, odstępy, długie treści, wolne 3G, offline, błąd API, pusta lista)", "",
              "| Wariant · urządzenie | " + " | ".join(rep["pages"]) + " |", "|---|" + "---|" * len(rep["pages"])]
        for k, row in sorted(rep["variants"].items()):
            L.append(f"| {k} | " + " | ".join(f"{ICON[row[p]['status']]} " + "; ".join(f['message'][:60] for f in row[p]['findings'][:2]) if p in row else "·" for p in rep["pages"]) + " |")
    if rep["flows"]:
        L += ["", "## Scenariusze użytkownika (skrypty)", "", "| Flow | persona | urządzenie | wynik | kroki/czas | uwagi |", "|---|---|---|---|---|---|"]
        for f in rep["flows"]:
            note = "; ".join(([f"krok {f['failed_step']}: {f['error']}"] if not f["ok"] else []) + [x["description"] for x in f["friction"][:3]])
            L.append(f"| {f['flow']} | {f['persona'] or ''} | {f['target']} | {ICON[f['status']]} | {f['interactions']} interakcji / {f['seconds']} s | {note[:200]} |")
    if rep["explore"]:
        L += ["", "## Eksplorator (model jako persona)", "", "| Cel | persona | urządzenie | wynik | akcje | sukces model / sprawdzony | tarcia |", "|---|---|---|---|---|---|---|"]
        for e in rep["explore"]:
            fr = "; ".join(f"[{x.get('severity')}] {x.get('description')}" for x in (e.get("friction") or [])[:4]) or (e.get("error") or "")
            L.append(f"| {e['goal'][:60]} | {e['persona']} | {e['target']} | {ICON.get(e.get('status'), '·')} | {e.get('actions')} | {e.get('model_success')} / {e.get('verified_success')} | {fr[:300]} |")
    L += ["", "## Najważniejsze problemy (zgrupowane)", ""]
    for a in rep["top_findings"][:25]:
        if a["severity"] == "info": continue
        det = a.get("detail"); det = (" — np. " + json.dumps(det[:2], ensure_ascii=False)[:160]) if det else ""
        L.append(f"- {ICON[a['severity']]} **{a['check']}**: {a['message']} — {len(a['targets'])} profili, strony: {', '.join(a['pages'])}"
                 + (f", warianty: {', '.join(v for v in a['variants'] if v != 'base')}" if any(v != 'base' for v in a['variants']) else "") + det)
    if rep["judge_issues"]:
        L += ["", "## Uwagi sędziego wizualnego", ""]
        seen = set()
        for i in sorted(rep["judge_issues"], key=lambda i: {"high": 0, "medium": 1, "low": 2}.get(i.get("severity"), 3)):
            k = (i.get("page"), i.get("description", "")[:50])
            if k in seen: continue
            seen.add(k); L.append(f"- [{i.get('severity')}{', do naprawy w kodzie' if i.get('code_fixable') else ''}] {i.get('target')} / {i.get('page')} / {i.get('location')}: {i.get('description')}")
            if len(seen) >= 30: break
    L += ["", "## Galeria (miniatury, pełne w shots/)", ""]
    for t in rep["targets"]:
        row = rep["matrix"].get(t["id"], {})
        L.append(f"**{t['label'] or t['id']}** `{t['id']}`  " + " ".join(f"![{p}]({thumb(row[p]['shot'])})" for p in rep["pages"] if p in row and row[p].get("shot")))
    infos = [a for a in rep["top_findings"] if a["severity"] == "info"]
    if infos: L += ["", "## Informacyjnie", ""] + [f"- {a['check']}: {a['message']}" for a in infos[:10]]
    L += ["", f"Wykonane sprawdzenia: {', '.join(rep['ran_checks'])}", "",
          "Ograniczenia: emulacja w Playwright (viewport, DPR, dotyk, UA, silnik WebKit/Blink/Gecko), nie prawdziwe urządzenia: brak Safari iOS, "
          "klawiatury ekranowej, safe-area/notcha, zawiasu Duo/Fold, gestów systemowych. Pomiary wydajności lokalnie są zaniżone."]
    if any(rep.get("not_checked", {}).values()):
        L += ["", "Niesprawdzone jednostki i etapy: " + json.dumps(rep["not_checked"], ensure_ascii=False)[:1200] + ". Pełna lista w ux-report.json."]
    if rep.get('reason'): L += ["", "Przyczyna przerwania: " + rep['reason']]
    if rep.get('stale_inputs'): L += ["", "Dane zachowane z poprzedniej próby: " + ', '.join(rep['stale_inputs']) + '. Nie potwierdzają bieżącego przebiegu.']
    if rep.get('evidence_scope') == 'historical_artifact_aggregation':
        L += ["", "Zakres: agregacja zapisanych dowodów. Podczas generowania raportu nie wykonano tych kontroli ani wywołań modeli."]
    provenance = rep.get("provenance") or {}
    L += ["", f"Helix {provenance.get('helix_version', 'unknown')}; target {provenance.get('target_head') or 'unknown'}; provenance w ux-report.json."]
    return "\n".join(L) + "\n"

def render_html(rep, tmeta, res, flows, expl):
    e = html.escape; c = rep["counts"]
    status = rep['run_status'].upper() if rep.get('run_status') not in (None, 'complete') else 'PASS' if rep['pass'] else 'FAIL'
    S = ["<!doctype html><meta charset=utf-8><title>Helix UX</title><style>body{font:14px system-ui;margin:20px;background:#f6f6f6}"
         "table{border-collapse:collapse;background:#fff}td,th{border:1px solid #ddd;padding:4px 6px;vertical-align:top}"
         ".pass{background:#e7f7ea}.warn{background:#fff4d6}.fail{background:#fde2e2}img{max-width:220px;border:1px solid #ccc;display:block}"
         ".g{display:flex;flex-wrap:wrap;gap:10px}.c{background:#fff;padding:6px;border:1px solid #ddd;font-size:12px;max-width:380px}</style>",
         f"<h1>Raport UX {e(status)}</h1><p>{e(rep['at'])} · ✅ {c['pass']} ⚠️ {c['warn']} ❌ {c['fail']} · <a href=ux-report.md>markdown</a></p>",
         "<h2>Macierz</h2><table><tr><th>Urządzenie</th>" + "".join(f"<th>{e(p)}</th>" for p in rep["pages"]) + "</tr>"]
    for t in rep["targets"]:
        row = rep["matrix"].get(t["id"], {})
        S.append(f"<tr><td>{e(t['label'] or '')}<br><code>{e(t['id'])}</code><br>{e(t['engine'])}</td>" + "".join(
            f"<td class={row[p]['status']}>{ICON[row[p]['status']]} {row[p]['fails']}F/{row[p]['warns']}W<a href='{e(row[p]['shot'] or '')}'><img loading=lazy src='{e(thumb(row[p]['shot']) or '')}'></a></td>" if p in row else "<td>·</td>" for p in rep["pages"]) + "</tr>")
    S.append("</table><h2>Szczegóły</h2><div class=g>")
    for r in res:
        fs = "".join(f"<li class={f['severity']}>{e(f['message'])}</li>" for f in r["findings"] if f["severity"] != "info")
        S.append(f"<div class='c {r['status']}'><b>{e(r['target'])}</b> · {e(r['page'])} · {e(r['variant'])}<a href='{e(r.get('shot') or '')}'><img loading=lazy src='{e(thumb(r.get('shot')) or '')}'></a><ul>{fs}</ul></div>")
    S.append("</div><h2>Flow</h2><div class=g>")
    for f in flows:
        S.append(f"<div class='c {f['status']}'><b>{e(f['flow'])}</b> {e(f['target'])}<br>" + "".join(
            f"<a href='{e(s['shot'] or '')}' title='{e(json.dumps(s['step'], ensure_ascii=False))}'>{s['n']}{'✓' if s['ok'] else '✗'}</a> " for s in f["steps"]) + "</div>")
    for x in expl:
        S.append(f"<div class='c {x.get('status')}'><b>explore {e(x['persona'])}</b> {e(x['target'])}: {e(x['goal'])}<br>" + "".join(
            f"<a href='{e(s['shot'])}' title='{e(s.get('thought', ''))}'>{s['n']}:{e(str(s['action']))}</a> " for s in x["steps"]) + "</div>")
    provenance = rep.get("provenance") or {}
    if rep.get('reason'): S.append('<p>' + e(rep['reason']) + '</p>')
    if rep.get('evidence_scope') == 'historical_artifact_aggregation':
        S.append('<p>Zakres: agregacja zapisanych dowodów. Podczas generowania raportu nie wykonano tych kontroli ani wywołań modeli.</p>')
    S.append("</div>" + f"<p>Helix {e(provenance.get('helix_version') or 'unknown')}; target {e(provenance.get('target_head') or 'unknown')}; "
             '<a href="ux-report.json">provenance JSON</a></p>')
    return "\n".join(S)

# ---------------------------------------------------------------- command
def cmd_ux(ctx, a):
    u = cfg(ctx)
    if a.base_url: u["base_url"] = a.base_url; u["start_cmd"] = None if a.no_start else u["start_cmd"]
    if a.matrix: u["matrix"] = a.matrix; u["devices"] = None
    if a.devices: u["devices"] = a.devices.split(",")
    if a.no_variants: u["variants"] = []
    if a.no_judge: u["judge"]["enabled"] = False
    if a.explore: u["explore"]["enabled"] = True
    if a.action == "devices":
        av = engines(fresh=a.refresh); ts = build_targets(u, av)
        print(f"engines: {av}"); [print(f"  {t['id']:32} {t['engine']:8} {t.get('label', '')}{'  [' + ','.join(t['variants']) + ']' if t['variants'] else ''}{'  (' + t['engine_note'] + ')' if t.get('engine_note') else ''}") for t in ts]
        print(f"{len(ts)} profili"); return 0
    if not u.get("base_url"): raise SystemExit("set ux.base_url in helix.json (local dev server) or pass --base-url")
    assert_safe_url(u["base_url"], u["allow_hosts"])
    out = Path(a.out) if a.out else (ctx.evidence_root / f"ux-{dt.datetime.now():%Y%m%d-%H%M%S}")
    out.mkdir(parents=True, exist_ok=True); out = out.resolve()
    from helix_resources import Governor, ResourcePaused
    ctx = copy.copy(ctx)
    governor = getattr(ctx, 'resource_governor', None) or Governor(policy=ctx.cfg.get('resources', {}), requested_jobs=u['parallel'], out=out)
    ctx._ux_governor = governor; ctx._ux_out = out
    targets = build_targets(u, {}); spec = load_flows(ctx, u)
    steps = {"all": ["scan", "flows", "explore", "judge", "report"]}.get(a.action, [a.action])
    planned = [s for s in steps if (s != 'flows' or spec['flows']) and (s != 'explore' or spec['explore'] and (u['explore']['enabled'] or a.action == 'explore')) and (s != 'judge' or u['judge']['enabled'])]
    progress = dict(run_status='in_progress', stages={name: 'not_checked' for name in planned}, aggregation_only=a.action == 'report')
    original_inputs = {name: (out / name).stat().st_mtime_ns for name in ('scan.json', 'flows.json', 'explore.json', 'judge.json') if (out / name).is_file()}
    # `ux judge` ocenia zrzuty ze skanu wskazanego katalogu: ten skan jest wejściem tej próby, nie danymi z poprzedniej.
    if a.action == 'judge': original_inputs.pop('scan.json', None)
    if (out / 'ux-report.json').is_file():
        try:
            previous = json.loads((out / 'ux-report.json').read_text())
            progress['previous_attempt'] = {key: previous.get(key) for key in ('at', 'pass', 'run_status')}
            progress['previous_attempt'].update(stale=True, target_head=(previous.get('provenance') or {}).get('target_head'))
        except (ValueError, AttributeError): pass
    ctx._ux_progress_state = progress
    # Publish a non-PASS current attempt before any runner starts. A process
    # interruption must not leave a prior successful attempt as the latest run.
    progress['stale_inputs'] = list(original_inputs)
    _ux_progress(ctx)
    build_report(ctx, u, out, targets)
    current_stage = 'startup'
    def completed(name):
        if name in progress['stages']: progress['stages'][name] = 'complete'
        _ux_progress(ctx)
    with governor.monitor():
        try:
            _ux_wait(ctx)
            targets = build_targets(u, engines())
            with Server(ctx, u) if any(s in planned for s in ('scan', 'flows', 'explore')) else _Null():
                if 'scan' in planned:
                    current_stage = 'scan'
                    _ux_wait(ctx)
                    run_node('scan', job_for(ctx, u, out, targets)); completed('scan')
                if 'flows' in planned:
                    current_stage = 'flows'
                    _ux_wait(ctx)
                    ft = [t for t in targets if t['id'] in u['flow_devices']]
                    run_node('flows', job_for(ctx, u, out, ft, {'flows': spec['flows'], '_mode': 'flows'})); completed('flows')
                if 'explore' in planned:
                    current_stage = 'explore'
                    _ux_wait(ctx)
                    explore(ctx, u, out, targets, spec['explore'], {**PERSONAS, **spec['personas']}); completed('explore')
            if 'judge' in planned and (out / 'scan.json').exists():
                current_stage = 'judge'
                _ux_wait(ctx)
                judge(ctx, u, out, json.loads((out / 'scan.json').read_text()), targets); completed('judge')
            completed('report')
            progress['run_status'] = 'complete' if all(value == 'complete' for value in progress['stages'].values()) else 'partial'
        except ResourcePaused as exc:
            progress.update(run_status='resource_paused', reason=str(exc))
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
            from helix_packs import redact
            if isinstance(exc, subprocess.TimeoutExpired): detail = 'przekroczono limit czasu procesu'
            elif isinstance(exc, OSError): detail = 'errno=' + str(exc.errno)
            else: detail = redact(str(exc))
            reason = f'UX {current_stage}: {type(exc).__name__}; {detail}'
            progress.update(run_status='error', reason=reason)
            H.log(reason)
        finally:
            progress['stale_inputs'] = [name for name, stamp in original_inputs.items()
                if (out / name).is_file() and (out / name).stat().st_mtime_ns == stamp]
            _ux_progress(ctx)
    rep = build_report(ctx, u, out, targets)
    c = rep["counts"]
    status = rep['run_status'].upper() if rep['run_status'] != 'complete' else 'PASS' if rep['pass'] else 'FAIL'
    st = rep.get("screen_states") or {}
    print(f"UX {status}: ✅ {c['pass']} ⚠️ {c['warn']} ❌ {c['fail']} (warianty ❌ {rep['variant_counts']['fail']}); ekrany z treścią {st.get('content', 0)}/{sum(st.values())} -> {out / 'ux-report.md'}")
    return rep

class _Null:
    def __enter__(self): return self
    def __exit__(self, *a): pass

def gate_ux(ctx, cp_id):
    from helix_environment import provenance
    class A: action = "all"; base_url = None; no_start = False; matrix = None; devices = None; no_variants = False; no_judge = False; explore = False; refresh = False
    A.out = str(ctx.ev(cp_id) / "ux")
    u = cfg(ctx)
    if not u.get("enabled"):
        res = {"gate": "ux", "pass": True, "skipped": "ux.enabled=false", "provenance": provenance(ctx.repo, models=[])}
    else:
        rep = cmd_ux(ctx, A)
        res = {"gate": "ux", "pass": rep["pass"], "counts": rep["counts"], "blocking": rep["blocking"], "report": A.out + "/ux-report.md", "provenance": rep["provenance"], "run_status": rep.get("run_status"), "resources": rep.get("resources"), "not_checked": rep.get("not_checked")}
    (ctx.ev(cp_id) / "ux.json").write_text(json.dumps(res, indent=2, ensure_ascii=False)); H.log(f"gate ux: {'PASS' if res['pass'] else 'FAIL'}")
    return res

# ---------------------------------------------------------------- coverage ("co zapomnieliśmy")
ROW_RE = re.compile(r"^\|\s*(?P<id>[A-Z][A-Z0-9]*-\d+)\s*\|(?P<item>[^|]*)\|(?P<check>[^|]*)\|(?P<how>[^|]*)\|(?P<sig>[^|]*)\|(?P<status>[^|]*)\|\s*$")
def parse_checklist(text):
    cat, items = None, []
    for line in text.splitlines():
        if line.startswith("## "): cat = line[3:].strip(); continue
        m = ROW_RE.match(line)
        if m: items.append({"category": cat, **{k: v.strip() for k, v in m.groupdict().items()}})
    return items

def signal_state(ctx, sig, latest):
    """-> (state, note). state: auto-ok | auto-issues | configured | missing | none"""
    sig = sig.strip("` ")
    if not sig or sig in ("-", "–"): return "none", ""
    states = []
    for s in [x.strip("` ") for x in re.split(r"[,+ ]+", sig) if x.strip("` ")]:
        if s.startswith("gate:"):
            g = s[5:]
            ok = {"behavior": bool(ctx.test_cmd()), "visual": bool(ctx.cfg["visual"].get("enabled")),
                  "review": sum(1 for r in ctx.cfg["providers"]["reviewers"] if r.get("enabled", True)) >= 2,
                  "truth": bool((ctx.cfg.get("truth") or {}).get("required"))}.get(g)
            states.append(("configured" if ok else "missing", f"{s}: {'włączona' if ok else 'wyłączona'}"))
        elif s.startswith("ux:"):
            chk = s[3:]
            if not latest: states.append(("configured" if cfg(ctx).get("enabled") else "missing", f"{s}: brak przebiegu UX")); continue
            ran = latest.get("ran_checks", [])
            hit = chk in ran or any(r.startswith(chk + ":") for r in ran)
            if not hit: states.append(("missing", f"{s}: nie sprawdzane w ostatnim przebiegu")); continue
            sev = [v for k, v in latest.get("by_check", {}).items() if k == chk or k.startswith(chk + ":") or k.startswith(chk + "-")]
            bad = "fail" in sev or "warn" in sev
            states.append(("auto-issues" if bad else "auto-ok", f"{s}: {'są problemy' if bad else 'ok'} ({latest['at']})"))
        else: states.append(("missing", f"{s}: nieznany sygnał"))
    order = ["missing", "configured", "auto-issues", "auto-ok"]
    best = max(states, key=lambda x: order.index(x[0]))[0]
    return best, "; ".join(n for _, n in states)

def cmd_coverage(ctx, a):
    proj = ctx.repo / "helix-coverage.md"; tpl = TEMPLATES / "coverage-checklist.md"
    if a.init:
        if proj.exists() and not a.force: raise SystemExit(f"{proj} exists (--force to overwrite)")
        shutil.copy(tpl, proj); print(f"{proj} — ustaw kolumnę Status (todo|partial|done|n/a) dla swojego projektu"); return
    src = proj if proj.exists() else tpl
    items = parse_checklist(src.read_text())
    lf = ctx.state_dir / "ux-latest.json"; latest = json.loads(lf.read_text()) if lf.exists() else None
    L = [f"# Pokrycie jakości — {ctx.repo.name} ({H.now()})", "", f"Źródło: `{src}`" + ("" if proj.exists() else " (szablon; `helix coverage --init` tworzy kopię projektu)"),
         f"Ostatni przebieg UX: {latest['at'] + ' ' + latest['dir'] if latest else 'brak'}", ""]
    tally = {"covered": 0, "issues": 0, "manual-done": 0, "configured": 0, "gap": 0, "n/a": 0}; gaps = []; cat = None
    for it in items:
        st, note = signal_state(ctx, it["sig"], latest); manual = it["status"].lower()
        if manual in ("n/a", "na"): eff = "n/a"
        elif st == "auto-ok": eff = "covered"
        elif st == "auto-issues": eff = "issues"
        elif manual == "done": eff = "manual-done"
        elif st == "configured" or manual == "partial": eff = "configured"
        else: eff = "gap"
        tally[eff] += 1
        if eff == "gap": gaps.append(it)
        if it["category"] != cat:
            cat = it["category"]; L += ["", f"## {cat}", "", "| ID | Pozycja | Jak | Helix | Stan |", "|---|---|---|---|---|"]
        icon = {"covered": "✅ auto", "issues": "⚠️ auto: problemy", "manual-done": "✅ ręcznie", "configured": "🟡 częściowo/skonfig.", "gap": "❌ luka", "n/a": "– n/d"}[eff]
        L.append(f"| {it['id']} | {it['item']} | {it['how']} | {it['sig'] or '-'} | {icon}{(' — ' + note) if note else ''} |")
    head = [f"**Podsumowanie:** {len(items)} pozycji · ✅ auto {tally['covered']} · ⚠️ auto z problemami {tally['issues']} · ✅ ręcznie {tally['manual-done']}"
            f" · 🟡 częściowo {tally['configured']} · ❌ luki {tally['gap']} · n/d {tally['n/a']}", ""]
    out = "\n".join(L[:5] + head + L[5:]) + "\n"
    dest = ctx.state_dir / "coverage.md"; dest.write_text(out)
    (ctx.state_dir / "coverage.json").write_text(json.dumps({"tally": tally, "gaps": [g["id"] for g in gaps]}, indent=1))
    if a.out: Path(a.out).write_text(out)
    print(out if a.full else "\n".join(head) + f"\nLuki (pierwsze 15): " + ", ".join(f"{g['id']} {g['item']}" for g in gaps[:15]) + f"\n-> {dest}")
    return tally
