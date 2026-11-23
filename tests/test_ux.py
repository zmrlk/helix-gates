"""UX pack tests (device matrix, safety guard, findings rules, report, coverage, real Playwright run).
Run: python3 -m unittest discover -s tests -v"""
import socket
import json, os, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

HOME = Path(__file__).resolve().parent.parent
HELIX = HOME / "bin/helix"
sys.path.insert(0, str(HOME / "bin"))
from helix_contracts import VERSION
import importlib.machinery, importlib.util
_l = importlib.machinery.SourceFileLoader("helix_main", str(HELIX)); _s = importlib.util.spec_from_loader("helix_main", _l)
helix_main = importlib.util.module_from_spec(_s); sys.modules["helix_main"] = helix_main; _l.exec_module(helix_main)
import helix_ux as U
U.H = helix_main

def sh(cmd, cwd, **kw): return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, **kw)
ALL = {"chromium": "1", "webkit": "1", "firefox": "1"}

def mkrepo(d, files, cfg):
    d = Path(d)
    for k, v in files.items(): (d / k).parent.mkdir(parents=True, exist_ok=True); (d / k).write_text(v)
    (d / "helix.json").write_text(json.dumps({**cfg, "helix_version": VERSION}))
    for c in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"]): sh(c, d)
    return d

class Matrix(unittest.TestCase):
    def u(self, **kw): return helix_main.deep_merge(U.DEFAULT_UX, kw)
    def test_full_matrix_covers_all_device_classes_both_orientations(self):
        ts = U.build_targets(self.u(), ALL); ids = {t["id"] for t in ts}
        for need in ("phone-small@portrait", "phone-small@landscape", "iphone-max@landscape", "android@portrait", "fold-cover@portrait",
                     "fold-open@landscape", "surface-duo@portrait", "surface-duo-spanned@landscape", "ipad-mini@portrait",
                     "ipad-pro@landscape", "android-tablet@portrait", "laptop/firefox", "desktop/webkit", "ultrawide/chromium"):
            self.assertIn(need, ids)
        self.assertEqual({t["kind"] for t in ts}, {"phone", "foldable", "tablet", "desktop"})
        self.assertEqual(len(ts), 22 + 9)
    def test_iphone_uses_webkit_and_falls_back_with_note(self):
        t = next(t for t in U.build_targets(self.u(), ALL) if t["id"] == "iphone@portrait"); self.assertEqual(t["engine"], "webkit")
        t = next(t for t in U.build_targets(self.u(), {"chromium": "1"}) if t["id"] == "iphone@portrait")
        self.assertEqual(t["engine"], "chromium"); self.assertIn("webkit", t["engine_note"])
        self.assertEqual([x["id"] for x in U.build_targets(self.u(), {"chromium": "1"}) if x["kind"] == "desktop"], ["laptop/chromium", "desktop/chromium", "ultrawide/chromium"])
    def test_variants_assigned_and_slow3g_only_on_chromium(self):
        ts = {t["id"]: t for t in U.build_targets(self.u(), ALL)}
        self.assertIn("slow3g", ts["android@portrait"]["variants"]); self.assertIn("zoom200", ts["laptop/chromium"]["variants"])
        self.assertIn("dark", ts["phone-small@portrait"]["variants"]); self.assertNotIn("slow3g", ts["phone-small@portrait"]["variants"])
        u = self.u(variant_targets={"slow3g": ["phone-small@portrait"]})
        self.assertNotIn("slow3g", {t["id"]: t for t in U.build_targets(u, ALL)}["phone-small@portrait"]["variants"])
    def test_custom_device_and_quick_matrix(self):
        ts = U.build_targets(self.u(devices=["laptop", {"id": "kiosk", "viewport": [1080, 1920], "kind": "tablet"}]), {"chromium": "1"})
        self.assertEqual([t["id"] for t in ts], ["laptop/chromium", "kiosk@portrait", "kiosk@landscape"])
        self.assertEqual(len(U.build_targets(self.u(matrix="quick"), ALL)), 2 + 2 + 2 + 2 + 3 + 3)
    def test_unknown_preset_rejected(self):
        with self.assertRaises(SystemExit): U.build_targets(self.u(devices=["nokia-3310"]), ALL)

class Safety(unittest.TestCase):
    def test_only_local_or_allowlisted_hosts(self):
        for ok in ("http://127.0.0.1:4173/", "http://localhost:3000", "http://app.test/", "http://example-app.local/"):
            U.assert_safe_url(ok, [])
        U.assert_safe_url("https://staging.example.com/", ["staging.example.com"])
        for bad in ("https://panel.example.com/", "https://example-app.example/"):
            with self.assertRaises(SystemExit): U.assert_safe_url(bad, [])
    def test_cli_refuses_production_url(self):
        with tempfile.TemporaryDirectory() as d:
            mkrepo(d, {"a.txt": "x"}, {"ux": {"enabled": True}})
            p = sh(["python3", str(HELIX), "--repo", d, "ux", "scan", "--base-url", "https://panel.example.com/", "--no-start"], d)
            self.assertNotEqual(p.returncode, 0); self.assertIn("refuses", p.stdout + p.stderr)
    @unittest.skipUnless(shutil.which("node"), "Node unavailable")
    def test_node_guard_and_rules(self):
        js = f"""const u=require('{HOME}/bin/ux.cjs');
const th={{tap_min:44,min_font_px:12,min_font_fail_px:10,fixed_cover_max:0.3,lcp_warn_ms:2500,lcp_fail_ms:4000,cls_warn:0.1,cls_fail:0.25,transfer_warn_kb:3000}};
const L={{meta_viewport:null,overflow_px:120,offenders:[{{sel:'table'}}],clipped:[],overlaps:[],covered:[{{sel:'#buy',by:'#cookie',fixed:true}}],fixed_cover_ratio:0.5,fixed:[],
  tiny_targets:[{{sel:'x',w:18,h:18}}],small_targets:[],small_text:[{{sel:'p',px:9}}],broken_images:[],text_chars:10,interactive_count:3}};
const f=u.findingsFor({{mobile:true,layout:L,collect:{{page_errors:['boom']}},axe:[{{id:'color-contrast',impact:'serious',help:'c',tags:['wcag2aa'],nodes:2,targets:[]}},{{id:'region',impact:'moderate',help:'r',tags:['best-practice'],nodes:1,targets:[]}}],
  perf:{{lcp_ms:5000,cls:0.05,transfer_kb:10}},keyboard:{{trap:false,tab_stops:3,no_focus_indicator:['#b'],obscured:[],pointer_only:[]}}}},th,'base');
console.log(JSON.stringify({{checks:f.map(x=>x.check+':'+x.severity),worst:u.worst(f),local:u.hostAllowed('127.0.0.1',[]),prod:u.hostAllowed('example-app.example',[]),allow:u.hostAllowed('a.stg.example.com',['*.stg.example.com'])}}));"""
        p = sh(["node", "-e", js], HOME, env=dict(os.environ, HELIX_PLAYWRIGHT=helix_main.PW_PATH)); self.assertEqual(p.returncode, 0, p.stderr)
        j = json.loads(p.stdout)
        for c in ("meta-viewport:fail", "overflow:fail", "fixed-covers:fail", "fixed-area:warn", "tap-target:fail", "small-text:fail", "js-error:fail",
                  "a11y:color-contrast:fail", "a11y:region:info", "perf:lcp:fail", "kbd:focus-visible:fail"):
            self.assertIn(c, j["checks"])
        self.assertEqual(j["worst"], "fail"); self.assertTrue(j["local"]); self.assertFalse(j["prod"]); self.assertTrue(j["allow"])

    @unittest.skipUnless(shutil.which("node"), "Node unavailable")
    def test_rules_load_without_playwright_but_browser_use_and_cli_fail(self):
        with tempfile.TemporaryDirectory() as d:
            # Preload: the dependency resolver reports Playwright missing, as on a clean machine.
            stub = Path(d) / "missing-playwright.cjs"
            stub.write_text("const M = require('module'), real = M._load;\n"
                            "M._load = function (name) { if (name === './dependencies.cjs') return () => { throw new Error('Missing playwright: synthetic'); };"
                            " return real.apply(this, arguments); };\n")
            js = (f"const u = require({json.dumps(str(HOME / 'bin/ux.cjs'))});"
                  "let browser = 'no error'; try { u.resolveTarget({pw_device: 'iPhone 13'}); } catch (e) { browser = e.message; }"
                  "u.executionTools({}).then((tools) => {"
                  "console.log(JSON.stringify({worst: u.worst([{severity: 'warn'}]), local: u.hostAllowed('127.0.0.1', []),"
                  " checks: u.findingsFor({mobile: true, layout: {meta_viewport: null, overflow_px: 0, clipped: [], overlaps: [], covered: [], small_targets: [],"
                  " tiny_targets: [], small_text: [], fixed: [], broken_images: [], text_chars: 100}}, {}, 'base').map(f => f.check), browser,"
                  " tools: tools.map(t => t.tool)})); });")
            p = sh(["node", "-r", str(stub), "-e", js], d); self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout), {"worst": "warn", "local": True, "checks": ["meta-viewport"], "browser": "Missing playwright: synthetic", "tools": ["node"]})
            p = sh(["node", "-r", str(stub), str(HOME / "bin/ux.cjs"), "engines"], d)
            self.assertNotEqual(p.returncode, 0); self.assertIn("Missing playwright: synthetic", p.stderr); self.assertEqual(p.stdout, "")

class Coverage(unittest.TestCase):
    def test_template_parses_with_unique_ids_and_valid_columns(self):
        items = U.parse_checklist((HOME / "templates/coverage-checklist.md").read_text())
        self.assertGreaterEqual(len(items), 80)
        ids = [i["id"] for i in items]; self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(i["how"] in ("auto", "model", "ręcznie") for i in items), [i for i in items if i["how"] not in ("auto", "model", "ręcznie")][:2])
        cats = {i["category"] for i in items}
        for c in ("UX i urządzenia", "Dostępność", "Wydajność", "Bezpieczeństwo", "Prywatność i RODO", "Język i formaty (i18n/locale)",
                  "E-mail, XLSX i załączniki", "Druk i PDF", "Role i uprawnienia", "Obciążenie i współbieżność", "Prawo i zgodność"):
            self.assertIn(c, cats)
    def test_coverage_combines_signals_latest_run_and_manual_status(self):
        with tempfile.TemporaryDirectory() as d:
            mkrepo(d, {"package.json": '{"scripts":{"test":"node --test"}}'}, {"ux": {"enabled": True}})
            p = sh(["python3", str(HELIX), "--repo", d, "coverage", "--init"], d); self.assertEqual(p.returncode, 0, p.stderr)
            md = Path(d) / "helix-coverage.md"; md.write_text(md.read_text().replace("| SEO-01 | Panel poza indeksem | Panel, konto, zamówienia i staging mają `noindex` i są za logowaniem | auto | - | todo |",
                                                                                     "| SEO-01 | Panel poza indeksem | x | auto | - | done |"))
            (Path(d) / ".helix/ux-latest.json").write_text(json.dumps({"dir": "x", "at": "2026-10-24", "ran_checks": ["overflow", "clipped", "overlap", "a11y"],
                                                                        "by_check": {"a11y:color-contrast": "fail"}, "counts": {}, "pass": False}))
            p = sh(["python3", str(HELIX), "--repo", d, "coverage", "--full"], d); self.assertEqual(p.returncode, 0, p.stderr)
            out = p.stdout
            self.assertRegex(out, r"\| UX-02 \|.*✅ auto"); self.assertRegex(out, r"\| A11Y-01 \|.*⚠️ auto: problemy")
            self.assertRegex(out, r"\| A11Y-04 \|.*❌ luka"); self.assertRegex(out, r"\| SEO-01 \|.*✅ ręcznie")
            self.assertRegex(out, r"\| XLSX-01 \|.*🟡")          # gate:behavior configured (npm test)
            self.assertRegex(out, r"\| SEC-01 \|.*❌ luka")
            self.assertTrue((Path(d) / ".helix/coverage.md").exists())

class Report(unittest.TestCase):
    def test_matrix_judge_and_blocking(self):
        self.assertEqual(U.judge_cell([{"page": "a", "severity": "high", "code_fixable": True}], "a"), "fail")
        self.assertEqual(U.judge_cell([{"page": "*", "severity": "medium", "code_fixable": True}], "b"), "warn")
        self.assertEqual(U.judge_cell([{"page": "a", "severity": "high", "code_fixable": True}], "b"), "pass")

class JudgeCoverage(unittest.TestCase):
    def test_every_page_is_judged_in_sheets_and_a_failed_sheet_is_reported_not_passed(self):
        from types import SimpleNamespace
        from PIL import Image
        with tempfile.TemporaryDirectory() as d:
            out = Path(d); pages = ["p%d" % i for i in range(1, 6)]
            for name in pages: Image.new("RGB", (40, 80), (200, 200, 200)).save(out / (name + ".png"))
            scan = {"results": [{"target": "phone-small@portrait", "page": n, "variant": "base", "shot": n + ".png", "findings": []} for n in pages]}
            targets = [{"id": "phone-small@portrait", "engine": "webkit", "label": "tel"}]
            calls = []
            def ask(ctx, provider, prompt, **kw):
                calls.append(prompt)
                if len(calls) == 2: raise U.H.ProviderError("limit")
                return json.dumps({"scores": {"layout": 4}, "issues": [], "summary": "ok", "valid": True}), {"provider": "gemini", "model": "m"}
            u = helix_main.deep_merge(U.DEFAULT_UX, {"judge": {"targets": "all", "max_pages": 4, "parallel": 1}})
            ctx = SimpleNamespace(cfg={"providers": {"visual_judge": "gemini"}}, repo=out)
            old = U.H.ask; U.H.ask = ask
            try: result = U.judge(ctx, u, out, scan, targets)
            finally: U.H.ask = old
            device = result["phone-small@portrait"]
            self.assertEqual(len(calls), 2)                          # 5 pages = 2 sheets, no page is skipped
            self.assertEqual(device["not_judged_pages"], ["p5"])     # a sheet with a model error does not pretend to be judged

    def test_free_slot_takes_the_next_device_without_waiting_for_the_oldest(self):
        # The judge must not wait for the whole oldest device before starting the next one, or it runs one device at a time.
        import threading
        from types import SimpleNamespace
        from PIL import Image
        with tempfile.TemporaryDirectory() as d:
            out = Path(d); Image.new("RGB", (40, 80), (200, 200, 200)).save(out / "p.png")
            ids = ["slow@portrait", "fast@portrait", "third@portrait"]
            scan = {"results": [{"target": t, "page": "p", "variant": "base", "shot": "p.png", "findings": []} for t in ids]}
            targets = [{"id": t, "engine": "chromium", "label": t} for t in ids]
            third_started, order = threading.Event(), []
            def ask(ctx, provider, prompt, **kw):
                if "slow@portrait" in prompt: self.assertTrue(third_started.wait(5))   # the slow one finishes only after the third has started
                if "third@portrait" in prompt: third_started.set()
                order.append(next(t for t in ids if t in prompt))
                return json.dumps({"scores": {"layout": 4}, "issues": [], "summary": "ok", "valid": True}), {"provider": "gemini", "model": "m"}
            u = helix_main.deep_merge(U.DEFAULT_UX, {"judge": {"targets": "all", "max_pages": 4, "parallel": 2}})
            ctx = SimpleNamespace(cfg={"providers": {"visual_judge": "gemini"}}, repo=out)
            old = U.H.ask; U.H.ask = ask
            try: result = U.judge(ctx, u, out, scan, targets)
            finally: U.H.ask = old
            self.assertEqual(sorted(result), sorted(ids)); self.assertEqual(order[-1], "slow@portrait")


def runtime_available():
    from helix_dependencies import node_module
    if not node_module('playwright'): return False
    try:
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0))
    except OSError: return False
    return True

# Run real browser tests only on an explicitly enabled integration worker.
if os.environ.get('HELIX_BROWSER_IT') == '1':
    class RealRun(unittest.TestCase):
        """Real Playwright run on a tiny local app: one broken page, one clean page, one flow with a download."""
        def test_scan_flows_report(self):
            with tempfile.TemporaryDirectory() as d:
                head = '<!doctype html><html lang="pl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>t</title></head><body><main>'
                files = {
                    "app/ok.html": head + '<h1>Zamówienia</h1><p style="font-size:16px">Wszystko działa. Zażółć gęślą jaźń.</p><a href="f.pdf" download id="dl" style="display:inline-block;padding:14px">Pobierz fakturę</a></main></body></html>',
                    "app/bad.html": head + '<h1>Lista</h1><div style="width:900px;background:#eee">szeroka tabela</div><button style="width:16px;height:16px;padding:0" aria-label="x"></button></main></body></html>',
                    "app/f.pdf": "%PDF-1.4\n%%EOF\n",
                    "flows.json": json.dumps({"flows": [{"id": "faktura", "persona": "accountant", "steps": [{"goto": "/ok.html"}, {"expect": {"text": "Zamówienia"}}, {"download": "#dl", "expect_filename": "\\.pdf$"}]}]}),
                }
                port = 4199
                cfg = {"ux": {"enabled": True, "start_cmd": f"python3 -m http.server {port} --bind 127.0.0.1 -d app", "base_url": f"http://127.0.0.1:{port}/",
                              "pages": [{"name": "ok", "path": "/ok.html"}, {"name": "bad", "path": "/bad.html"}], "flows": "flows.json",
                              "flow_devices": ["android@portrait"], "desktop_engines": ["chromium"], "variants": ["zoom200"],
                              "variant_targets": {"zoom200": ["laptop/chromium"]}}}
                mkrepo(d, files, cfg)
                p = sh(["python3", str(HELIX), "--repo", d, "ux", "all", "--devices", "android,laptop", "--no-judge", "--out", f"{d}/out"], d, timeout=600)
                self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
                rep = json.loads((Path(d) / "out/ux-report.json").read_text())
                m = rep["matrix"]
                self.assertEqual(m["android@portrait"]["bad"]["status"], "fail")
                self.assertEqual(m["laptop/chromium"]["bad"]["status"], "pass", m["laptop/chromium"]["bad"])
                self.assertIn(m["android@portrait"]["ok"]["status"], ("pass", "warn"))
                checks = {a["check"] for a in rep["top_findings"]}
                self.assertIn("overflow", checks); self.assertIn("tap-target", checks)
                self.assertEqual(rep["flows"][0]["status"], "pass", rep["flows"])
                self.assertIn("download", rep["ran_checks"]); self.assertIn("zoom200", rep["ran_checks"])
                for f in ("ux-report.md", "ux-report.html", "scan.json", "flows.json"): self.assertTrue((Path(d) / "out" / f).exists(), f)
                self.assertTrue(list((Path(d) / "out/thumbs").rglob("*.jpg")))
                self.assertTrue((Path(d) / ".helix/ux-latest.json").exists())
                self.assertFalse(rep["pass"])

if os.environ.get('HELIX_BROWSER_IT') == '1':
    class ClosedDetails(unittest.TestCase):
        """Content of a closed <details> (outside <summary>) is not on screen: no covered/fixed-covers alarms for it,
        even when CSS keeps its boxes laid out (::details-content animation). The <summary> itself is still audited."""
        def test_layout_audit_skips_closed_details_content(self):
            html = ('<!doctype html><html><head><meta name=viewport content="width=device-width"><style>'
                    'body{margin:0;font:16px sans-serif}.bar{position:fixed;left:0;right:0;bottom:0;height:80px;background:#222;color:#fff}'
                    'details.anim::details-content{content-visibility:visible;display:block;height:0;overflow:hidden}.sp{height:300px}'
                    '</style></head><body><main><div class=sp>x</div>'
                    '<details class=anim><summary style="padding:14px">Wiecej</summary><a id=hidA href="#a" style="display:inline-block;padding:14px">Ukryty A</a></details>'
                    '<details><summary style="padding:14px">Zwykle</summary><details open><summary>w</summary><a id=hidB href="#b">Ukryty B</a></details></details>'
                    '<details id=fx style="position:fixed;bottom:0;left:0;right:0;height:80px"><summary id=fxs>pasek</summary></details>'
                    '<a href="#c" style="display:inline-block;padding:14px">Widoczny</a><div class=sp>y</div></main><div class=bar>pasek</div></body></html>')
            js = f"""const u=require({json.dumps(str(HOME / 'bin/ux.cjs'))});
    const pw=require(require({json.dumps(str(HOME / 'bin/dependencies.cjs'))})('playwright'));
    (async()=>{{const b=await pw.chromium.launch();const p=await b.newPage({{viewport:{{width:390,height:500}}}});
    await p.setContent({json.dumps(html)});
    const L=await p.evaluate(u.layoutAudit,{{vw:390,vh:500,touch:true,tap_min:44,min_font_px:12,max_interactive:80}});
    await b.close();console.log(JSON.stringify(L));}})().catch(e=>{{console.error(e);process.exit(1);}});"""
            p = sh(["node", "-e", js], HOME, env=dict(os.environ, HELIX_PLAYWRIGHT=helix_main.PW_PATH), timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            L = json.loads(p.stdout)
            covered = json.dumps(L["covered"])
            self.assertNotIn("Ukryty", covered, L["covered"])
            self.assertEqual(L["interactive_count"], 4, L)          # 3 summaries + visible link; hidden links skipped
            self.assertTrue(any(c["sel"] == "#fxs" and c["fixed"] for c in L["covered"]), L["covered"])  # summary still audited

if __name__ == "__main__": unittest.main()


class NodeTimeout(unittest.TestCase):
    def test_scan_limit_grows_with_pages_and_devices(self):
        # A fixed one-hour limit can truncate large scans, so the limit grows with the planned pages and devices.
        import json, tempfile
        from pathlib import Path
        folder = Path(tempfile.mkdtemp())
        for pages, targets, variants, expected in ((8, 7, 0, 3600), (128, 28, 0, 6 * 128 * 28), (128, 8, 10, 6 * 128 * 28)):
            job = folder / f'job-{pages}-{variants}.json'; job.write_text(json.dumps({'pages': [{}] * pages, 'targets': [{}] * targets, 'variants': [{}] * variants}))
            self.assertEqual(U.node_timeout(job), expected)


class EmptyReport(unittest.TestCase):
    def test_report_without_any_checked_cell_is_not_pass(self):
        # A scan that `ux judge` rejects as stale must not yield a PASS report with zero cells.
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            (out / "ux-progress.json").write_text(json.dumps({"run_status": "complete", "stages": {"judge": "complete", "report": "complete"}}))
            u = helix_main.deep_merge(U.DEFAULT_UX, {"pages": [{"name": "start", "path": "/"}]})
            ctx = SimpleNamespace(cfg={"providers": {}}, repo=out, state_dir=out)
            rep = U.build_report(ctx, u, out, [{"id": "phone-small@portrait", "engine": "webkit", "label": "tel"}])
            self.assertEqual(sum(rep["counts"].values()), 0)
            self.assertFalse(rep["pass"])


class ScreenState(unittest.TestCase):
    # Splash screens, server function errors and empty pages are classified before judging, so the judge does not rate them as screens.
    def test_classifies_redirect_data_error_empty_and_content(self):
        full = {"text_chars": 900, "interactive_count": 20}
        self.assertEqual(U.screen_state({"screen": {"redirected": True}, "layout": full}), "redirected")
        self.assertEqual(U.screen_state({"collect": {"http_errors": ["500 http://h/functions/v1/fetch_orders"]}, "layout": full}), "data_error")
        self.assertEqual(U.screen_state({"screen": {"error_text": True}, "collect": {"http_errors": ["406 http://h/rest/v1/x"]}, "layout": full}), "data_error")
        self.assertEqual(U.screen_state({"collect": {"http_errors": ["406 http://h/rest/v1/x"]}, "layout": full}), "content")
        self.assertEqual(U.screen_state({"collect": {"http_errors": ["404 http://h/favicon.ico"]}, "layout": full}), "content")
        self.assertEqual(U.screen_state({"layout": {"text_chars": 48, "interactive_count": 0}}), "empty")
        self.assertEqual(U.screen_state({"layout": full}), "content")

    def test_judge_gets_only_screens_with_content(self):
        from types import SimpleNamespace
        from PIL import Image
        with tempfile.TemporaryDirectory() as d:
            out = Path(d); Image.new("RGB", (40, 80), (200, 200, 200)).save(out / "p.png")
            full = {"text_chars": 900, "interactive_count": 20}
            scan = {"results": [{"target": "t@portrait", "page": "ok", "variant": "base", "shot": "p.png", "findings": [], "layout": full},
                                {"target": "t@portrait", "page": "types", "variant": "base", "shot": "p.png", "findings": [], "layout": full,
                                 "screen": {"redirected": True, "final_path": "/"}}]}
            asked = []
            def ask(ctx, provider, prompt, **kw):
                asked.append(prompt)
                return json.dumps({"scores": {"layout": 4}, "issues": [], "summary": "ok", "valid": True}), {"provider": "p", "model": "m"}
            u = helix_main.deep_merge(U.DEFAULT_UX, {"judge": {"targets": "all", "max_pages": 4, "parallel": 1}})
            ctx = SimpleNamespace(cfg={"providers": {"visual_judge": "gemini"}}, repo=out)
            old = U.H.ask; U.H.ask = ask
            try: result = U.judge(ctx, u, out, scan, [{"id": "t@portrait", "engine": "webkit", "label": "t"}])["t@portrait"]
            finally: U.H.ask = old
            self.assertEqual(len(asked), 1)
            self.assertIn("ok", asked[0]); self.assertNotIn("types", asked[0])
            self.assertEqual(result["skipped_pages"], {"types": "redirected"})
            self.assertNotIn("not_judged_pages", result)


class JudgeResume(unittest.TestCase):
    def test_resume_keeps_fully_judged_devices_and_repeats_only_the_rest(self):
        # Projekt B: limity Gemini 4 i Flash high wyczerpane w trakcie; ponowna ocena wszystkiego od zera marnuje limit.
        from types import SimpleNamespace
        from PIL import Image
        with tempfile.TemporaryDirectory() as d:
            out = Path(d); Image.new("RGB", (40, 80), (200, 200, 200)).save(out / "p.png")
            ids = ["done@portrait", "failed@portrait", "partial@portrait"]
            scan = {"results": [{"target": t, "page": "p", "variant": "base", "shot": "p.png", "findings": []} for t in ids]}
            targets = [{"id": t, "engine": "chromium", "label": t} for t in ids]
            used = {"provider": "gemini-flash", "model": "m"}
            (out / "judge.json").write_text(json.dumps({"done@portrait": {"issues": [], "scores": {"layout": 3}, "_used": used},
                "failed@portrait": {"error": "limit"}, "partial@portrait": {"issues": [], "_used": used, "not_judged_pages": ["p"]}}))
            asked = []
            def ask(ctx, provider, prompt, **kw):
                asked.append(next(t for t in ids if t in prompt))
                return json.dumps({"scores": {"layout": 4}, "issues": [], "summary": "ok", "valid": True}), used
            u = helix_main.deep_merge(U.DEFAULT_UX, {"judge": {"targets": "all", "max_pages": 4, "parallel": 2, "resume": True}})
            ctx = SimpleNamespace(cfg={"providers": {"visual_judge": "gemini"}}, repo=out)
            old = U.H.ask; U.H.ask = ask
            try: result = U.judge(ctx, u, out, scan, targets)
            finally: U.H.ask = old
            self.assertEqual(sorted(asked), ["failed@portrait", "partial@portrait"])
            self.assertEqual(result["done@portrait"]["scores"], {"layout": 3})
            self.assertTrue(all(not v.get("error") and not v.get("not_judged_pages") for v in result.values()))

    def test_resume_repeats_only_failed_sheets_of_a_device(self):
        # Resuming a device with a few missing sheets judges only the missing ones, not all sheets again.
        from types import SimpleNamespace
        from PIL import Image
        with tempfile.TemporaryDirectory() as d:
            out = Path(d); Image.new("RGB", (40, 80), (200, 200, 200)).save(out / "p.png")
            pages = [f"p{i}" for i in range(8)]
            scan = {"results": [{"target": "dev@portrait", "page": p, "variant": "base", "shot": "p.png", "findings": []} for p in pages]}
            targets = [{"id": "dev@portrait", "engine": "chromium", "label": "dev"}]
            used = {"provider": "gemini-flash", "model": "m"}
            first, second = sorted(pages[:4]), sorted(pages[4:])
            (out / "judge.json").write_text(json.dumps({"dev@portrait": {
                "issues": [{"page": "p0", "severity": "high", "message": "stare"}], "scores": {"layout": 2}, "summary": "pierwszy",
                "valid": True, "_used": used, "not_judged_pages": second,
                "_sheets": [{"pages": first, "issues": 1}, {"pages": second, "error": "limit"}]}}))
            asked = []
            def ask(ctx, provider, prompt, **kw):
                asked.append(prompt)
                return json.dumps({"scores": {"layout": 3}, "issues": [{"page": "p5", "severity": "medium", "message": "nowe"}],
                                   "summary": "drugi", "valid": True}), used
            u = helix_main.deep_merge(U.DEFAULT_UX, {"judge": {"targets": "all", "max_pages": 4, "parallel": 1, "resume": True}})
            ctx = SimpleNamespace(cfg={"providers": {"visual_judge": "gemini"}}, repo=out)
            old = U.H.ask; U.H.ask = ask
            try: result = U.judge(ctx, u, out, scan, targets)["dev@portrait"]
            finally: U.H.ask = old
            self.assertEqual(len(asked), 1)
            self.assertTrue(all(p in asked[0] for p in second) and "p0" not in asked[0])
            self.assertEqual([i["message"] for i in result["issues"]], ["stare", "nowe"])
            self.assertEqual(result["scores"], {"layout": 2})
            self.assertNotIn("not_judged_pages", result)
            self.assertEqual(len(result["_sheets"]), 2)
