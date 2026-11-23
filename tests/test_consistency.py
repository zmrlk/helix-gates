"""UI consistency module tests: unit helpers, static layer, runtime on a fixture app with planted inconsistencies, contract + baseline gate.
Run: python3 -m unittest discover -s tests -v"""
import json, os, shutil, socket, subprocess, sys, tempfile, threading, unittest, functools, http.server
from pathlib import Path

HOME = Path(__file__).resolve().parent.parent
HELIX = HOME / "bin/helix"
FIX = HOME / "tests/fixtures/consistency-app"
sys.path.insert(0, str(HOME / "bin"))
from helix_contracts import VERSION
import importlib.machinery, importlib.util
if "helix_main" not in sys.modules:
    _l = importlib.machinery.SourceFileLoader("helix_main", str(HELIX)); _s = importlib.util.spec_from_loader("helix_main", _l)
    _m = importlib.util.module_from_spec(_s); sys.modules["helix_main"] = _m; _l.exec_module(_m)
helix_main = sys.modules["helix_main"]
from helix_dependencies import has_yaml, node_module
import helix_consistency as C
C.H = helix_main

def sh(cmd, cwd): return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=600)
def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def make_repo(port=None):
    d = Path(tempfile.mkdtemp(prefix="helix-cs-")); shutil.copytree(FIX, d, dirs_exist_ok=True)
    cfg = json.loads((d / "helix.json").read_text().replace("PORT", str(port or 1)))
    cfg["helix_version"] = VERSION
    # Static local HTML and synchronous handlers need no hydration/animation delay.
    # Navigation still waits for networkidle; all viewports and probes remain enabled.
    cfg["consistency"]["settle_ms"] = 0
    if port is None: cfg["consistency"]["pages"] = []
    (d / "helix.json").write_text(json.dumps(cfg))
    for c in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"]): sh(c, d)
    return d

class Unit(unittest.TestCase):
    def test_delta_e(self):
        self.assertLess(C.delta_e("rgb(26, 22, 15)", "#1a160f"), 0.5)
        self.assertGreater(C.delta_e("#ffffff", "#000000"), 90)
        self.assertLess(C.delta_e("rgba(0,0,0,0)", "rgba(255,0,0,0)"), 0.1)
    def test_near_duplicate_tiny_vs_large(self):
        tol = C.DEFAULT_CS["tolerances"]
        a = (("fs", 14.0), ("radius", 8.0), ("bg", "#1a160f")); b = (("fs", 13.0), ("radius", 8.0), ("bg", "#1a160f")); c = (("fs", 20.0), ("radius", 8.0), ("bg", "#1a160f"))
        self.assertTrue(C.compare(a, b, tol)[0]); self.assertFalse(C.compare(a, c, tol)[0]); self.assertFalse(C.compare(a, a, tol)[0])
        self.assertTrue(C.compare((("radius", 6.0),), (("radius", 8.0),), tol)[0])
        self.assertTrue(C.compare((("bg", "#1a160f"),), (("bg", "#2a2318"),), tol)[0])     # ΔE small -> near
        self.assertFalse(C.compare((("bg", "#1a160f"),), (("bg", "#dc2626"),), tol)[0])    # different colour -> distinct variant
    def test_english_detection(self):
        self.assertTrue(C.is_english("Insufficient permissions. Required: orders.approve"))
        self.assertTrue(C.is_english("Something went wrong, please try again"))
        for s in ("Zamówienie przyjęte", "Apple Pencil (2. generacji)", "Produkt testowy UX nr 10", "E2E Hurt Sp. z o.o.", "Status", "Dashboard"):
            self.assertFalse(C.is_english(s), s)
    def test_date_money_formats(self):
        self.assertEqual(C.date_kind("24.10.2026"), "DD.MM.RRRR"); self.assertEqual(C.date_kind("2026-10-24"), "RRRR-MM-DD")
        self.assertNotEqual(C.money_kind("1 234,56 zł"), C.money_kind("1234.56 PLN")); self.assertEqual(C.money_kind("99,00 zł"), C.money_kind("1 234,56 zł"))
        self.assertEqual(C.thousands_kind("1 234,56 zł"), "spacja"); self.assertIsNone(C.thousands_kind("99,00 zł"))
    def test_tag_scanner_handles_jsx_and_svelte(self):
        src = '<ul>{items.map((o) => (<li className="a b" key={o.id}>{o.x > 1 ? "y" : "n"}</li>))}</ul>\n<button class="x {on ? \'y\' : \'\'}" onclick={() => (open = true)}>A</button>'
        tags = [(n, cl) for _, cl, n, _, _ in C.scan_tags(src)]
        self.assertIn(("li", False), tags); self.assertIn(("button", False), tags)
        t = C.build_tree(src); names = [n["tag"] for n in C.walk(t)]
        self.assertEqual(names[:3], ["#root", "ul", "li"]); self.assertEqual(C.classes_of(' class="x {on ? \'y\' : \'\'} z"'), ["x", "z"])
    @unittest.skipUnless(has_yaml(), "PyYAML/js-yaml unavailable")
    def test_yaml_roundtrip(self):
        d = {"version": 1, "tokens": {"font_size": [12, 14.5], "colors": ["#fff", "rgba(0,0,0,0.1)"]}, "exceptions": [{"rule": "chrome-shared", "match": "a:b", "reason": "x # y"}],
             "copy": {"date_format": "DD.MM.RRRR", "yes": "no"}}
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "c.yaml"; p.write_text(C.dump_yaml(d)); self.assertEqual(C.load_yaml(p), d)

def _btn(label, ctx, fw, color="rgba(26,22,15,1)"):
    st = {"fs": 14, "fw": fw, "ff": "Arial", "radius": 8, "h": 36, "pt": 0, "pr": 16, "pb": 0, "pl": 16, "bg": "rgba(255,255,255,1)", "color": color,
          "bw": 1, "bc": "rgba(214,210,201,1)", "tt": "none", "ls": "normal", "shadow": False, "w": 80, "lh": 20}
    return {"role": "button", "variant": "secondary", "label": label, "ctx": ctx, "rect": [0, 0, 80, 36], "style": st, "icon": None}
def _raw(pages):
    return {"results": [{"page": p, "state": "base", "area": "admin", "target": "desktop", "kind": "desktop", "ok": True, "components": comps, "chrome": [], "copy": {}} for p, comps in pages]}

class FalsePositives(unittest.TestCase):
    """regressions from the example-app pilot: these must NOT be reported."""
    def test_active_nav_item_is_not_drift_but_page_button_is(self):
        tol = C.DEFAULT_CS["tolerances"]
        F = C.analyze_components(_raw([("a", [_btn("Katalog", "nav", 600)]), ("b", [_btn("Katalog", "nav", 400, "rgba(107,102,95,1)")]), ("c", [_btn("Katalog", "nav", 400, "rgba(107,102,95,1)")])]), tol)
        self.assertFalse([f for f in F if f["rule"] == "same-label-different-style"])
        F = C.analyze_components(_raw([("a", [_btn("Zapisz", "main", 600)]), ("b", [_btn("Zapisz", "main", 400)]), ("c", [_btn("Zapisz", "main", 400)])]), tol)
        self.assertTrue([f for f in F if f["rule"] == "same-label-different-style"])
    def test_more_is_not_a_details_synonym(self):
        self.assertNotIn("więcej", dict(C.SYNONYMS)["details"])
    def test_layout_only_class_bundles_are_not_components(self):
        nodes = [{"tag": "div", "classes": ["flex", "items-center", "justify-between", "gap-2"], "children": [], "file": f"f{i}.svelte", "line": 1} for i in range(5)]
        self.assertEqual(C.find_duplicates(nodes), [])
        nodes = [{"tag": "span", "classes": ["rounded-full", "px-2", "text-xs", "font-semibold", "bg-amber-100"], "children": [], "file": f"f{i}.svelte", "line": 1} for i in range(3)]
        self.assertEqual(len(C.find_duplicates(nodes)), 1)

class Static(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.repo = make_repo(); cls.st = C.static_scan(cls.repo, C.DEFAULT_CS["static"] | {"paths": ["src"]}); cls.F = C.analyze_static(cls.st, None)
    def rules(self): return [(f["rule"], f["title"], f["detail"]) for f in self.F]
    def test_shared_components_found(self):
        self.assertEqual(set(self.st["shared"]), {"button", "badge", "dialog"})
    def test_raw_button_where_shared_exists(self):
        f = [x for x in self.F if x["rule"] == "raw-element" and "admin/+page.svelte" in x["title"]]
        self.assertEqual(f[0]["count"], 3); self.assertEqual(f[0]["severity"], "low")
        self.assertEqual(f[0]["confidence"], "ASSUMPTION")  # presence is not an approved design contract
        C.ADOPTION.clear(); C.ADOPTION["button"] = 1
        agg = next(x for x in C.aggregate_static(self.F) if x["key"] == "agg:raw-element:button")
        self.assertEqual(agg["severity"], "low"); self.assertIn("adopcja", agg["title"])
        self.assertEqual(agg["confidence"], "ASSUMPTION")
        self.assertTrue(any(x["rule"] == "raw-element" and "InvoicesCard.tsx" in x["title"] for x in self.F))
        self.assertFalse(any(x["rule"] == "raw-element" and "ui/Button.svelte" in x["title"] for x in self.F))
    def test_own_modal_implementations(self):
        f = next(x for x in self.F if x["rule"] == "multi-impl"); self.assertIn("admin/+page.svelte", f["detail"]); self.assertIn("company/+page.svelte", f["detail"])
    def test_hardcoded_values(self):
        hard = " ".join(f["detail"] for f in self.F if f["rule"] == "hardcoded")
        self.assertIn("text-[13px]", hard); self.assertIn("#ff0000", hard); self.assertNotIn("w-[420px]", hard)
    def test_duplicated_badge_and_card(self):
        ex = [f for f in self.F if f["rule"] == "extract-component"]
        self.assertTrue(any("Badge" in f["title"] and f["count"] >= 3 for f in ex), [f["title"] for f in ex])
        self.assertTrue(any("Card" in f["title"] and "OrdersCard.tsx" in f["detail"] and "InvoicesCard.tsx" in f["detail"] for f in ex), [f["title"] for f in ex])

class Ratchet(unittest.TestCase):
    def f(self, key, sev="medium", conf="VERIFIED", count=None):
        return C.finding("x", sev, key, key, confidence=conf, count=count)
    def test_new_verified_fails_assumption_advisory(self):
        r = C.compare_baseline([self.f("a"), self.f("b", conf="ASSUMPTION")], {"keys": {}}, ["high", "medium"])
        self.assertEqual([x["key"] for x in r["new"]], ["a"]); self.assertEqual([x["key"] for x in r["advisory"]], ["b"]); self.assertFalse(r["pass"])
    def test_grown_count_fails(self):
        r = C.compare_baseline([self.f("a", count=5)], {"keys": {"a": {"severity": "medium", "count": 3}}}, ["medium"])
        self.assertEqual(len(r["worse"]), 1); self.assertFalse(r["pass"])
    def test_missing_coverage_is_incomplete(self):
        base = {"keys": {"a": {"severity": "medium", "layer": "runtime"}}, "coverage": ["p#base@desktop", "q#base@desktop"]}
        r = C.compare_baseline([], base, ["medium"], cov=[{"id": "p#base@desktop", "ok": True, "problems": []}])
        self.assertFalse(r["pass"]); self.assertEqual(r["incomplete"][0]["id"], "q#base@desktop"); self.assertEqual(r["fixed"], [])
    def test_expired_and_incomplete_exceptions(self):
        F = [self.f("rt:x:admin")]
        C.apply_contract(F, {"exceptions": [{"rule": "x", "match": "admin", "reason": "r", "owner": "k", "until": "2000-01-01"},
                                            {"rule": "x", "match": "zzz"}]})
        rules = [f["rule"] for f in F]
        self.assertEqual(F[0]["status"], "open"); self.assertIn("exception-expired", rules); self.assertIn("exception-incomplete", rules)

class Runtime(unittest.TestCase):
    """real Playwright run on the fixture app: every planted inconsistency must be caught."""
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(FIX / "public"))
        h.log_message = lambda *a, **k: None
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", cls.port), h)
        cls.addClassCleanup(cls.srv.server_close)
        thread = threading.Thread(target=cls.srv.serve_forever, daemon=True); thread.start()
        cls.addClassCleanup(thread.join)
        cls.addClassCleanup(cls.srv.shutdown)
        cls.repo = make_repo(cls.port)
        cls.out = cls.repo / "out"; r = sh([str(HELIX), "consistency", "all", "--out", str(cls.out)], cls.repo)
        assert r.returncode == 0, r.stderr[-2000:]
        cls.F = json.loads((cls.out / "findings.json").read_text())
    def has(self, rule, *subs):
        for f in self.F:
            t = f["title"] + " " + f["detail"]
            if f["rule"] == rule and all(s in t for s in subs): return f
        self.fail(f"brak {rule} {subs}; są: " + "\n".join(f"{f['rule']}: {f['title']}" for f in self.F))
    def test_button_13_vs_14(self): self.has("same-label-different-style", "Zapisz", "13px ↔ 14px")
    def test_radius_6_vs_8(self): self.has("near-duplicate", "zaokrąglenie: 6px ↔ 8px")
    def test_badge_11_vs_12(self): self.has("near-duplicate", "Plakietka", "11px ↔ 12px")
    def test_missing_icon(self): self.has("icon-presence", "Eksport")
    def test_toast_vs_inline(self): self.has("pattern-notification", "toast", "inline")
    def test_details_vs_preview_label(self): self.has("copy-synonym", "szczegóły", "podgląd")
    def test_details_drawer_vs_page(self): f = self.has("pattern-details", "szuflada z prawej", "osobna strona"); self.assertEqual(f["severity"], "high")
    def test_english_backend_error(self): self.has("copy-english", "Insufficient permissions")
    def test_admin_with_shop_header(self): self.has("chrome-foreign", "Koszyk", "Ulubione")
    def test_sidebar_card_vs_flat(self): self.has("sidebar-style", "karta: admin=nie, company=tak")
    def test_date_and_money_formats(self): self.has("copy-date", "DD.MM.RRRR", "RRRR-MM-DD"); self.has("copy-money", "PLN")
    def test_token_drift_13px(self): self.has("token-drift", "font-size 13px")
    def test_report_files(self):
        for n in ("consistency-report.md", "consistency-report.html", "consistency-top.png", "proposed-components.md", "design-contract.proposed.yaml"):
            self.assertTrue((self.out / n).exists(), n)
        md = (self.out / "consistency-report.md").read_text(); self.assertIn("## Top", md); self.assertIn("VERIFIED", md)
        prop = C.load_yaml(self.out / "design-contract.proposed.yaml")
        self.assertEqual(prop["patterns"]["details"]["status"], "proposal"); self.assertIn("button", prop["components"])
        self.assertIn("Koszyk", prop["areas"]["admin"]["chrome_forbidden"])
    def test_ratchet_gate_runtime(self):
        r = sh([str(HELIX), "consistency", "baseline", "--out", str(self.repo / "b1")], self.repo); self.assertEqual(r.returncode, 0, r.stderr[-800:])
        g = sh([str(HELIX), "gate", "consistency"], self.repo); self.assertEqual(g.returncode, 0, g.stdout + g.stderr[-800:])
        # plant a NEW drift (green button with another radius) in a copy of the fixture site served by a second server
        pub = self.repo / "public"; (pub / "company.html").write_text((pub / "company.html").read_text().replace(
            '<button class="btn btn-primary">Zapisz</button>', '<button class="btn btn-primary" style="border-radius:5px">Zapisz</button>'))
        port = free_port(); h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(pub)); h.log_message = lambda *a, **k: None
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), h)
        thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
        try:
            cfg = json.loads((self.repo / "helix.json").read_text()); cfg["consistency"]["base_url"] = f"http://127.0.0.1:{port}/"; (self.repo / "helix.json").write_text(json.dumps(cfg))
            g = sh([str(HELIX), "gate", "consistency"], self.repo); self.assertEqual(g.returncode, 2, g.stdout)
            res = json.loads(g.stdout.strip().splitlines()[-1]); self.assertGreaterEqual(res["counts"]["new"], 1)
        finally:
            srv.shutdown(); thread.join(); srv.server_close(); cfg["consistency"]["base_url"] = f"http://127.0.0.1:{self.port}/"; (self.repo / "helix.json").write_text(json.dumps(cfg))

class Gate(unittest.TestCase):
    @unittest.skipUnless(has_yaml(), "PyYAML/js-yaml unavailable")
    def test_static_ratchet_new_and_fixed_and_exception(self):
        repo = make_repo()
        contract = {"version": 1, "status": "approved", "components": {"button": {"component": "Button", "require": True}}}
        (repo / "design-contract.yaml").write_text(C.dump_yaml(contract))
        r = sh([str(HELIX), "consistency", "baseline", "--static-only", "--out", str(repo / "b")], repo); self.assertEqual(r.returncode, 0, r.stderr[-800:])
        self.assertTrue((repo / "design-baseline.json").exists())
        g = sh([str(HELIX), "gate", "consistency", "--static-only"], repo); self.assertEqual(g.returncode, 0, g.stdout + g.stderr[-500:])
        # new raw <button> in another file -> FAIL; more raw buttons in a known file -> FAIL (count ratchet)
        (repo / "src/routes/shop/New.svelte").write_text('<button class="px-2">Kup</button>\n<button>Dodaj</button>\n<button>X</button>\n')
        g = sh([str(HELIX), "gate", "consistency", "--static-only"], repo); self.assertEqual(g.returncode, 2, g.stdout)
        self.assertIn("st:raw:button:src/routes/shop/New.svelte", json.loads((repo / "helix-evidence").glob("consistency.json").__next__().read_text())["new"])
        # declared exception in the contract -> PASS again
        contract["exceptions"] = [{"rule": "raw-element", "file": "New\\.svelte", "reason": "prototyp", "owner": "fixture owner"}]
        (repo / "design-contract.yaml").write_text(C.dump_yaml(contract))
        g = sh([str(HELIX), "gate", "consistency", "--static-only"], repo); self.assertEqual(g.returncode, 0, g.stdout + g.stderr[-500:])
        # checkpoint form writes evidence under helix-evidence/<cp>/consistency.json
        (repo / "src/routes/shop/New.svelte").unlink()
        g = sh([str(HELIX), "gate", "consistency", "cp1", "--static-only"], repo); self.assertEqual(g.returncode, 0, g.stdout + g.stderr[-500:])
        self.assertTrue((repo / "helix-evidence/cp1/consistency.json").exists())

def load_tests(loader, tests, pattern):
    # Keep the server fixture importable for fake-server cleanup tests. Real browser
    # cases are selected only by the explicit integration switch.
    classes = [Unit, FalsePositives, Static, Ratchet, Gate]
    if os.environ.get('HELIX_BROWSER_IT') == '1':
        classes.append(Runtime)
    return unittest.TestSuite(loader.loadTestsFromTestCase(cls) for cls in classes)

if __name__ == "__main__":
    unittest.main()
