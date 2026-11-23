"""G0 'Prawda i kontekst' tests. Origin case: example-app ERP called 'LegacyERP' (name in code) while prod uses Example ERP.
Run: python3 -m unittest discover -s tests -v"""
import datetime as dt
import contextlib, io
from types import SimpleNamespace
from unittest.mock import patch
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path

HELIX = Path(__file__).resolve().parent.parent / "bin/helix"
sys.path.insert(0, str(HELIX.parent))
from helix_contracts import VERSION
from test_provider_plan import load_helix

def sh(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, shell=isinstance(cmd, str))

class TruthGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); r = self.repo = Path(self.tmp.name)
        (r / "src").mkdir(); (r / "deploy").mkdir(); (r / "test").mkdir()
        # legacy name in code, real backend in deploy config (the LegacyERP/ExampleERP trap)
        (r / "src/erp.js").write_text("// legacy LegacyERP client (kept for history)\nexport const legacyERP = { url: process.env.LEGACY_ERP_URL };\n"
                                      "export function sendOrder(o) { return { backend: process.env.ERP_BACKEND, total: o.total }; }\n")
        (r / "deploy/docker-compose.yml").write_text("services:\n  worker:\n    environment:\n      ERP_BACKEND: exampleERP\n")
        (r / "test/erp.test.js").write_text("import { test } from 'node:test'; import assert from 'node:assert/strict';\n"
                                            "import { sendOrder } from '../src/erp.js';\n"
                                            "test('keeps total', () => assert.equal(sendOrder({ total: 5 }).total, 5));\n")
        (r / "package.json").write_text('{"name":"t","private":true,"type":"module","scripts":{"test":"node --test"}}')
        (r / "helix.json").write_text(json.dumps({"helix_version": VERSION, "test_cmd": "node --test", "data_egress": {"status": "approved", "allowed_providers": ["grok"], "exclude_paths": []}}))
        for c in (["git", "init", "-q"], ["git", "add", "-A"],
                  ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init"]):
            sh(c, r)
        self.ev = r / "helix-evidence/cp1"

    def tearDown(self): self.tmp.cleanup()

    def helix(self, *args): return sh(["python3", str(HELIX), "--repo", str(self.repo), *args], self.repo)

    def ledger(self, **kw):
        t = json.loads((self.ev / "truth.json").read_text()); t.update(kw)
        (self.ev / "truth.json").write_text(json.dumps(t))

    def gate(self):
        p = self.helix("gate", "truth", "cp1"); return p, json.loads((self.ev / "truth-gate.json").read_text())

    def test_init_writes_template_and_template_fails(self):
        self.assertEqual(self.helix("truth", "init", "cp1").returncode, 0)
        self.assertTrue((self.ev / "truth.json").exists())
        p, r = self.gate()
        self.assertEqual(p.returncode, 2); self.assertFalse(r["pass"])
        self.assertTrue(any("placeholder" in f for f in r["fails"]))

    def test_origin_case_name_in_code_is_not_proof(self):
        self.helix("truth", "init", "cp1", "--kind", "report")
        self.ledger(systems=[{"name": "ERP", "flow": "order sync", "touched": True, "status": "unconfirmed"}],
                    claims=[{"id": "C1", "text": "example-app sends orders to LegacyERP ERP", "tag": "VERIFIED", "affects_prod": True,
                             "evidence": ["src/erp.js:2"]}])
        (self.ev / "truth-check.json").write_text(json.dumps({"false_claims": [], "break_risks": [], "summary": "-"}))
        p, r = self.gate()
        self.assertFalse(r["pass"]); self.assertIn("name in code is not proof", " ".join(r["fails"]))
        # same claim re-tagged as ASSUMPTION is allowed in a report (must be shown as assumption)
        self.ledger(claims=[{"id": "C1", "text": "ERP might be LegacyERP (name in src/erp.js)", "tag": "ASSUMPTION",
                             "affects_prod": True, "evidence": ["src/erp.js:2"], "source_status": "FOUND", "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(), "ttl": 3600}])
        p, r = self.gate()
        self.assertTrue(r["pass"], r); self.assertFalse(r["pr_allowed"]); self.assertTrue(r["warns"])

    def test_gate_rejects_saved_zero_test_suites(self):
        self._fix_ledger("confirmed", "pr")
        truth = json.loads((self.ev / "truth.json").read_text())
        for phase in ("before", "after"):
            truth["behaviour"]["suite_" + phase]["passed"] = 0
        self.ledger(behaviour=truth["behaviour"])
        _, result = self.gate()
        self.assertFalse(result["pass"])
        self.assertIn("0 passed", " ".join(result["fails"]))

    def test_unlabeled_and_bad_evidence_fail(self):
        self.helix("truth", "init", "cp1", "--kind", "report")
        self.ledger(systems=[], claims=[{"id": "C1", "text": "Tpay webhook marks paid"},
                                        {"id": "C2", "text": "x", "tag": "VERIFIED", "evidence": ["src/erp.js:99"]},
                                        {"id": "C3", "text": "y", "tag": "VERIFIED", "evidence": ["sha:deadbeef"]}])
        p, r = self.gate(); fails = " ".join(r["fails"])
        self.assertFalse(r["pass"]); self.assertIn("unlabeled", fails)
        self.assertIn("has 3 lines, cited 99", fails); self.assertIn("deadbeef not found", fails)

    def test_zero_tests_is_error(self):
        self.helix("truth", "init", "cp1")
        (self.repo / "test/erp.test.js").unlink()
        result = self.helix("truth", "suite", "cp1", "before")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("0 tests", result.stderr)
        suite = json.loads((self.ev / "truth.json").read_text())["behaviour"]["suite_before"]
        self.assertEqual(suite["passed"], 0)

    def _fix_ledger(self, status, target):
        self.helix("truth", "init", "cp1", "--target", target)
        (self.repo / "src/erp.js").write_text((self.repo / "src/erp.js").read_text() + "// fix\n")
        self.ledger(systems=[{"name": "ERP: Example ERP", "flow": "order sync worker", "touched": True, "status": status,
                              "confirmed_by": "Owner, chat 24.10.2026" if status == "confirmed" else ""}],
                    claims=[{"id": "C1", "text": "Prod worker uses ExampleERP backend", "tag": "VERIFIED", "affects_prod": True,
                             "evidence": ["config:deploy/docker-compose.yml:4", "owner:Owner, chat 24.10.2026"],
                             "source_status": "FOUND", "retrieved_at": dt.datetime.now(dt.timezone.utc).isoformat(), "ttl": 3600},
                            {"id": "C2", "text": "sendOrder keeps the total", "tag": "VERIFIED", "affects_prod": False,
                             "evidence": ["src/erp.js:3"]}],
                    behaviour={"characterization_tests": ["test/erp.test.js: keeps total"], "diff_allowlist": ["src/erp.js"]})
        self.assertEqual(self.helix("truth", "suite", "cp1", "before").returncode, 0)
        self.assertEqual(self.helix("truth", "suite", "cp1", "after").returncode, 0)
        t = json.loads((self.ev / "truth.json").read_text())
        self.assertEqual(t["behaviour"]["suite_after"]["passed"], 1)
        # Admission is exercised through the real CLI. The following local
        # checker adapter is an explicit synthetic fixture for truth-gate rules,
        # not evidence of a successful manual export or model execution.
        # Decyzja właściciela 15.11.2026: wysyłka jest dopuszczona, więc ręczny handoff Groka zapisuje zlecenie i czeka na werdykt.
        pending = self.helix("truth", "check", "cp1", "--provider", "grok")
        self.assertNotEqual(pending.returncode, 0, pending.stdout + pending.stderr)
        self.assertIn("request written", pending.stdout + pending.stderr)
        self.assertTrue((self.ev / "review-request-truth.md").exists())
        answer = json.dumps({"summary": "synthetic checker", "false_claims": [], "break_risks": [
            {"file": "src/erp.js", "severity": "major", "issue": "retry may resend", "how_to_verify": "test"}]})
        H = load_helix()
        ctx = H.Ctx(self.repo)
        with patch.object(H, 'call_grok', return_value=answer) as checker, contextlib.redirect_stdout(io.StringIO()):
            H.cmd_truth(ctx, SimpleNamespace(action='check', checkpoint='cp1', provider='grok'))
        checker.assert_called_once()
        result = json.loads((self.ev / 'truth-check.json').read_text())
        self.assertEqual(result['break_risks'][0]['id'], 'F1')

    def test_unconfirmed_system_blocks_pr_but_allows_local(self):
        self._fix_ledger("unconfirmed", "pr")
        self.ledger(independent_check={"file": "truth-check.json", "resolutions": {"F1": "covered by test/erp.test.js, no resend path"}})
        p, r = self.gate(); self.assertFalse(r["pass"]); self.assertIn("UNCONFIRMED", " ".join(r["fails"]))
        self.ledger(target="local"); p, r = self.gate()
        self.assertTrue(r["pass"], r); self.assertTrue(r["local_only"]); self.assertFalse(r["pr_allowed"])

    def test_full_pass_and_unresolved_check_fails(self):
        self._fix_ledger("confirmed", "pr")
        p, r = self.gate(); self.assertFalse(r["pass"]); self.assertIn("unresolved ['F1']", " ".join(r["fails"]))
        self.ledger(independent_check={"file": "truth-check.json", "resolutions": {"F1": "no retry path in diff, see src/erp.js:3"}})
        p, r = self.gate(); self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertTrue(r["pass"]); self.assertTrue(r["pr_allowed"])
        self.assertIn("PASS", (self.ev / "truth.md").read_text())

    def test_diff_outside_allowlist_and_regression_fail(self):
        self._fix_ledger("confirmed", "pr")
        (self.repo / "deploy/docker-compose.yml").write_text("services: {}\n")  # unrelated prod config change
        t = json.loads((self.ev / "truth.json").read_text())
        t["behaviour"]["suite_after"]["passed"] = 0; t["behaviour"]["suite_after"]["failed"] = 1
        t["independent_check"]["resolutions"] = {"F1": "no retry path in diff, see src/erp.js:3"}
        (self.ev / "truth.json").write_text(json.dumps(t))
        p, r = self.gate(); fails = " ".join(r["fails"])
        self.assertIn("outside allowlist", fails); self.assertIn("after 0 passed/1 failed", fails)

    def test_required_truth_blocks_approve(self):
        (self.repo / "helix.json").write_text(json.dumps({"helix_version": VERSION, "test_cmd": "node --test", "truth": {"required": True}}))
        hx = self.repo / ".helix"; hx.mkdir(exist_ok=True)
        (hx / "plan.json").write_text(json.dumps({"checkpoints": [{"id": "cp1", "title": "t", "goal": "g"}]}))
        (hx / "cp1.state.json").write_text(json.dumps({"id": "cp1", "status": "awaiting_approval", "gates": {}, "log": []}))
        p = self.helix("approve", "cp1")
        self.assertNotEqual(p.returncode, 0); self.assertIn("G0 truth gate required", p.stderr)

if __name__ == "__main__": unittest.main()
