# Local claim ledger — Pro maturity extension

G0 status: NOT RUN, no PASS and no PR/readiness claim. The operator prohibited git, network,
private memory access and commits. `bin/helix` cmd_truth(init) calls git;
cmd_plan reads memory and calls a provider; cmd_run calls git. Those commands were
not run. This document is a local claim ledger, not generated G0 evidence.
No live systems are touched (`systems: []`); no production claims are made.

| Tag | Claim | Local evidence |
|---|---|---|
| VERIFIED | Existing catalog extended, not replaced by parallel pipelines | new/profiles/pro-standard.json:1; new/templates/ci/ |
| VERIFIED | Runtime controls earn no verified points | bin/helix_pro.py:1; tests/test_pro_maturity.py:1 |
| VERIFIED | Offline plan emits schema checkpoint fields and refuses overwrite | bin/helix_new.py:1; tests/test_pro_maturity.py:1; schemas/plan.json:1 |
| VERIFIED | Design-reference and UX-review workflows are templates, not executed agent reviews | new/templates/DESIGN.md.tpl:1; new/templates/ux-review.md.tpl:1 |
| VERIFIED | Local Oil UI reference declares MIT licensing | <workspace>/refs/oil-ui/LICENSE:1 |
| ASSUMPTION | Research recommendations fit a particular deployment or legal context | Owner review required; no runtime/production verification |

Baseline before edits: test_pro.py 6 PASS; test_new.py 50 PASS.
After edits: test_pro*.py 17 PASS (11 new tests); test_new.py 50 PASS.
Full discovery is run with an external test-only restriction hook that prevents
Git, network, installation and provider subprocesses. Any affected test is skipped,
never reported as PASS. The full unrestricted suite cannot be claimed green.

VERIFIED: restricted full discovery: 221 discovered, 110 PASS, 111 SKIP, 0 failures/errors.
Command: `PYTHONPATH=/tmp/helix-offline-tests python3 -m unittest discover -s tests -v`.
Log: `/tmp/helix-offline-tests/results.log`; hook: `/tmp/helix-offline-tests/sitecustomize.py`.
The hook refuses prohibited subprocesses and socket operations before execution.
