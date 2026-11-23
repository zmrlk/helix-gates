# Project running skill

ASSUMPTION: preparation workflow; owner must approve project specifics.

Workflow: intake -> evidence -> requirements -> ADR -> brand check -> design -> program -> handoff. Read brand.yaml, DESIGN.md and design-contract.yaml before UI work; never invent brand. Separate current behavior from proposals.

Commands and gates: helix new brand check; helix new check; helix plan; helix truth init cpN; helix truth suite cpN before; helix truth suite cpN after; helix truth check cpN; helix gate truth cpN; helix run cpN. Use behavior, visual, review, security, integrity, perf, UX and consistency gates as configured. Never skip a gate or commit yourself.

Track work with helix board and helix task; keep WIP at most 5.

Closure evidence: link command outputs, acceptance tests and gate verdicts before requesting owner approval; only exit 0 means PASS; exit 2 is FAIL; ERROR is not PASS.

Escalation: stop for missing brand, unconfirmed production behavior, regulatory interpretation, spend, auth, payments, migrations or failed gates; ask the named owner.

Update documentation, traceability, hashes and acceptances when artifacts change.

ASSUMPTION: design workflow after approved brand intake:
1. Inventory key screens/flows for mobile and web. Adapt `new/templates/design-references.json.tpl`;
   retain 3–5 distinct pattern links and rationale for each flow (M+ audit control).
   Sources may include Mobbin, Refero, Appshots, 60fps and UI Sources.
2. Never copy third-party branding/assets. Brand colors, fonts, logos and assets
   always come from approved brand intake. A style preset only layers density,
   composition and motion onto that brand; record rationale and owner choice.
3. After a usable prototype, after material flow changes and before handoff,
   complete `new/templates/ux-review.md.tpl` using existing UX/consistency probes.
   A static review cannot satisfy runtime verification.

Before implementation: adapt design-decision.json.tpl into design-decisions/cpN.json; obtain human acceptance of a selected variant with two distinct approaches, benefits and trade-offs. Never invent approval. End checkpoint report and HANDOFF with ## What changed and why, concrete changes, purpose, validation and risks. For brownfield, review system-map.json; static imports are ASSUMPTION rather than verified runtime topology.
