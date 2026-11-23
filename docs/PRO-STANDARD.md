# Helix Pro standard

ASSUMPTION: this is Helix project policy, synthesized from local council research;
weights and thresholds are recommendations, not certification or requirements
imposed by the cited organizations. External links were not fetched in this task.

VERIFIED (implementation): the versioned [catalog](../new/profiles/pro-standard.json)
and [offline scorer](../bin/helix_pro.py) cover nine areas. Audit never executes
repository code, probes, Lighthouse, k6 or CI. Evidence means bounded source
presence; it does not prove quality, execution or production behavior.

```sh
helix new audit --repo ./existing --profile M --out ./audit-output
helix new plan --to pro --audit ./audit-output/audit.json --out ./improvement-plan.json
```

Audit outputs per-area scores, top three gaps and three remediation steps per gap,
including a shipped template and Helix command. JSON includes every applicable
control, threshold, source, evidence and remediation. `satisfied` means offline
selectors matched; `status` is authoritative about verification scope.
`needs-runtime` applies even when runtime configuration is missing. UX/a11y use
`helix ux`; rendered UI uses `helix consistency scan`; performance uses the existing
k6 baseline and Lighthouse/field measurements. These commands are proposed actions,
never executed by audit. Runtime results are not imported by this version.

Scoring: per area, round(100 × eligible weight / applicable weight). Eligible means
present offline evidence, no runtime requirement and no exception. Runtime
controls and owner exceptions earn zero. `preparation_score` also credits configured
runtime controls, excluding exceptions. Overall score averages area scores with
weights security=3, data=3, ops/reliability=2, documentation=2, all others=1. Missing evidence earns
zero; it is not proof of a missing feature. Draft placeholders earn zero. Profile
inheritance S→M→L→XL selects controls; M+ existing CI blockers still check preparation.
Security/data/ops controls have weight 3; most other controls weight 2; the catalog
records each weight. No aggregate score can waive a critical defect.

ASSUMPTION: a proposed Pro target is ≥85 in each applicable area plus successful
runtime and human reviews of critical controls. Offline audit cannot certify this
target; runtime-heavy areas intentionally cannot achieve it on configuration alone.
The generated plan includes all missing, runtime and excepted controls, ordered by
security/data, then reliability, then remaining controls; weight and ID break ties.
It contains only fields allowed by [schemas/plan.json](../schemas/plan.json), and
never changes `.helix`, runs checkpoints, commits or grants approval. Owners must
confirm applicability (including projects with no UI/persistent data), then use G0
and normal checkpoint gates. N/A qualification and runtime evidence import remain
future work; do not manufacture points to compensate.

## Control matrix

Detection O = offline preparation; R = runtime required, always needs-runtime here.
Each threshold is the review target, not proof established by a regex match.

| Area | Control ID (profile+) | Detection | Threshold / review target | Remediation template | Source |
|---|---|---|---|---|---|
| performance | slo (S+) | O | Every critical path declares a positive p95_ms budget, error_rate in [0,1), window and owner. | [template](../new/templates/slo.yaml.tpl) | [source](https://sre.google/sre-book/service-level-objectives/) |
| performance | load (M+) | O+R | All project k6 thresholds pass at the declared load; configuration alone earns no verified points. | [template](../new/templates/ci/k6-baseline.js) | [source](https://grafana.com/docs/k6/latest/using-k6/thresholds/) |
| security | threat-model (S+) | O | Assets, trust boundaries, abuse cases and applicable ASVS version/IDs are reviewed with named owners. | [template](../new/templates/threat-model.md.tpl) | [source](https://asvs.owasp.org/) |
| backend/architecture | architecture (S+) | O | Boundaries and owners documented; advanced complexity has an approved ADR and measurable trigger. | [template](../new/templates/architecture.yaml.tpl) | [source](https://12factor.net/) |
| UX | ux-probes (S+) | O+R | All critical persona flows complete with no blocking UX findings across the declared device matrix. | [template](../new/templates/ux-review.md.tpl) | [source](https://www.w3.org/TR/WCAG22/) |
| UI | design-contract (S+) | O | Approved brand source exists; DESIGN and design-contract project exactly the approved color/font tokens. | [template](../new/templates/DESIGN.md.tpl) | [source](https://shopify.dev/docs/api/polaris) |
| UI | consistency (M+) | O+R | Rendered key states contain no unapproved significant token/component deviations. | [template](../new/templates/design-contract.yaml.tpl) | [source](https://shopify.dev/docs/api/polaris) |
| ops/reliability | ops-slo (S+) | O | Each SLI has target, measurement window, error-budget action and alert owner. | [template](../new/templates/slo.yaml.tpl) | [source](https://sre.google/sre-book/evolving-sre-engagement-model/) |
| data | data-model (S+) | O | Documented relations, constraints and migrations preserve declared business invariants. | [template](../new/templates/data-model.yaml.tpl) | [source](https://sre.google/sre-book/data-integrity/) |
| testing/CI | postgres-ci (M+) | O | CI declares PostgreSQL, connection wiring, migrations and integration tests; execution still unverified. | [template](../new/templates/ci/postgres.yml) | [source](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers) |
| testing/CI | playwright-ci (M+) | O | Playwright configuration and a CI execution command exist; actual E2E success still unverified. | [template](../new/templates/ci/e2e.yml) | [source](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers) |
| testing/CI | k6-ci (M+) | O | CI includes the budgeted k6 execution command; actual threshold results still unverified. | [template](../new/templates/ci/load.yml) | [source](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers) |
| ops/reliability | ha (L+) | O | Replica/failover design and recovery responsibilities are documented; controlled failover remains unverified. | [template](../new/templates/regions-dr.yaml.tpl) | [source](https://sre.google/sre-book/evolving-sre-engagement-model/) |
| data | restore (L+) | O+R | Backup/restore procedure is connected to CI; observed restore must meet declared RTO/RPO. | [template](../new/templates/backup-restore-drill.md.tpl) | [source](https://sre.google/sre-book/data-integrity/) |
| ops/reliability | observability (L+) | O | Structured redacted logs, metrics, traces and actionable alerts have named owners. | [template](../new/templates/runbook.md.tpl) | [source](https://sre.google/sre-book/evolving-sre-engagement-model/) |
| backend/architecture | shared-rate-limit (L+) | O | Concurrent clients share a bounded rate limiter with tested 429 and Retry-After behavior. | [template](../new/templates/architecture.yaml.tpl) | [source](https://12factor.net/) |
| backend/architecture | distributed-locks (L+) | O | Job lease/fencing and deduplication prevent duplicate effects under retry/concurrent delivery. | [template](../new/templates/architecture.yaml.tpl) | [source](https://12factor.net/) |
| testing/CI | tests (S+) | O | Versioned behavior tests cover critical paths and negative cases; execution still unverified. | [template](../new/templates/ci/e2e.yml) | [source](https://docs.github.com/en/actions/tutorials/use-containerized-services/create-postgresql-service-containers) |
| performance | cwv (S+) | O+R | Field p75 LCP <=2500ms, INP <=200ms, CLS <=0.1; Lighthouse lab cannot establish field INP. | [template](../new/templates/cwv-budget.md.tpl) | [source](https://web.dev/articles/vitals) |
| security | asvs (S+) | O | Applicable ASVS controls have owners and negative tests; no unresolved confirmed high/critical findings. | [template](../new/templates/asvs-matrix.md.tpl) | [source](https://asvs.owasp.org/) |
| UX | a11y (S+) | O+R | No blocking accessibility defects; automated checks alone do not establish WCAG conformance. | [template](../new/templates/a11y-checklist.md.tpl) | [source](https://www.w3.org/TR/WCAG22/) |
| UI | design-references (M+) | O | Every declared key flow has 3–5 references with URL and rationale; owner confirms flow coverage. | [template](../new/templates/design-references.json.tpl) | [source](https://x.com/Abmankendrick/status/2114269196804592099) |
| UX | ux-review (M+) | O+R | Critical flow reaches an observable result; top 3 issues include evidence; static review remains needs-runtime. | [template](../new/templates/ux-review.md.tpl) | [source](https://github.com/oil-oil/oil-ui) |
| ops/reliability | prr (S+) | O | Named owner, SLO, actionable alerts, rollback and restore evidence reviewed. | [template](../new/templates/prr-checklist.md.tpl) | [source](https://sre.google/sre-book/evolving-sre-engagement-model/) |
| data | backup-policy (S+) | O+R | Measured restore meets RPO/RTO and preserves invariants; offline audit cannot prove execution. | [template](../new/templates/backup-restore-drill.md.tpl) | [source](https://sre.google/sre-book/data-integrity/) |

## Design references and task review

After approved brand intake, inventory key screens/flows and fill
[design-references.json](../new/templates/design-references.json.tpl): 3–5 distinct
pattern URLs with rationale per key mobile/web flow. M+ audits check declared
coverage and structure; owners verify completeness. Mobbin (mobbin.com), Refero
(refero.design), Appshots, 60fps (60fps.design) and UI Sources (uisources.com) are
inspiration sources supplied in the [UI reference post](https://x.com/Abmankendrick/status/2114269196804592099).
Never copy another brand or assets. Colors, fonts, logos and assets always come
from approved brand intake. Style presets may adjust density, composition and
motion only, with rationale and owner choice.

Use the [UX review draft](../new/templates/ux-review.md.tpl) after a usable prototype,
after significant flow changes and before handoff. A reviewer infers a goal from
the interface and follows a main path; record actual outcomes and at most three
significant issues, separating observations from hypotheses. Run existing UX and
consistency probes, fix issues and recheck. Static review is explicitly incomplete.
This is an adaptation of ideas from [Oil UI](https://github.com/oil-oil/oil-ui), supplied
via [the second post](https://x.com/Yarad_ai/status/2114024642897723845), not a new
agent runner. The local reference has MIT LICENSE, SKILL.md, references/, scripts/,
assets/ and tests/. No code, text excerpts or assets were vendored; templates were
written for Helix. No third-party notice for copied material is required.

## Research provenance and limits

Local inputs: `research-codex.md`, `research-grok.md`, `research-agy.md` and
`research-team.md` under `<workspace>/gaps/`. Recommendations were
merged into the existing catalog and PostgreSQL/E2E/k6 templates, without adding
duplicate pipelines. Team ideas retained: silent failure detection and authorization
expiry in PRR/runbook, idempotency in backend remediation, redaction and untrusted
input in ASVS/threat-model drafts. Product-specific reports and private source
paths were not used as evidence of current vulnerabilities or production behavior.

Primary reference families: [ASVS](https://asvs.owasp.org/),
[WCAG 2.2](https://www.w3.org/TR/WCAG22/), [CWV](https://web.dev/articles/vitals),
[k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/),
[Google SRE](https://sre.google/sre-book/evolving-sre-engagement-model/),
[12-factor](https://12factor.net/), [DORA](https://dora.dev/guides/dora-metrics/),
[SLSA](https://slsa.dev/), [Scorecard](https://scorecard.dev/).
DORA trends, provenance verification, deep ASVS execution and automated drills
remain roadmap work; citing them does not claim Helix implements those verifiers.

Verification and G0 limits: [local evidence ledger](PRO-STANDARD-EVIDENCE.md).

## 0.4.0-beta offline additions

VERIFIED (catalog and `tests/test_sweep.py`): `documentation` is area nine, weight 2.
The weighted percentage uses the same denominator/zero-credit exception policy
as other areas. Targets S=50, M=70, L=85, XL=90 are advisory and emitted as
`target`/`meets_target`; they do not silently waive gates. Eleven controls:
`docs-quickstart` (3), `docs-architecture` (3), `docs-adr` (2), `docs-api` (3),
`docs-data` (2), `docs-runbook` (3), `docs-onboarding` (2), `docs-changelog` (1),
`docs-user-admin` (2), `docs-freshness` (3), `docs-ownership` (3). Both user and admin guides are required.
Selectors check bounded non-placeholder content, not the validity of OpenAPI or
Mermaid syntax. External docs_paths use the same explicit bounded document reader.
Every Markdown and OpenAPI/data-model/schema document in the bounded inventory needs an owner, nonfuture ISO
review date and explicit `code` list in `docs-metadata.json`. Empty code lists are
allowed for documents that describe no code. Paths resolve relative to the
metadata file and must belong to the existing readable audit inventory; metadata
never grants permission to read another file. External `docs_paths` can include
both the documents and their metadata. Freshness requires at least one described
code file and checks every document/code pair: document mtime older than code or
review date before code mtime produces a warning and no freshness credit.
An unrelated recent document or JSON file cannot mask a stale pair. Checkouts and
clock skew can still mislead the heuristic; semantic correctness remains unverified.
Remediation: `new/templates/docs-metadata.json.tpl` and
`new/templates/documentation-pack.md.tpl`; update examples and reviews with code.
Custom gates accept `area: "documentation"`; unexecuted gates earn no score.
External observability/postmortem contracts undergo the same populated-schema
validation as local evidence.

VERIFIED (schemas, catalog and tests): M+ `privacy-contract`, `ai-eval-budget`,
`license-inventory`, `observability-contract`, `incident-postmortem` each weight 2,
advisory. Structured JSON rejects empty nested fields and wrong types. AI requires
injection/refusal/quality-pl/extraction cases and numeric token/retry/fallback limits.
Privacy includes flows, retention/deletion, subprocessors, fixture policy and owner;
licenses include versioned components, SPDX/NOTICE and assets. Observability has
signals, thresholds/runbooks and owner; postmortems have timeline, impact, causes
and actions with owners/deadlines. Templates are corresponding `.json.tpl` files.
These are reviewed plans, not evidence that evals, deletion, license verification,
alerts or incident drills ran. Remaining TOP items are prioritized in BACKLOG.md.

VERIFIED (`bin/helix_platform.py`, `tests/fixtures/commerce-platform-xl.json`):
XL or `--platform` adds a schema-checked platform program to the hash/approval
manifest. Portfolio: merchant admin, consumer app, POS, payments, fulfillment,
billing, partner/app ecosystem, analytics, internal tools. Capabilities resolve to
products and contexts; contexts resolve to teams with matching ownership boundaries.
API/data owners, streams, handoff/conflict locks, modular monolith ADR, extraction
metric/threshold, public APIs, extension isolation, tenancy/sharding, cross-product
identity and versioned shared design system are mandatory. Milestones form a DAG,
each with owner, team, acceptance and approved contracts matching dependencies.
Draft init never fabricates approval; full `new check` still requires all other gates.

VERIFIED (`bin/helix`, `bin/helix_platform.py`): new configs opt into design decisions
before implementation. Two distinct alternatives, benefits/trade-offs, selected ID,
approved status, approver and timezone-aware timestamp are required. Existing configs
opt in via `design_decision.required: true`. Implementer report explanations are
validated before visual/review gates; evidence summary retains the explanation.
HANDOFF explanations require at least eight words and no placeholders. This lexical
check does not judge explanation quality or authenticate approval. Brownfield maps
contain bounded static import hints; unresolved links are labeled ASSUMPTION.
