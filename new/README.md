# Helix New contracts (v1)

Offline preparation for greenfield and brownfield, scale S/M/L/XL and independent
risk low/high/regulated. PASS means preparation completeness, not runtime,
security, legal compliance or production readiness. Human acceptance remains
required; the validator cannot authenticate an approver's identity.

```
python3 bin/helix new init --mode greenfield --profile S --risk low --dir ./app --out ../app-helix-new
python3 bin/helix new init --mode brownfield --profile XL --risk regulated --dir ./large-app --out ../large-app-helix-new
python3 bin/helix new audit --repo ./existing --out ./audit-output
python3 bin/helix new brand check --dir ../app-helix-new/proposed
python3 bin/helix new check --dir ../app-helix-new/proposed
python3 bin/helix new handoff --dir ../app-helix-new/proposed
```

Init leaves the target untouched by default and creates external drafts that
deliberately FAIL check. Only explicit `--write` creates new target files; it
refuses every existing destination, including helix.json. Fill
charter, measurable PRD, domain, ADR, data/threat models, program and budgets.
Use the mandatory project SKILL.md throughout delivery; it points to existing
Helix plan/run/truth/quality gates, board, escalation and closure evidence.
Helix New does not bypass those gates or execute target commands. Models run
only for explicitly requested neutral availability probes (`--refresh-providers`),
not source review.
Read-only Git identity and local tool-version probes are recorded separately;
`--no-probe` disables the latter.
The delivery program is separate from `.helix/plan.json`, which `helix plan`
creates per implementation task using the existing Helix workflow.

All shipped `.yaml` templates contain JSON (a YAML subset) so the default path
requires only Python's standard library. Existing Helix `load_yaml` handles
handwritten YAML if an existing parser is available. No parser installation is
attempted. Invalid syntax/unreadable files/unsafe paths/missing parser = ERROR 3;
missing artifacts, failed contract, incomplete acceptance or hash drift = FAIL 2;
PASS = 0. Findings never echo parser exceptions or source file contents.

## Project configuration proposal

`new init` and `new audit` write `helix.proposed.json`, `project-proposal.json`,
`provider-plan.json`, `environment.json`/`.md`, the security `deep-plan/`, and a
short Polish `NEW-REPORT.md` in disjoint external output. `init` also puts drafts
in `proposed/`. With no `--out`, init uses the target sibling `<name>-helix-new-init`.
The config pins the current Helix version, preserves explicit roles/models and
project settings, discovers UI roots such as `frontend/src`, and proposes the
declared database version. Local server binaries and production evidence remain
separate. An unverified or different local database version is a visible gap.

```sh
helix --repo /code/app --config /audits/app/helix.json --state-dir /audits/app/state --offline new audit --out /audits/app/preparation --no-probe
helix --repo /code/app --config /audits/app/preparation/helix.proposed.json --state-dir /audits/app/state providers --refresh
helix --repo /code/app --config /audits/app/preparation/helix.proposed.json --state-dir /audits/app/state --offline new audit --out /audits/app/preparation-checked --no-probe
```

For one online preparation step, opt into short availability probes:

```sh
helix --repo /code/app --config /audits/app/helix.json --state-dir /audits/app/state new audit --out /audits/app/preparation-online --refresh-providers --jobs 3
```

`new init` accepts the same flags. `--jobs` here limits simultaneous availability
probes, independently from the deep scan plan. The probes use the configured
model chains and a separate neutral temporary directory per call. They send only
a constant JSON ping, never project sources, AGENTS files or application data.
Explicit models, including an explicit default, remain unchanged. A single writer
saves every completed attempt in configuration order, including redacted failures.
The report distinguishes current availability probes from source reviews (none).
`--offline --refresh-providers` is rejected before any provider call or output.
Output collisions are checked before probing. `providers --refresh --jobs 3`
uses the same concurrency and isolation when invoked separately.

The proposal reads the dated real model probes from external state or an explicit
`--provider-cache FILE`. Missing/expired evidence gives LIMITED and an explicit
refresh instruction; no login is inferred from a binary or token. The role plan
requires a verifier from another family. Proposed roles are separate from actual
execution metadata. A missing data-egress policy creates an empty allowlist and
a pending owner question, never an approval to send source code.

For a large repository, schedule the first `security deep --mode full` overnight
with jobs 3, then `--mode daily`, then `--mode release` before shipping. The plan
records batches, calls, bytes and estimated time from measured throughput; a
missing measurement remains unknown. Full and daily have no implicit time cap;
release has 30 minutes. Daily/release require a matching COMPLETE receipt from
this repository or an explicit `--since REF`. Source reviews are currently blocked
even with approval until prepared-package transport is admitted; see
[data egress](../docs/data-egress.md). Accept the proposal deliberately before using its configuration;
writing a proposal does not accept the drafts, model egress, findings or waivers.

## Acceptance and hashes

`handoff-manifest.yaml` uses `schema_version: 1`, `mode`, `profile`, `risk`,
`status: approved`, `accepted_by`, `artifacts`, `claims`, `traceability`, `gaps`.
Each artifact entry has `path`, lowercase SHA-256 `sha256`, `status: approved`
and named `accepted_by`. Include every required artifact from the selected
profile plus compliance for high/regulated or L/XL, and audit/gap-plan for
brownfield. Additional artifacts are hashed and reviewed too. Absolute paths,
symlinks, escaping paths and duplicate entries are rejected. The manifest does
not hash itself. After reviewing a changed artifact, calculate its SHA-256
with Python `hashlib.sha256(Path(path).read_bytes()).hexdigest()`, update the
entry and obtain the owner's renewed acceptance; never accept a draft by merely
refreshing hashes.

Every claim has `tag: VERIFIED|ASSUMPTION` and `statement`. VERIFIED also needs
local `evidence: path:line`, checked for existence. Markdown artifacts must carry
claim labels. Runtime/production claims still need the independent G0 evidence
and owner context; local names do not establish what runs in production.
Traceability entries contain `requirement`, `adr`, `test`, `checkpoint`, `gate`.
Open gaps require `description`, `owner`, `deadline`; placeholders and missing
required artifacts cannot be waived by a gap entry. HANDOFF.md is under 400 words.

Schemas in `schemas/` are JSON Schema documents; the offline validator implements
the subset they use: type, enum, required, properties, items, minItems, minimum,
pattern. It also rejects empty strings, TODO/TBD/FIXME and angle-bracket placeholders.
Project content requires human review: formal completeness cannot prove intent.
`build_contracts.py` regenerates shipped schemas, profiles and draft templates.

## Source brand before design

`brand.yaml` requires approved status, named owner, `logo`, nonempty `colors` and
`fonts`. Each item has `value` and `source: {kind: url|file|owner, reference: ...}`.
File references must exist inside the project; URLs are checked syntactically,
never fetched. Owner references identify an explicit asset approval record.
No sample palette, fonts or logo are copied into drafts.

`design-contract.yaml` preserves the structure of
`templates/design-contract.example.yaml` (areas, chrome, tokens, components,
patterns, copy, tolerances, exceptions), with blank brand values and proposal
status. Its `tokens.colors` and `tokens.fonts` must equal the brand arrays.
DESIGN.md contains a fenced JSON object with exactly these two arrays; it must
match too. Missing source brand blocks design approval and handoff. Palette
frequency from an audit is observation, never owner approval.

## Scale and risk

L and XL require full accepted `adr/tenancy.yaml` (database/cache/files/queues/
analytics isolation and tests), `partitioning.yaml` (key, strategy, rebalance,
numeric threshold), `regions-dr.yaml` (residency, transfers, backup/deletion,
numeric RTO/RPO and recovery test), `capacity.yaml` (numeric RPS/concurrency/GB,
growth, peak factor and load plan), per-critical-path SLOs, cost per tenant and
compliance matrix. This validates plans; it does not execute load or DR tests.

S/M default to simple infrastructure. `architecture.yaml.advanced_features`
and affirmative architecture/PRD/program prose mentioning cells, multi-region,
sharding, microservices or Kafka require a matching `decisions` entry with
`feature`, `status: approved`, positive numeric `threshold`, `metric`, `adr`
(pointing to a hashed artifact), and `accepted_by`. Prose detection is a bounded
heuristic; list actual features explicitly and let humans review architecture.

High and regulated risk require `compliance.yaml` even at S. Its matrix covers
industry × country × data × role, applicability, source, FOUND status, retrieval
date, positive TTL, control, evidence and reviewer. These are reviewed inputs,
not a legal certification or an automated check of laws or source freshness.

## Read-only brownfield audit

Use disjoint target/output directories. Existing output may contain separate runtime/state artifacts, but audit and proposal destinations must not exist. Audit inventories
source languages, declared frameworks, manifests, tests, CI, migrations, Docker
and documents, plus hex/CSS-variable/font declarations in CSS, Tailwind and token
files. Observations cite path:line; gaps and reconstruction are ASSUMPTION.
Output contains `audit.json`, `gap-plan.md`, `reconstruction-proposal.md` and a
`proposed/` brownfield draft package. Review its defaults (S/low), choose the
actual profile/risk and reconstruct intent with owners before handoff.

The scan never executes or imports target code. It skips symlinks, credential
and memory/mail filenames, hidden agent state, dependencies/builds, unsupported binary extensions and excluded generated content; source reads are
not silently truncated by a size limit. Coverage is bounded and explicit, so an absent
observation is not proof of absence. Only constrained palette values and known
framework declarations are copied; arbitrary file contents are not reported.

## Helix Pro standard (0.4.0-beta)

`helix new audit --repo PATH --out EXTERNAL_DIR --profile M` writes `audit.json`
(with `maturity.areas`) and `audit.md`. Profiles default to S. Eight separate
areas: performance, security, backend/architecture, UX, UI, ops/reliability,
data, testing/CI. Versioned requirements, evidence selectors and weights are in
`profiles/pro-standard.json`. Each score is the rounded percentage of applicable
requirement weights with observed evidence. Top three missing requirements are
ordered by weight, then stable ID. Exceptions never earn points.

This is **offline evidence maturity**, not proof that tests ran or production
meets an SLO. Missing evidence is ASSUMPTION; observed evidence includes VERIFIED
path/line references. UX uses Helix UX configuration; UI uses the existing
brand check, design-contract and consistency configuration. These are marked
`needs runtime probe`; run the existing UX/consistency/brand gates separately.

`helix new check` additionally blocks M/L/XL when PostgreSQL service CI,
migrations/integration tests, Playwright config and E2E CI, or k6 CI/thresholds
linked to `slo.yaml` are missing. GitHub Actions and GitLab workflows are
recognized. A test compose file alone cannot prove CI service execution.
L/XL also require declarations of HA/replicas, backup/restore tests in CI,
structured logs/metrics/traces, shared rate limiting and distributed job locks.
The exact recognized paths and patterns are published in the standard JSON;
custom layouts should be reviewed and adapted rather than assumed compliant.

A temporary exception in project-root `pro-exceptions.json` has this shape:

```json
{"exceptions":[{"requirement":"postgres-ci","reason":"Tracked remediation with owner","approved_by":"Project owner","expires":"2026-11-30"}]}
```

Expiry is an inclusive ISO calendar date evaluated locally. Missing approval,
reason, invalid or expired dates do not waive requirements. Owner approval is
a recorded declaration, not authenticated by the offline tool. Review exceptions
with the handoff. The score and missing evidence remain visible.

Copy and adapt templates from `new/templates/ci/`: PostgreSQL integration,
Playwright smoke, load workflow and k6 baseline. Supply the project setup,
migration, integration and app-start scripts; configure Playwright `webServer`.
The example k6 script reads JSON-compatible YAML `slo.yaml` from three directories
above its location (`load_test.p95_ms` and `load_test.error_rate`); update the
relative path if moved. Provision k6 in the CI runner. No template is executed
by audit or init; no packages are installed by these commands.

## Pro maturity extension

See [PRO-STANDARD.md](../docs/PRO-STANDARD.md) for the versioned control matrix,
weighted offline/preparation scores, `needs-runtime`, design references and review.
`helix new plan --to pro --audit ./audit-output/audit.json --out ./improvement-plan.json`
generates a deterministic schema-compatible proposal, never executing checkpoints.
Re-run older audits before planning; output overwrite is refused. Adapt the shipped
remediation templates manually. An offline finding cannot establish runtime PASS.

## Platform program and design decisions (0.4.0-beta)

VERIFIED: XL and `init --platform` include `platform-program.json`; see
[Pro standard](../docs/PRO-STANDARD.md) for portfolio, ownership, DAG and
dependency contract validation. Templates intentionally remain unapproved.
New projects enable `design_decision.required`; adapt design-decision.json.tpl
into design-decisions/cpN.json before implementation. HANDOFF and checkpoint
reports require a populated What changed and why section. Brownfield audits
emit system-map.json with static components and unresolved dependency hints.

Transport preparation reuses the audit source snapshot. It detects Secure
cookies, Keycloak and WebAuthn declarations per app and proposes
`runtime.https.enabled: true` only when needed and not explicitly configured.
The external proposal preserves explicit false and host settings. NEW-REPORT
separates observed HTTP from proposed HTTPS, with file/line evidence and
unresolved options. No readiness, login or cookie test receives execution
credit. Init without a source snapshot reports NOT_RECORDED.

## Merged project evidence and discovery

`pro-evidence.json` maps custom gates to Pro requirements; tests and CI without
execution earn preparation only. `new ids reserve|list|check` uses one shared
absolute registry across worktrees. `new modules` validates AI and manual modules
against the same component catalog and all project gates; audit/check/handoff
include an existing `ai-modules.json`, while absence remains NOT_CONFIGURED.
See [examples and receipt requirements](../docs/project-evidence.md).

The source catalog includes .NET, JS/TS modules and Svelte/Vue/HTML/CSS. SDK/TFM
declarations do not prove execution or NuGet integration support. Runtime proposals
use the generic provider registry and project configuration; readiness and blind
2xx do not prove provider behavior. [Adapters](../docs/runtime-adapters.md) and
[nine-repository evidence](../docs/generality.md) retain incomplete coverage.
Ponytail debt and simplicity remain advisory, without execution credit.
