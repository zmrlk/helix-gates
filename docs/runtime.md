# Helix runtime / aplikacja na danych syntetycznych

Plan is an offline hypothesis (ASSUMPTION), never evidence of production behavior.
Only completed checks are VERIFIED for the synthetic copy. An unavailable tool,
unsupported command, external identity/payment requirement, or expired time budget
produces BLOCKED with a log. Smoke E2E is not a claim about full business workflows;
axe is automated WCAG coverage and Lighthouse is lab data, not field CWV p75.

Discovery walks arbitrary project layouts, excluding dependencies, build outputs,
private agent directories, credential files, real `.env` files and symbolic links.
It recognizes SvelteKit/Svelte, Next/React, Nuxt/Vue, Angular, Remix, Astro,
Express/Fastify/Nest and basic Django/FastAPI declarations. Package scripts are used
as declared; missing production start scripts can require a project-specific script.
Python dependencies are installed into a temporary virtual environment.

SQL migrations are applied in natural filename order, each in a transaction.
Unavailable required extensions block the migrator in the catalog preflight. Other
SQL failures are recorded as FAIL in schema-apply while later SQL files continue;
no production completeness is claimed.
Apps include local and shared repository database sources (an offline association
hypothesis); another detected app’s private migrations are excluded. A creating initial migration takes precedence over baseline SQL. Incremental
chains use schema/ (preferred over schema.sql), followed by later numbered migrations;
an unversioned baseline is followed by all detected migrations. Prisma, Drizzle, Knex, Alembic and Django use local migration
commands; unsupported tooling is BLOCKED rather than fabricated success.
Only small SQL seeds containing literal INSERT VALUES and passing conservative
email/phone/PESEL/NIP/dump heuristics are used. Script seeds and suspicious SQL
are rejected; this heuristic is not a proof of provenance.
Generated synthetic inserts use defaults or synthetic scalar values, and reuse only
foreign-key values already in this disposable database. Unsupported required columns can
leave a table empty. Restore compares exact row counts for every user table.
Backup runs whenever the disposable database exists, even if install/build/start/health fails.
Counts do not establish content equality, encryption, retention or production RPO/RTO.

Environment names come from example/sample files and source references, never real
`.env` values. Database URLs always point at the ephemeral localhost database,
secrets are random, URLs are loopback and other variables are synthetic strings.
Classification is advisory: cloud, SMTP, payment, telemetry and identity variables
receive dummy values and loopback endpoints on port 1. Only an observed execution
or health failure blocks an app; startup log excerpts explain failures such as
OIDC discovery connection errors. Public routes (including local login pages) can
be checked; external authentication and protected flows remain explicitly uncovered.
Package manager HOME is fresh and caller credentials are not inherited.
Playwright restricts browser requests, but that alone does not restrict the app or
database server. Project commands now require the process admission described below.
Dummy URLs, a ready database and an installed sandbox executable are not proof of
enforced isolation.

Only the disposable copy may receive dependency installations (including browser
harness dependencies). No system installation, production connection or deployment.
`--keep` deliberately retains processes, database and temporary files for diagnosis;
remove them manually afterwards. Default cleanup stops process groups and PostgreSQL,
removes containers and the copy, including on exceptions and SIGINT/SIGTERM.
SIGKILL cannot be handled by any process; use ephemeral CI workers for that case.

Budgets default to LCP 2500 ms, CLS 0.1, TBT 200 ms, performance 0.8,
HTTP p95 500 ms and error rate below 0.01. S/M/L/XL scale k6 users and duration.
Override with `helix.json`: `runtime.budgets` (`lcp_ms`, `cls`, `tbt_ms`,
`performance`, `p95_ms`, `error_rate`, `vus`, `duration`). A `slo.yaml`, `slo.yml`
or `contracts/slo.yaml` may supply `p95_ms` and `error_rate` directly or in `slo`.
Global `--budget-min` and bounded per-command deadlines constrain execution.

Run unit tests with `python3 -m unittest discover -s tests` (fake executor, no runtime).
Run real fixtures explicitly outside the restricted sandbox:
`sh scripts/run_runtime_it.sh` (`HELIX_RUNTIME_IT=1`). The integration directory has
no package initializer, so default unittest discovery does not load it or count skips.
Existing UX/consistency browser classes also require explicit `HELIX_BROWSER_IT=1`;
unit discovery does not probe local sockets or launch browsers.

Raporty tekstowe ograniczają listy dowodów do liczby i 5 przykładów; komplet jest
w artefakcie JSON. Wynik audytu nie dowodzi zachowania produkcji.

Schema application excludes archive/archived/old/legacy/deprecated/backup/_unused/examples.
Natural SQL order and per-file transactions isolate failures; failed files get one retry.
Seed-named DDL remains part of the chain. Database readiness requires pg_isready and
SELECT 1. Partial schema application does not prevent startup. Importing a failed
schema-apply lowers the data audit score independently of backup fidelity.


0.5.4-beta: schema plans include migrations, baseline+migrations and snapshot candidates,
conventions, duplicate table creators and repository script references. Ambiguous SQL
chains are tried in separate disposable databases (90 seconds shared trial budget).
The minimum error count wins; ties favor more successful files. The choice remains
ASSUMPTION. JSON retains every trial count; schema-apply summarizes five error categories.
An already-exists error signals a Helix selection problem; missing objects without
duplicate creators suggest a project dependency problem. dbmate applies only migrate:up;
golang-migrate excludes down files. Flyway versions precede repeatable migrations.
Flyway undo scripts (`U<version>__*.sql`) alongside versioned migrations are excluded.
HTTP responses of any status mean the app is up; HTTP 5xx fails E2E with the first
startup error. Connection refusal and timeout remain distinct health states.
Health evidence is reset for each application part, including parts blocked before startup.
Issuer variables enable a loopback HTTPS synthetic OIDC provider when openssl exists.
It supports discovery, JWKS, authorization code, signed RS256 ID tokens and userinfo.
Trust is scoped through NODE_EXTRA_CA_CERTS, SSL_CERT_FILE and REQUESTS_CA_BUNDLE;
TLS verification stays enabled. This does not verify production identity policies.
The stub process and temporary certificate are removed in cleanup. Start/build commands,
observed URL and health are retained in JSON. Backup PASS means existing table counts
survive dump/restore; failed schema application remains separately FAIL and lowers the
data audit score. No tables or differing counts fail backup with a specific reason.

Use `--no-oidc-stub` to test behavior without synthetic identity. Browser access to the
stub is restricted to its exact origin; Chromium trusts only its generated SPKI pin.

### Runtime 0.6.2-beta

Project migration scripts (`migrate*.sh`, Make migration targets, package scripts)
are tried before SQL strategies in fresh temporary databases, with DATABASE_URL
and PG variables scoped to each database. Tool conventions also provide runners.
Migration README references are retained as evidence. Each candidate reports
applied/failed operation counts and error categories; a runner counts as one
operation, since its internal file ledger is owned by the project. A complete,
successful project runner wins; otherwise selection minimizes failures. The
selected plan and alternatives are distinct in JSON. Commands have timeouts and
logs, and run only in a disposable copy with synthetic environment values.
Earlier reports explicitly lacked OS network isolation. Current runs require a
separate process admission before project execution; local database configuration
alone still grants no network safety credit. Historical observations remain
historical and are not upgraded by the current engine.

Issuer discovery covers SvelteKit static/dynamic private imports, JS/Python env
access, environment examples and YAML/TOML declarations. Matching issuer/auth
names receive the HTTPS stub URL; reports list substituted variable names.
Authentication bypass flags are informational and are never set by Helix.

VERIFIED: The previous `needs-oidc` fixture's accessibility failure was
`document-title` and `html-has-lang`, while Lighthouse rejected its `text/plain`
response as non-HTML (local round-five fixture report and logs, reviewed in round
six). Those are fixture content defects, independent of OIDC. Reports now show
individual axe IDs and Lighthouse runtime error messages. An HTTP 5xx response
is FAIL for browser and Lighthouse checks with the exact status code, rather
than a missing-service BLOCKED. Infrastructure errors remain BLOCKED with their
first diagnostic; performance failures name the metric and budget.

Offline regression coverage includes `project-runner` (a shell psql loop) and
`oidc-dynamic-private` (a SvelteKit dynamic private issuer declaration). The
integration runner includes both fixtures; running integration requires existing
database/browser tools and dependencies. No installation is required by the
offline regression suite.

### Database fidelity (0.6.3-beta)

Runtime scans safe repository files for database image pins, Terraform engine versions,
Supabase major_version, tool version files, CI services, Helm configuration and runbooks.
Prisma/Flyway providers identify the engine; MERGE and NULLS NOT DISTINCT provide
a weaker PostgreSQL 15 minimum. Conflicting explicit pins block execution for resolution.
Absent exact pins are ASSUMPTIONs (default PostgreSQL 16, raised by syntax minima).
Non-PostgreSQL engines are detected but currently BLOCKED rather than emulated.

Containers prefer the target major (postgres, pgvector or PostGIS). Native selection
checks postgres --version in versioned Linux, Homebrew and Postgres.app locations
and PATH; a mismatched native backend is BLOCKED unless explicitly permitted with
--allow-version-mismatch. No installation or daemon startup is performed automatically.
SHOW server_version records the actual connected server before migration or application
startup, for containers, native PostgreSQL and the explicit CI service backend.
A different major blocks that backend unless --allow-version-mismatch was supplied;
an unknown or malformed version blocks even with the flag. Each fallback measures
its own server and cleans up the rejected owned backend. The explicit flag permits
measured results for a known mismatched version while retaining WARN and DEGRADED
for schema-apply, backup and load, excluding audit credit. Failed/skipped checks retain
their diagnostic meaning. Backend fallback always carries WARN.

The top of runtime.md and database_fidelity in JSON include backend, image/binary,
actual version, target, compatibility and evidence (five examples in Markdown,
all file/line references in JSON). These are repository observations, not proof
of production deployment. A blocked backend includes OS-specific recovery commands.

### Process network admission

Runtime places dependency installation, migrations and their retries, seeds, build,
application starts and browser/Lighthouse/k6 measurements behind one process boundary.
The initial backend uses macOS Seatbelt through the system `sandbox-exec`; finding
that executable is only a capability observation. A bounded neutral local probe must
confirm the tested network and write restrictions, including inheritance by an exec
child, before a production process receives a grant. An unsupported host, denied
probe or expired budget gives BLOCKED before project code starts. There is no
unprotected native fallback or project-configurable exception.

The policy permits only Helix-owned loopback TCP ports and any explicitly required
owned Unix socket. It does not expose host Docker, Podman or SSH-agent sockets.
Writes are limited to the disposable project and its scratch space; protected control
files remain outside writable roots. One exception applies to the browser measurement
scope only: processes there may create the browser's default profile directories in the
account's `Library/Application Support` (`Google`, `Google/Chrome`,
`Google/Chrome for Testing`, `Chromium`), directories only and nothing inside them.
Chrome creates them on start even with `--user-data-dir` and aborts without them, so on
an account that never ran the browser a measurement leaves these empty directories behind. Children receive no inherited socket or directory
descriptors. Each grant is tied to its generated policy; changing a port or retrying
requires admission for the current policy.

PostgreSQL needs its own server grant: restricting `psql` does not restrict SQL
executed by another process. The initial backend supports an owned native server
started under its own policy. An existing service or a daemon-created container is
blocked without independent server isolation, even if its client is wrapped. Database
major-version and extension checks remain separate prerequisites after admission.

Installation is also restricted. A missing local dependency may block npm or pip;
Helix does not permit external traffic merely because a package-manager script needs
it. Preparing an offline dependency cache is a separate operation. Outgoing-integration
sinks and evidence that an application actually used them are separate from this
process boundary.

`network_isolation` records the backend, scope, policy hash, admission reason and
attempted phases. Synthetic executor grants remain `synthetic_test`, never OS
execution proof or a complete runtime PASS. Older reports without the field retain
unknown isolation; a current run without an admission attempt is NOT_RUN. A local probe proves only
its recorded checks, not application execution, production isolation or an Internet
connectivity test. Linux and container-network backends remain unsupported here.

### PostgreSQL extension preflight

Runtime reads literal extension declarations from the selected SQL migration scope,
retaining file and line references. Comments, quoted text, function bodies and down
migrations do not create requirements. Ordinary extensions such as `pg_trgm`,
`btree_gist`, `fuzzystrmatch` and `pgcrypto` do not select a special image. Existing
pgvector and PostGIS image selection remains separate from actual availability.

Before migrations, each owned base or trial database is checked through a constant
`pg_available_extensions` query. The fresh restore database is checked before
`pg_restore` as well. Missing required extensions block that operation before the
migrator runs. A failed query, timeout or malformed result is an incomplete check,
not a successful empty catalog. Availability from one trial is not transferred to
another database.

`database_fidelity.extension_checks` records each scope, requirements, declarations,
available/default/installed versions, missing entries and the query log. The record
is persisted before migrations, including failures. Catalog availability does not
prove installation, activation permissions, a declared `VERSION`, successful
migrations or application behavior. Helix does not install packages or run
`CREATE EXTENSION` on behalf of this preflight; explicit migrations retain control
over activation. Dynamic project runners without literal requirements retain an
unresolved scope. Owner reports keep these limits visible and award no points for
catalog readiness.

### Fresh database runners and startup diagnostics (0.7.2-beta)

Offline planning detects fresh/bootstrap switches in the runner and adjacent
README, retaining file/line evidence. Runtime trials use a separate disposable
database for each candidate in order: normal runner, detected fresh variants,
migrations-only, baseline+migrations, snapshot. The first complete successful
candidate wins; if all fail, selection prefers fewer failures and more applied
files. JSON and Markdown retain each trial's command template (database URL
redacted), applied/failed counts, duration, first error and category.

Dummy environment values follow name/type heuristics and safe numeric, boolean
or loopback defaults from `.env.example`/`.env.sample`. Adapter controls and
`NODE_ENV` are omitted unless the project supplies a safe value; `PORT` is always
the assigned runtime port. Bootstrap variables are scoped to their runner trial.
Startup reports retain CRASHED, exit code, error category and first diagnostic;
application checks stay BLOCKED by that cause. An environment type error can
trigger one corrected restart, with a separate log and record for both attempts.

The offline release gate is `python3 scripts/check_release_version.py` and runs
before `scripts/run_tests_parallel.py` starts tests. It validates VERSION against
unique changelog headings and locally available `origin/master` release subjects;
it never fetches. Missing history fails explicitly. `--since TRUSTED_BASE` defines
the current commit range excluded from the reuse check (default: HEAD only).

Release guard (offline): `python3 scripts/check_release_version.py --pre-push`
compares VERSION and CHANGELOG with the locally recorded `origin/master` and
rejects a reused release. Missing history fails closed. Refresh that reference
before publishing; the check does not fetch and cannot prevent a concurrent push.
The `.githooks/pre-push` template is provided without installation or permission
changes. To enable it yourself, make the template executable and run
`git config core.hooksPath .githooks` (this changes your local Git configuration).

Runtime schema trials record every candidate's status, applied/failed counts and
first error. If no runner succeeds, selection falls back to Helix SQL strategies,
even when a failed runner has fewer errors. A failed fallback remains a failure.
Chromium trusts only SPKI keys generated for this run, including the HTTPS
front and local IdP, via launch args (Playwright) and `--chrome-flags`
(Lighthouse). See the [local HTTPS contract](runtime-integrations.md#lokalny-https-i-cookies).
Browser coverage records observed authorization code requests and successful
returns to the application; real users and provider policies remain outside scope.

### Execution ledger and HTTP diagnostics

`parts[].database.variants` retains every migration trial in order, including
refused runners and forbidden adoption modes (SKIPPED). Each item includes
command/env (credential variables redacted), suggestion location, PASS/FAIL/REFUSED/
SKIPPED, applied/failed counts, first SQL error location, logs and elapsed seconds.
`selected` and `selection_reason` explain the chosen strategy. runtime.md shows
at most ten ledger rows and points to the full JSON.

An executed, documented fresh runner failure with a SQL location creates
`fresh-install-broken` (high, data/ops, owner=project, VERIFIED within the synthetic
run). Import with `helix new audit --runtime-report PATH` preserves the finding
in audit.json and audit.md. It does not establish production behavior.

Browser response records contain method, URL without query/fragment, status and
source app/stub. Lighthouse uses its network audit. Stub logs omit query strings.
k6 uses only routes successfully reached at their original path by e2e, without
following redirects; other routes are listed in excluded_routes. Per URL/status
counters and request measurements are in logs/load-requests.jsonl; status_by_url
is the report summary. Redirect responses are measured as redirects, not as
proof that an authenticated page was served to k6. No e2e routes means BLOCKED.

Historical logs without response URLs cannot prove the origin of a 404 or the
terminal redirect of a failed load request; report those as ASSUMPTION rather
than attributing them to a missing table. An app 500 plus an executed missing-
relation diagnostic is reported as a partial schema failure with its start log.
The repository hook is executable; enable it explicitly using the existing
instructions. A missing version checker asks for `rebase na origin/master`.
The optional release controller is called with `check` only if advertised by
its help output; the runtime stream does not create or modify that controller.
