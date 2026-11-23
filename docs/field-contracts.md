# Field-work contracts (0.4.0-beta)

Owner: Helix maintainers. Reviewed: 2026-10-25.

These checks consume local JSON and retained artifacts. They never invoke git,
tests, providers or a network. A host must actually run the tests; a declared
successful run is an attestation, not an independently reproduced execution.
Do not place credentials in reports. Paths for evidence are confined to the
project. Start with `templates/helix-contracts.json` and retain every section explicitly.
Decisions, runs, registry, domain, documentation, budget and owner report must be
populated; controls with no applicable records retain an explicit empty list.
A version-only input fails. Project commands reject a missing or incompatible pin
before executing work.

```
helix --repo . contracts --input helix-contracts.json --out evidence/contracts.json
helix --repo . contracts --profile configurable-product --out evidence/product.json
helix --repo . merge-audit --out evidence/merge.json
helix --repo . owner-report --out docs/owner-current.md
```

Exit 0 = contracts passed, 2 = failed. Warnings remain advisory. Reports stamp
`helix_version`; set the same `helix_version` in the project's `helix.json` and
contract. Comparisons record `before_version` and `after_version`; differing
versions fail. Update the pin deliberately before rerunning both sides.

Contract fields (include every section and every applicable record):

- `decisions`: positive unique `number`, `executors`, `acknowledged`, enforcing
  `test`, and `run`. Every executor acknowledges every applicable decision.
- `merge`: complete `conflicts` inventory (exported by the host from its conflict
  review), `resolutions`: `conflict`, `reviewer`, `choice` (manual/ours/theirs),
  `reason`. UI conflicts additionally require `before`, `after` images. Common UI paths
  and extensions trigger this check even without `ui: true`.
  The validator checks inventory coverage, not completeness against git history.
- `runs`: host responses. Each has `status: passed`, integer `exit: 0`, `who`,
  `where`, `sha`, `command`, nonempty `log` file and `tree` file (DOM or accessibility
  error-context). Unexecuted/failed responses earn zero. Host retains logs and
  returns this JSON and files to the executor; executor fixes and requests another
  host run with the new revision. Never reuse an old revision as current evidence.
- `rule_changes`: registry `id`, `reason`, `bad_case`, passing `self_test` run.
  Record every threshold/rule modification, including measurement corrections.
- `budget`: `rules` with `id`, `component`, measured `seconds`, `limit`;
  `components` maps component to seconds limit. Exceeding either warns. `shards`
  is a positive batch count. `fast: true` selects only `affected` components;
  use a full run for final acceptance. Returned `batches` are a host work plan.
- `registry`: reserve `id`, `type`, `prefix`, `reserved_by` before use. IDs are
  globally unique; a prefix belongs to one type. Merge reservations centrally.
- `domain`: dictionaries `mechanisms`, `patterns`, `components`, `industries`.
  Each nonterminal ID maps to a nonempty array of IDs from the next dictionary.
  Links support many-to-many relationships; dangling references fail.
- `product`: `axes` includes theme, radius, shape, density (additional axes work).
  `cases` contains each Cartesian configuration as `config`, a passing `run`,
  and `contrast_passed: true`. This initial profile uses exhaustive coverage.
- `catalog`: allowed component IDs. `modules` records `components` and `gates`
  with passing runs for contract, tests, permissions, appearance. Apply this
  identical contract to manual and AI modules. A component inventory is an
  attestation; source-level import verification belongs to the project gate.
- `owner_report`: `state`, single file `current`, `screenshots`, `gates`, pending
  `decisions`, `obsolete` paths. Always regenerate the same output file; the
  obsolete list is explicitly marked “do not open”.
- `documentation`: `path`, `owner`, ISO `reviewed` date, `code` paths. Future
  dates fail; code mtime newer than the review date warns (UTC). This is the
  field contract. The Pro documentation area additionally validates every Markdown/API/data-model/schema
  file through `docs-metadata.json`, checks per-document code mtimes and emits
  stale warnings; see `new/templates/docs-metadata.json.tpl`.

The Pro offline score awards no points to declared, unexecuted custom gates;
preparation remains separately visible. Existing source-based maturity checks
remain offline evidence, and are not claims of test execution.
