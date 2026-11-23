# Documentation pack (split into named files)
ASSUMPTION: TODO supply project-specific content and owner review.
- README.md: install/setup, run, quickstart and working examples.
- architecture.md: components/dependencies and mermaid diagram with --> edges.
- adr/ADR-001.md: context, alternatives, decision, consequences.
- openapi.yaml: openapi version, paths, operations, errors, auth and examples.
- data-model.md: entities/tables, relations, migrations and ownership.
- runbook.md: alert/incident, on-call owner, recover/rollback and escalation.
- CONTRIBUTING.md: setup, test, review/pull request workflow.
- CHANGELOG.md: version, date, Added/Changed/Fixed release notes.
- user-guide.md and admin-guide.md: tasks/usage, troubleshooting/support.
Update docs with code; mtime is an offline heuristic, not semantic proof.
External documents must be explicitly declared in docs_paths.

Copy docs-metadata.json.tpl beside the documents. For every Markdown file, fill
path, owner, reviewed (YYYY-MM-DD, not future), and code (explicit described-code
paths, empty list only for non-code documents). Paths are relative to the metadata
file. External docs_paths must include the metadata too. Review/update each doc
with its own code; stale pair warnings cannot be cleared by an unrelated document.
