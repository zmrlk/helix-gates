# Helix lessons

## Behaviour-preservation and dependencies

Behaviour-preservation blocks every dependency change: additions, removals,
version updates and changes to manifests or lockfiles, including development and
test dependencies. A passing suite alone does not authorize such a change.

To allow one deliberately, obtain the owner's explicit authorization, record the
specific dependencies, versions, purpose and expected behaviour impact in the
checkpoint goal and truth evidence, and add the exact manifest and lockfile paths
to `behaviour.diff_allowlist` in `truth.json`. Adjust any project-specific dependency
policy explicitly; the allowlist does not override that policy. Keep the exception
limited to the approved change and verify the full suite before and after.

## Filesystem identity and skipped coverage

Resolve both sides before comparing filesystem paths or computing relative paths.
A repository reached through `/var` and `/private/var` on macOS has one identity.
Use `bin/helix_paths.py` in Python and `bin/paths.cjs` in Node. Preserve the lexical
name only when recording a skipped symlink itself, so an external or broken link
still has an entry in the coverage ledger. Do not silently follow external links.

## Test discovery

Use `node --test` for Node autodiscovery, or list test files explicitly. Do not use
a directory operand: Node 22 may interpret it as a file. Zero discovered tests is
an error even if the runner exits successfully. Truth checks also reject saved
zero-test suites and nonzero suite exits.

## Generated commits

The first line of a commit message is limited to 120 characters, including the
`helix(cpN): ` prefix. Helix validates this before staging files; shorten the
checkpoint title if it would exceed the limit. Newlines in titles are rejected.

## Keyboard audit (24.10.2026)

A focus indicator counts when it appears on the element, on its `::before` or
`::after`, or on one of two ancestors (`:focus-within`). WCAG 2.4.7 accepts all of
them, and design systems often draw the ring on a wrapper or pseudo-element.
Comparing only the element's own style gave false `kbd:focus-visible` failures.

WebKit on macOS follows the Safari default: plain Tab skips links and buttons.
The audit presses Option+Tab there, otherwise every page reports
`kbd:unreachable` and a false keyboard trap.

## Closed `<details>` in the UX audit (25.10.2026)

Content of a closed `<details>` (everything outside its `<summary>`) is not on
screen, but CSS such as `::details-content` animations can keep its boxes laid
out. Hit-testing those boxes gave false `fixed-covers` alarms ("bar covers a
link") on phones. Layout rules use one shared `isEffectivelyHidden()` that skips
`details:not([open])` content; the `<summary>` is still audited.
