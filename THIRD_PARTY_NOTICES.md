# Third-party notices

## Cloudflare security-audit-skill

Helix vendors source review instructions, schemas and validators from
https://github.com/cloudflare/security-audit-skill at commit `c1c8a8c`.

Copyright (c) 2025-2026 Cloudflare, Inc. Licensed under the MIT License.
The full license is preserved at [vendor/security-audit-skill/LICENSE](vendor/security-audit-skill/LICENSE).
Provenance is recorded in [VENDORED.md](vendor/security-audit-skill/VENDORED.md).

This attribution covers the vendored component only. Helix's own license is TBD during private beta.

## Keycloak 26.8.1

The runtime adapter uses Keycloak as an external process in the local image
`quay.io/keycloak/keycloak:26.8.1`. Helix does not vendor the server or download
the image automatically. The upstream server is licensed under Apache-2.0:
[LICENSE.txt at tag 26.8.1](https://github.com/keycloak/keycloak/blob/26.8.1/LICENSE.txt).

The adapter records the inspected local image ID, available repository digests
and actual server version. This notice describes the upstream server license;
it does not establish the licenses of every component in the container image.

## Ponytail 4.9.0

Helix preserves the unmodified `ponytail-review`, `ponytail-audit` and
`ponytail-debt` instruction texts from a local plugin cache declaring version
4.9.0. The upstream project is
[DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail).

Copyright (c) 2026 DietrichGebert. These vendored texts are licensed under
the MIT License; the complete license is preserved at
[vendor/ponytail/4.9.0/LICENSE](vendor/ponytail/4.9.0/LICENSE).
Original relative paths, exact file hashes and the import date are recorded in
[VENDORED.json](vendor/ponytail/4.9.0/VENDORED.json).

The local cache was compared byte for byte. Its upstream commit is unknown,
and no remote tag or commit was verified. Only the three instruction texts
and license are vendored, without plugin code, hooks or the main skill.
This notice applies to that component only and does not change Helix's license.

## Optional managed tools

Helix installs the following exact main packages only with explicit
`helix tools install --yes`. They remain external processes in
`~/.local/share/helix/tools`; their implementation is not vendored here.
The upstream license sources below were read on 2026-10-25.

| Tool | Main package pin | Upstream license and source |
| --- | --- | --- |
| ast-grep | `@ast-grep/cli@0.51.0` (npm) | [MIT at 0.51.0](https://github.com/ast-grep/ast-grep/blob/0.51.0/LICENSE) |
| Knip | `knip@6.43.0` (npm) | [ISC at knip@6.43.0](https://github.com/webpro-nl/knip/blob/knip%406.43.0/LICENSE) |
| jscpd | `jscpd==5.4.2` (PyPI wheel) | [MIT at v5.4.2](https://github.com/kucherenko/jscpd/blob/v5.4.2/LICENSE) |
| Squawk | `squawk-cli==2.70.0` (PyPI wheel) | [Apache-2.0 OR MIT declaration at v2.70.0](https://github.com/sbdchd/squawk/blob/v2.70.0/Cargo.toml), [MIT text](https://github.com/sbdchd/squawk/blob/v2.70.0/LICENSE-MIT) |
| mutmut | `mutmut==3.8.0` (PyPI wheel) | [BSD-3-Clause at 3.8.0](https://github.com/boxed/mutmut/blob/3.8.0/LICENSE) |

The earlier registry label GPL-3.0 for Squawk was incorrect for this pin.
These declarations cover the named main packages, not a completed audit of
all transitive dependencies. Installation receipts retain resolved versions,
package integrity and file hashes; successful installation is not evidence
that a Helix adapter has scanned a client project. Package licenses remain in
the isolated installed distributions. Stryker and its test runner are outside
this installer and require a separate pinned setup in a disposable project copy.

## CI tools and external license boundary

Helix CI pins `zizmor==1.15.0` and `semgrep==1.181.0` as separately installed
processes. Zizmor declares [MIT](https://github.com/zizmorcore/zizmor#license)
(upstream declaration checked 2026-10-26). Semgrep's open-source CLI declares
[LGPL-2.1](https://github.com/semgrep/semgrep/blob/develop/COPYRIGHT); rule packs and proprietary
engines have separate terms. Neither implementation is copied into Helix.

The managed-package table above is the installer scope; it is not a license
inventory for every optional scanner. The broader registry and license notes
are in [TOOLS](docs/rethink/TOOLS.md). GPL/LGPL/AGPL programs, where selected,
remain external tools or local container images, not vendored source. Container
presets do not download or redistribute images. Their image dependencies and
transitive package licenses require separate review. The vendored Ponytail and
Cloudflare components retain their MIT notices.

## Vercel Web Interface Guidelines

Helix preserves the unmodified `command.md` of
[vercel-labs/web-interface-guidelines](https://github.com/vercel-labs/web-interface-guidelines)
at the last commit touching that file (`4ecfb9fb8d1d3b7009674869b3aaee2f904042e1`).
Its "Rules" section is reproduced verbatim inside `prompts/review_ui.md`.

Copyright (c) 2025 Vercel Labs. Licensed under the MIT License; the complete
license is preserved at
[vendor/web-interface-guidelines/4ecfb9f/LICENSE](vendor/web-interface-guidelines/4ecfb9f/LICENSE).
Exact file hashes and the import date are recorded in
[VENDORED.json](vendor/web-interface-guidelines/4ecfb9f/VENDORED.json).
