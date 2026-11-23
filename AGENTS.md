# For Codex / other agents
For non-trivial changes in a repo that has `helix.json`, follow `SKILL.md` (helix-gates, DRAFT).
In short: `helix plan`, then `helix run cpN` per checkpoint; never commit or skip gates yourself.
Before any fix/PR or report of findings: gate G0 (`helix truth init|suite|check cpN`, `helix gate truth cpN`). Names in code are not proof of what runs in prod; label every claim VERIFIED (evidence) or ASSUMPTION.

Fast development gate for Helix itself: `python3 scripts/run_tests_parallel.py` (class fixtures stay in one worker); `HELIX_TEST_TIMES=1 HELIX_TEST_BATCH=1` prints timings. Run `helix new audit` as well.

## Ledger wymagań

`helix requirements check [--run] [--json]`, `requirements add` i
`requirements report`: [kontrakt i przykłady](docs/requirements-ledger.md).
Każda nowa wypowiedź właściciela → REQ z cytatem i źródłem w tym samym commicie.
Wrapper/CI: `helix requirements check --require-ledger-touch --since REF`
(zaufany ref sprzed zmian); wykrywa docs/owner-statements i trailer Owner-Statement.
Pending MUST są jawnym długiem; mapowanie testu nie oznacza jego wykonania.
Nie zatwierdzaj samodzielnie waiverów ani zmiany baseline.

## Ciągłość agentów

`helix agents generate`, `helix agents check`, `handoff write|read|check`, `claim take|release|list|check`,
`decisions add|list|check`, `continuity report [--json]` utrzymują stan w repo.
Polityka i pin: `.helix/agent-policy.json|yaml`; [instrukcja](docs/continuity.md).
Stary `handoff --run-id` nadal generuje raport przebiegu. Bez force push.

## Plany, modele i ogólność

Przed dużym skanem czytaj plan ról oraz `security deep --plan`. Pierwszy full
zaplanuj na noc, później daily, przed wydaniem release; ogranicz jobs i budżet,
respektuj presję zasobów. `status --reminder-only` tylko przypomina.
Autor i weryfikator muszą należeć do niezależnych rodzin. Zachowaj jawne modele;
brak dostępności lub zgody `data_egress` nie uprawnia do podmiany ani wysyłki.
Transport źródeł pozostaje wstrzymany według [polityki](docs/data-egress.md).
Ponytail i narzędzia advisory nie zaliczają bramek jakości.

Wspólne reguły muszą działać poza jednym projektem. Guardy, syntetyczne dane,
integracje i trasy bierz z kodu lub jawnej konfiguracji, bez wyjątków nazw klientów.
[SKILL.md](SKILL.md), [runtime](docs/runtime-adapters.md) i
[dowody projektu](docs/project-evidence.md) określają granice wykonania.
Niewykonane testy/CI to przygotowanie; zużycie modelu bez telemetryki to null.

Jawny tryb oszczędny zlecony przez właściciela określa zakres wykonania w danym
zadaniu. Pominięta pełna bramka lub niezależny checker pozostają NOT_RUN/niezaliczone;
nie twórz PASS, waivera ani zgody w ich zastępstwie. Commit przekazuj wskazanemu
wrapperowi, jeśli właściciel wybrał taki tryb.
