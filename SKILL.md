---
name: helix
description: Bramki jakości dla każdej nietrywialnej zmiany kodu i dla każdego raportu o repozytorium: G0 prawda i kontekst (ledger twierdzeń VERIFIED/ASSUMPTION, systemy potwierdzone przez właściciela), checkpointy, G1 testy zachowania, G2 porównanie wizualne, G3 dwie niezależne recenzje innej rodziny modelu, G4 człowiek. Użyj, gdy piszesz lub zmieniasz kod w repo z helix.json, gdy ktoś mówi „helix”, „bramki”, „przejdź przez G0–G4”, „zrecenzuj niezależnie”, albo zanim zgłosisz znaleziska o repo. Nie do stylu kodu ani pojedynczych edycji dokumentacji. Modelowane na Helixie Shopify Engineering. DRAFT beta.
metadata:
  version: "0.9.3-beta"
  split: "2026-11-02 rdzeń + references/"
---

# helix (DRAFT)

Rdzeń skilla: mieści się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu. **Po każdym kompaktowaniu w długiej sesji wczytaj ten plik ponownie** (`/helix`), bo tylko ten rdzeń wraca do kontekstu; pliki z `references/` wczytujesz na nowo, gdy dochodzisz do danego etapu.

Agent-agnostic. Codex: reference this file from the repo's `AGENTS.md`. Claude Code: copy the folder to `~/.claude/skills/helix-gates/`.
CLI: `helix` (Python 3.11+, requirements.txt; Playwright for the visual gate and UX pack; axe-core for a11y).

## Czytaj, gdy

| Plik | Czytaj, gdy |
|---|---|
| `references/srodowisko.md` | zaczynasz pracę w nowym repo albo maszynie: `helix doctor`, `helix update`, `helix env`, przegląd AST security deep |
| `references/providers.md` | konfigurujesz albo zmieniasz recenzentów, modele, łańcuchy fallback, ręczny handoff Groka, sondy dostępności |
| `references/ux.md` | checkpoint ma UI: macierz urządzeń, flows, explorer, judge, coverage, `helix visual audit`, `perf weight` |
| `references/security.md` | uruchamiasz `helix security|perf|integrity` albo `security deep` |
| `references/kontrakty.md` | zadania `.helix/tasks`, narzędzia `.helix/tools.json`, reguły `.helix/rules`, ledger wymagań, handoff i ciągłość agentów |
| `references/new.md` | nowy projekt albo wejście w zastane repo (`helix new init|audit`) |
| `references/duze-repo.md` | repo za duże na jeden przebieg: `--config`, `--state-dir`, tryby full/daily/release, obciążenie maszyny |
| `references/runtime.md` | runtime, Keycloak, HTTPS, WebAuthn, polityka tożsamości, kody wyjścia 0/2/3 |
| `references/ponytail.md` | audyt prostoty, komentarze `ponytail:` |
| `references/egress-i-narzedzia.md` | wysyłka źródeł do dostawców (data egress) albo instalacja narzędzi (`helix tools`) |
| `references/ogolnosc.md` | dodajesz regułę zależną od projektu, mapujesz bramki przez `pro-evidence.json`, CI |

## Principle
An attempt may be wrong. It may not move forward until it is proven. Small checkpoints, strict gates, feedback remembered.

## Gate G0 — "Prawda i kontekst" (truth & context). Runs FIRST: before any fix/PR and before reporting findings
Rule: **a name in code is not proof of what runs in production.** Legacy integration names can differ from the deployed backend. Verify the live configuration and owner context before changing behavior.

1. `helix truth init cpN [--kind fix|report] [--target local|pr]` -> `helix-evidence/cpN/truth.json` (ledger template).
2. Fill it:
   - **systems**: every live system/integration the change or report touches (ERP, payments, mail, workers, storage), named the way the OWNER names it. `status: confirmed` + `confirmed_by: "<who, when, where>"`, otherwise `unconfirmed`. Write `"systems": []` only if nothing live is touched.
   - **claims**: every factual statement of the report/PR, one per entry. `tag: VERIFIED` needs evidence; otherwise `tag: ASSUMPTION`. Nothing unlabeled. `affects_prod: true` for claims about what runs in production.
     Evidence kinds: `path:line` (code, checked to exist), `config:path:line`, `deploy:path:line`, `sha:<commit>` (checked with git), `cmd:<file with command + output>`, `owner:<who, when, where>`, `prod:<observation>`.
     A prod claim proven only by plain code references FAILS. Check config/env, deploy files, recent commits, or ask the owner.
   - **behaviour** (fixes): `characterization_tests` that pin CURRENT behaviour around the change (written before the fix, passing on the old code), `diff_allowlist` (only the files the fix needs).
3. `helix truth suite cpN before` (before editing) and `helix truth suite cpN after` -> full-suite pass/fail counts. Fewer passes or more failures = FAIL.
4. `helix truth check cpN [--provider gemini|codex|claude-via-agy|grok-cli|grok]` -> a different model gets systems + claims + diff and answers "what is false, what could break the working system" (`truth-check.json`). Pick a provider/family other than the implementer's. Every blocker/major finding needs a resolution with evidence in `independent_check.resolutions` (`{"F1": "..."}`): fix the claim, fix the code, or explain with evidence.
5. `helix gate truth cpN` -> `truth.md` (checklist `[x]` ok / `[!]` warning / `[ ]` blocks) + `truth-gate.json`, exit 0 = PASS, 2 = FAIL. Paste `truth.md` into the report/PR.

Outcomes:
- **FAIL**: unlabeled claim, invalid evidence, prod claim backed only by code, missing/regressed suite counts, diff outside allowlist, unresolved checker finding, template placeholders.
- **PASS, local only** (`local_only: true, pr_allowed: false`): fix touches an unconfirmed system or rests on an unconfirmed prod ASSUMPTION. Keep it on a local branch. No PR until the owner confirms. With `--target pr` the same ledger FAILS.
- **PASS, PR allowed**: all touched systems confirmed by the owner, prod assumptions confirmed.
- Reports (`--kind report`): unconfirmed systems and ASSUMPTIONs are allowed but must appear as such in the text (`[!]`).

`"truth": {"required": true}` in `helix.json` makes `helix approve` and autonomous commits refuse without a passing G0.
When reporting to Owner: say what is VERIFIED (with evidence) and what is ASSUMPTION, in separate parts. Never present an assumption as a fact.

## Loop
1. `helix plan "<task>"` -> `.helix/plan.json`. A human reviews the checkpoint list in minutes (few-word titles) and may edit it.
2. For each checkpoint: `helix run cpN` (the implementer works -> gates 1..3 in order; on failure, the gate's findings go back to the implementer as feedback; repeat within limits).
3. Supervised mode: stops at gate 4 (`awaiting_approval`). The human runs `helix approve cpN ["note"]` (commit + memory) or `helix reject cpN "feedback"` (memory + `pending_feedback` for the next run).
4. Autonomous mode (`--autonomous` or `"mode":"autonomous"`): gate 4 is skipped, gates 1-3 are NOT relaxed, and each checkpoint ends with a commit `helix(cpN): title` plus an evidence bundle.

The agent must never commit, skip a gate or override a failed gate by itself. Only `helix approve` / autonomous mode commit.

## Checkpoint plan format (`.helix/plan.json`)
```json
{"task": "...", "checkpoints": [
  {"id": "cp1", "title": "few words", "goal": "one sentence",
   "test_cases": ["user-perspective case incl. edge cases", "..."],
   "visual": true, "visual_scope": "what part of the screen to compare at this checkpoint"}]}
```
Order: skeleton first, smallest slices first. Logic-only checkpoints use `visual:false`, which skips gate 2.

## Gate contracts
| Gate | Input | Pass condition | Output files |
|---|---|---|---|
| G0 truth | `truth.json` (systems, claims, behaviour, independent check) | no `[ ]` items; PR only if every touched system and prod assumption is owner-confirmed | `truth.md`, `truth-gate.json`, `truth-check.json`, `truth-suite-*.log` |
| 1 behavior | `test_cmd` (config or auto: npm/pnpm/yarn test, pytest, go test, cargo test, phpunit, make test) | exit 0 | `behavior.log`, `behavior.json` |
| 2 visual | `start_cmd` + `url` (the new app) vs `reference_url` or `reference_image`, same viewport + `actions` (state) | judge says `valid` and no `code_fixable` difference (any severity). INVALID (different state) = fail + recapture. No judge = pixel diff < 0.1% (stated in evidence) | `screenshots/{before,after,reference,diff}.png`, `visual.json` |
| 3 review | `git diff <checkpoint base>` + architecture doc + checkpoint | ALL enabled reviewers return approve. Only `blocker`/`major` block; `nit` never blocks (anti-nitpick). Max `max_review_rounds` rounds | `diff.patch`, `review-<name>-r<n>.json`, `review.json` |
| 2b ux (optional) | `ux` config: local `base_url`, pages, device matrix, flows | no ❌ cell in device×page matrix (automated checks + judge high/code_fixable) and every scripted flow passes. Variants block only with `ux.gate.variants_block`. Explorer is advisory. `ux.required: true` blocks `approve` | `ux/ux-report.{md,json,html}`, `ux/shots/`, `ux.json` |
| 4 human | evidence bundle | `helix approve` | memory.md entry, commit |

Reviewers run as separate processes with fresh context (`codex exec --ephemeral`, a new agy conversation) and different prompts:
`review_architecture` (architecture & correctness) and `review_tests` (tests & security).
Optional third prompt for checkpoints that touch UI: `review_ui` (interface rules from the pinned Vercel Web Interface Guidelines, same blocker/major threshold); enable it as a reviewer in `helix.json`.
Architecture doc: `architecture_doc` or the first found of ARCHITECTURE.md, docs/ARCHITECTURE.md, AGENTS.md, CLAUDE.md, CONTRIBUTING.md.

## Dostawcy (skrót)

Role w `helix.json`: `codex`, `gemini`, `claude-via-agy`, `claude`, `grok-cli`, `grok` (ręczny handoff). Recenzenci i weryfikator muszą być z innej rodziny niż autor; brak niezależnej rodziny daje LIMITED. Łańcuchy modeli są próbowane po kolei, pierwszy jest zawsze główny; model, który odpowiedział, trafia do `summary.md`. Szczegóły, flagi CLI i handoff Groka: `references/providers.md`.

## Evidence bundle `helix-evidence/<cp>/`
`summary.md` (status, each gate, verdicts, models used), `behavior*.log`, `screenshots/`, `visual.json`, `diff.patch`, `review-*.json`, `implement-attempt*.md`, `agy-raw-*.json`. It is excluded from git (via `.gitignore`), so attach it to the PR by hand if needed.

## Memory
`.helix/memory.md`: every approve/reject with its text. It is injected into the planner and implementer prompts at every checkpoint. Write rejections as rules ("never X, always Y").

## Limits (`limits`)
`max_attempts` (implementation attempts per checkpoint, default 3), `max_review_rounds` (2), `checkpoint_timeout_s` (1800), `provider_timeout_s` (600), `grok_wait_s` (0 = do not block, set pending).
When limits run out, the status is `failed` with the evidence bundle. A human decides (fix the plan, reject with feedback, or `run --force`).

## Rules for the agent using this skill
- A clean working tree is required before `run` (base commit per checkpoint).
- Do not edit `.helix/` or `helix-evidence/` by hand, except for `plan.json` (allowed), a requested Grok verdict and its matching provenance receipt.
- Do not push, deploy or open PRs from inside the loop. That is a separate human step.
- Never open a PR (or say "ready") without a G0 PASS with `pr_allowed: true`. Never report findings without the claim ledger.
- Do not edit `truth-check.json` or `truth-gate.json` by hand. Only `truth.json` is written by the author.

## Zasady G0–G4 w skrócie i raport checkpointu

G0: przeczytaj rzeczywisty przepływ i rozpisz checkpointy, każdy do przejrzenia w ≤5 min:
co zmieniam, dowód działania, konkretny wycinek wzorca. G0 prawdy pozostaje obowiązkowe.
G1: test z perspektywy użytkownika musi najpierw paść na starym kodzie lub celowo
wstrzykniętym błędzie; zapisz fail-before/pass-after. Ekran po przebudowie nie powinien być cięższy.
G2: `helix visual audit URL --out DIR --case ekran-stan --sweep 280-1600:40`;
sprawdź oba motywy, dane zwykłe i skrajne oraz wszystkie przedziały layoutu.
Przebudowa ekranu: spisz wszystkie warunkowe elementy, pola edytowalne, liczniki,
puste/błędne/loading stany i linki; odtwórz zachowanie 1:1. Ucięcie treści albo pole
zamienione na tekst to zmiana zachowania. Tokeny odczytaj z projektu dla obu motywów.
Autor ogląda całą ramkę zrzutu. Automat bez wzorca raportuje `not_checked`;
nie potwierdza kompozycji, stanów interakcji ani niezależnej recenzji.
G3: autor ≠ recenzent; dwóch niezależnych recenzentów ze świeżym kontekstem,
bez znajomości wzajemnych werdyktów. Uwagi istotne wymagają poprawki i ponownego dowodu.
Recenzja prowadzona ręcznie (most, rada, handoff) ma te same reguły co `helix run`:
prompty `prompts/review_architecture.md` i `prompts/review_tests.md`, skala
`blocker|major|nit`, werdykt `approve|changes`; blokuje tylko `blocker` i `major`.
Runda 2 sprawdza wyłącznie naprawę uwag blokujących z rundy 1 oraz to, co zmieniła
poprawka; nie zleca nowego polowania. Po `max_review_rounds` (2) nie ma kolejnej pełnej rundy:
otwarte `nit` idą do raportu jako dług, a otwarty `blocker` albo `major` jest w raporcie
nazwany jako niezamknięty i rozstrzyga go G4. Poprawka uwagi blokującej zrobiona po ostatniej
rundzie dostaje jedno sprawdzenie zawężone do jej diffu; bez niego checkpoint nie jest zaliczony.
W raporcie podaj osobno
liczbę uwag o zachowaniu produktu oraz o testach i bramkach (`docs/g3-pomiar-2026-11-13.md`).
G4: człowiek akceptuje wynik. Feedback mechaniczny przenieś do testu/reguły,
ocenny do instrukcji w zatwierdzonym zakresie; prywatna pamięć wyłącznie na jawną prośbę.
Nie podpisuj automatycznie wzorców ani zgód. Audyt nigdy nie tworzy wzorca.

Raport checkpointu: `G0 prawda | G1 zachowanie + waga trasy baza→teraz | G2 liczba
zrzutów/pomiarów, PNG i niezależna ocena | G3 dwa werdykty i rundy | G4 czeka/zgoda`.
Każdy wynik z komendą i dowodem z bieżącego przebiegu, plus drobne uwagi i świadomy dług.

## Zmiany

- 2026-11-14: runtime na macOS pod izolacją przechodzi pełną ścieżkę na projekcie A (przeglądarka, e2e, a11y, Lighthouse, PDF, logowanie w lokalnym Keycloak); ekrany chronione ogląda sesja roli z `runtime.keycloak.parts.<część>.screen_role` (decyzja właściciela, domyślnie wyłączone), opis: `docs/runtime-integrations.md`.
- 2026-11-14: recenzent UI `review_ui` na przypiętych wytycznych interfejsu Vercela (MIT, `vendor/web-interface-guidelines/4ecfb9f`); z zakładek właściciela.
- 2026-11-13: G3 prowadzone ręcznie dostaje reguły silnika (skala, próg blokowania, zakres rundy 2, limit rund); powód: pomiar na projekcie C, `docs/g3-pomiar-2026-11-13.md`.
- 2026-11-02: podział na rdzeń + `references/` (treść bez zmian, przeniesiona); `name` = katalog `helix` (specyfikacja Agent Skills); opis przepisany pod wyzwalanie. Pin `helix_version` bez zmian.
