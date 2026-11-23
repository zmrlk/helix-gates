# Helix · Dostawcy modeli, łańcuchy, sondy

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

## Providers (pluggable per role, in `helix.json`)
- `codex`: `codex exec` (sandbox read-only for reviewers, workspace-write for the implementer, `-i` for images, `--output-schema`).
- `gemini`: `agy -p ... --model <id> --output-format json` (Antigravity CLI, Google login).
- `claude-via-agy`: same CLI, Claude models (no Claude Code login needed).
- `claude`: `claude -p` (needs Claude Code login).
- `grok-cli`: Grok Build CLI headless (`grok --prompt-file ... --output-format json --json-schema ... --permission-mode dontAsk --max-turns 4 --no-subagents --disable-web-search`), chain `grok-4.7` → `grok-4.6`. Same rules as agy: no commands, JSON verdict, empty/non-JSON → next. No `--add-dir` (Grok sessions work only in cwd; evidence lives inside the repo).
- `grok`: ręczny handoff bramki review tworzy osobny `manual-request-<reviewer>-r<n>-<hash>.md` i JSON z `request_id`. Prompt zawiera pełną różnicę, a identyfikator wiąże checkpoint, recenzenta, rundę, bazę oraz hashe promptu i całego diffu. Zapisz werdykt zgodny z `schemas/review.json` pod wskazaną nazwą `manual-verdict-...json` oraz osobny `.receipt.json` z `request_id`, SHA-256 bajtów werdyktu, providerem i rzeczywistą nazwą modelu. Potem ponów `helix gate review cpN`; brak któregokolwiek kompletu pozostawia konkretnego recenzenta pending. Stare wspólne `review-grok-r<n>.json` nie są nowym dowodem. Receipt ręcznie deklaruje pochodzenie modelu; provenance zachowuje `status=declared`, `method=manual_handoff`, `call_invoked=false`, również w agregacji właściciela. To nie jest sonda dostępności ani wywołanie CLI Helixa. Handoff `truth check` zachowuje dotychczasowy osobny kontrakt.

Model fallback chains (`models` in config) are tried in order on every call, so the primary model is always tried first. Any error (quota, rate limit, model unavailable, empty or non-JSON answer) moves to the next model, then to the `fallback` provider. The model that actually answered is recorded in `summary.md`.

## Sondy modeli podczas przygotowania

`--refresh-providers` jest jawnym krokiem online. Nie łącz go z `--offline`.
Sondy pracują równolegle, domyślnie trzy, wyłącznie w neutralnych katalogach
z krótkim JSON ping. Nie przekazuj do nich źródeł ani AGENTS klienta. Raportuj
aktualne availability probes osobno od source review i planu ról. Udana sonda
nie akceptuje polityki wysyłki kodu. Nie powtarzaj modelowych sond w testach:
używaj kontrolowanych callerów, zegara i syntetycznych odpowiedzi.
