# CI i szybka bramka

Workflow CI definiuje testy Helixa na macOS (arm64; Ubuntu dojdzie po zebraniu i przeglądzie pinów linux-x86_64 cp312), kontrolę wersji i wymagań,
audyt własnego repo oraz lokalne regresje Semgrep. Zizmor działa offline,
w trybie pedantic. Akcje mają pełne SHA, token tylko contents:read,
checkout nie zachowuje poświadczeń. Nie ma wywołań modeli ani produkcji.

Lokalnie: `python3 scripts/check_fast.py`. Hook instaluje operator:
`git config core.hooksPath .githooks`. Nie nadpisuj istniejącej konfiguracji
hooków; przy własnych hookach dopisz wywołanie skryptu. Hook nie jest dowodem
pełnej suity ani uruchomienia CI. Pełna bramka: `python3 scripts/run_tests_parallel.py`.

Regresje reguł: `semgrep --test --config config/tools tests/fixtures/semgrep`.
Reguły śledzą lokalny przepływ danych z params, url.searchParams i request.json
do tekstu SQL, adresu fetch i ścieżek fs. Parametry zapytań SQL i ciało fetch
nie są sinkami. Brak alarmu nie dowodzi walidacji; międzyplikowy przepływ,
własne wrappery i aliasy wymagają rozszerzenia reguł. Reguły nie deklarują
uniwersalnego sanitizera.

`helix bench --help` opisuje stałą komendę benchmarku na zewnętrznych etykietach.
Benchmark nie uruchamia modeli ani aplikacji celu.

Źródła kontraktów: [checkout v4.2.2](https://github.com/actions/checkout/releases/tag/v4.2.2),
[setup-python v5.6.0](https://github.com/actions/setup-python/releases/tag/v5.6.0),
[Zizmor](https://docs.zizmor.sh/usage/),
[Semgrep taint](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview).

Wywołania natywnych providerów zapisują `model-call-<id>.json` w katalogu
wyników. Raport checkpointu i `owner-report` pokazują czas monotoniczny,
input/output/total tokens i koszt USD per próba, także po błędzie. Wartości
pochodzą wyłącznie z zewnętrznej koperty CLI AGY/Grok; brak telemetryki
(Codex/Claude w trybie tekstowym, nieobsługiwany format) to `null`/„nieznane”.
Nie wyliczamy kosztu z długości promptu ani ceny z konfiguracji. Jawnie
zaraportowane zero jest zachowywane. Odrzucenie przed dopuszczeniem transportu
nie tworzy wywołania ani pliku. Receipt nie zawiera promptu, odpowiedzi ani
komendy. Cache pozostawia historyczny receipt; odczyt cache nie tworzy próby.

Dowody scalenia etapu 2 obejmują testy lokalne, Semgrep i zizmor. GitHub Actions
pozostaje NOT_RUN; obecność workflowu nie potwierdza jego wykonania.
