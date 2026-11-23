# Status przeglądu i przypomnienie po commicie

```sh
helix --repo /code/app --state-dir /audits/app/state --offline status
helix --repo /code/app --state-dir /audits/app/state --offline status --json
```

Domyślny wynik to jedna linia: liczba commitów od ostatniego potwierdzonego
COMPLETE, stan zmian lokalnych i sugerowane polecenia `daily` oraz `release`.
Jeśli zapisano plan checkpointów, podsumowanie zachowuje też ich dotychczasową
listę. `--reminder-only` zawsze zwraca jedną linię. `--json` zawiera rewizje,
datę, relację historii, ścieżki dowodów i uzasadnienie.

Status nie potrzebuje `plan.json`, nie tworzy `.helix`, nie skanuje źródeł,
nie uruchamia modeli ani sieci. Odczytuje lokalny Git, dokładny cursor COMPLETE,
jego `run-metadata.json` oraz opcjonalne istniejące checkpointy. Git działa bez
odświeżania indeksu i bez repozytoryjnego fsmonitor. Jeśli konfiguracja lokalna
lub globalna zawiera filtr `clean`, `smudge`, `process` albo `required`, status
nie uruchamia filtra ani `git status`: stan lokalnych zmian pozostaje nieznany.
Zachowuje licznik commitów i nie zgłasza wtedy `CURRENT`. Wartości poleceń filtrów
nie są odczytywane ani raportowane. To ostrożne ograniczenie obejmuje również
globalny Git LFS, nawet jeśli dane repo nie używa jego atrybutów. Podobnie Git
submodule wykryte w indeksie pozostają niesprawdzone: ich własne filtry mogą
uruchamiać kod, więc Helix nie zgłasza wtedy czystego worktree. Domyślna lokalizacja kursora
to `~/security-audit/<nazwa-repo>/completed/<hash-celu>/last-complete.json`;
przy `--state-dir` jest to `<state-dir>/security-audit/completed/<hash-celu>/last-complete.json`.

| Status | Znaczenie |
|---|---|
| `CURRENT` | Czysty HEAD ma potwierdzony COMPLETE; licznik wynosi 0. |
| `DUE` | Po COMPLETE doszły commity albo istnieją nieprzejrzane zmiany lokalne. |
| `NO_BASELINE` | Brak COMPLETE; licznik jest nieznany, najpierw potrzebny `full`. |
| `UNKNOWN_BASELINE` | Historia jest rozbieżna albo dowód nie potwierdza celu, rewizji lub zakresu. |
| `ERROR` | Nie udało się ustalić lokalnego repozytorium i HEAD. |

Nowszy częściowy przebieg nie zastępuje poprzedniego COMPLETE. Licznik 0 przy
lokalnych zmianach nadal oznacza `DUE`. COMPLETE opisuje zakończony przegląd
źródeł, nie zatwierdzenie produkcji ani brak ustaleń bezpieczeństwa.

## Jawna instalacja hooka

```sh
helix --repo /code/app --state-dir /audits/app/state --offline hooks install --post-commit
```

Instalator używa ścieżki wskazanej przez Git, w tym `core.hooksPath` i linked
worktrees. Tworzy wyłącznie nowy `post-commit`, odmawia istniejącego pliku lub
dowiązania i nie zmienia konfiguracji Git. Wynik pokazuje dokładną ścieżkę
oraz informację o możliwym współdzieleniu hooka.

Hook uruchamia tylko `--offline status --reminder-only`. Nie rozpoczyna audytu,
nie wywołuje providerów, nie wysyła kodu i nie akceptuje baseline. Błąd odczytu
wypisuje jako nieznaną zaległość, bez blokowania zakończonego commita.

Worktrees mogą współdzielić hooki. Jawny `--state-dir` jest przypisany wyłącznie
do kanonicznej ścieżki celu instalacji. W innym worktree ten sam hook wybiera
jego domyślny, odrębny cursor. Analogicznie `--config FILE` jest zachowany w
sugerowanych poleceniach i przypisany w hooku wyłącznie do celu instalacji;
helper statusu przechowuje ścieżkę, nie czyta wartości konfiguracji. Istniejące własne hooki można połączyć ręcznie po
przejrzeniu polecenia statusu; Helix nie dopisuje do nich kodu automatycznie.
