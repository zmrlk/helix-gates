# Helix · Środowisko, aktualizacja i przegląd AST

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

## Strukturalny przegląd bezpieczeństwa

`helix review deep ROOT --out EXTERNAL_DIR` i plan ryzyka security deep
wybierają zarządzany ast-grep 0.51.0 dla AUTH/IDOR/OTP/UPLOAD/MASS.
Czytaj `static_engine`: zakres parsera, wersję/receipt, luki i uzasadnienia
lokalnych kandydatów. Brak narzędzia ma jawny fallback possible/medium,
a brak alarmu ani guard składniowy nie zaliczają ochrony produkcji.
[Kontrakt AST i regresje](../docs/security-ast.md).

## Aktualizacja Helixa
`helix doctor` pokazuje commit, gałąź, lokalne zmiany i stan origin (fetch,
timeout 10 s; bez sieci: „nie sprawdzono”). `helix update` wykrywa repo z
położenia skryptu, wykonuje fetch + pull --ff-only, wypisuje nowe commity i
uruchamia doctor. Lokalne zmiany i rozbieżna historia wymagają ręcznej obsługi;
komenda nie robi merge/reset/stash i nie instaluje narzędzi systemowych.
`helix update --check` sprawdza wyłącznie zapisane lokalnie referencje origin,
bez pobierania i zmian; wynik może być nieaktualny.

## Środowisko projektu przed oceną

`helix --repo /code/app --offline env --no-probe --out /audits/app-environment`
odczytuje deklaracje środowiska bez uruchamiania aplikacji, usług i modeli.
Bez `--no-probe` dochodzą lokalne polecenia wersji narzędzi. Zachowuj osobno
deklarację repo, wynik lokalny i produkcję; macierz CI to alternatywy, a lokalny
`psql --version` opisuje klienta, nie serwer PostgreSQL.
Runtime porównuje również rzeczywiste `SHOW server_version` przed migracjami.
Inna major wymaga jawnego `--allow-version-mismatch` i daje DEGRADED, bez punktów;
nieznana wersja serwera blokuje wykonanie także z tą flagą.
Przed migracjami i restore sprawdza katalog rozszerzeń każdej własnej bazy.
Zachowaj różnicę między dostępnością, instalacją i wykonaną migracją; brak
wymaganego rozszerzenia blokuje daną operację, bez automatycznej instalacji.

Wersję produkcyjną wolno przytoczyć wyłącznie z jawnego `--prod-evidence FILE`:
JSON `components` zawiera `version`, `checked_at` ze strefą czasową i `evidence`.
To import dostarczonego dowodu, bez automatycznego połączenia z produkcją.
Bez niego produkcja pozostaje nieznana. `--out` musi być poza repo celu;
wyniki to `environment.json` i `environment.md`. Raportuj nazwy zmiennych
oraz braki deklaracji, nigdy ich wartości; rzeczywiste `.env` są pomijane.
`doctor --offline` pokazuje również podsumowanie środowiska.

Zachowuj wspólne `provenance`: wersję Helixa, HEAD/dirty źródeł Helixa i celu,
Python oraz faktycznie zapisane wersje użytych narzędzi i modeli. Nie wpisuj
konfiguracji providera jako dowodu jego odpowiedzi; nieznana wersja to `unknown`.
Zbieranie metadanych może odczytać lokalny Git, ale nie uruchamia dodatkowych
sond ani modeli. W agregacji `generation_provenance` opisuje nowy raport,
a `source_provenance` każdy dowód osobno. Nie podmieniaj starego SHA ani wersji
narzędzi bieżącymi. HEAD z dirty nie wystarcza do odtworzenia bez zrzutu źródeł.
