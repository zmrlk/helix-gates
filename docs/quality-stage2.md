# Precyzja i czytelność 0.8.0-beta

`helix new audit --repo ŚCIEŻKA --out KATALOG` dodaje `coverage.json`,
`quality.json` i `readability-model-tasks.json`; podsumowanie trafia do `audit.md`.
`lenses` korzysta z tego samego analizatora i istniejącego kontraktu findings.

Inwentarz: `git ls-files --cached --others --exclude-standard`. Bez git jest
jawny fallback filesystem, oznaczony INCOMPLETE. Tekst nie ma limitu rozmiaru;
odczyt deskryptora używa bloków 64 KiB, lokalne wzorce okien z nakładką 4 KiB.
Obecne analizatory potrzebują również scalonego tekstu w pamięci; nie jest to
ograniczony pamięciowo parser całego audytu. Nie ma gwarancji wykrycia wzorca
dłuższego niż okno. Coverage liczy odczyt, nie semantyczne sprawdzenie linii.
Pominięcia prywatności, symlinków, binariów i błędów są jawne; nieznana liczba
linii nie jest zerem. Jakiekolwiek pominięcie daje INCOMPLETE, nigdy PASS.
Deklaracja generowania w nagłówku jest dowodem klasyfikacji; plik nadal czytamy.

Kandydaci obejmują separatory liczb, float w kwotach, jednostki, zakresy,
czas bez strefy, podobne klucze, proste JSON i18n i jawne kolumny SQL.
Każdy ma plik:linia, severity, confidence, powód i sugestię. Brak dopasowania
nie dowodzi poprawności. YAML jest heurystyką kluczy, nie pełnym parserem.
Dynamiczne ORM, schemat bazy i pełna semantyka zakresów pozostają nieznane.

Progi S/M/L/XL: `config/quality-profiles.json`; projekt może jawnie podać
`quality_profiles` w `helix.json`. Funkcje Python mają granice AST; pozostałe
języki heurystykę nawiasów. Metryki cognitive/nesting są przybliżeniem.
Adaptery radon, jscpd, knip, typos, codespell, cspell i vale są ponownie używane
przez istniejące `helix tools scan`; audyt sam ich nie uruchamia (not-run).
Plain language dotyczy dokumentacji; detektor długości zdań nie ocenia kodu.
Pełna ocena żargonu, spójności terminów i PL/EN wymaga konfiguracji słowników.

Paczka modelu zawiera prompt, kontrakt JSON oraz ścieżki i hashe źródeł,
bez kopiowania treści. Przygotowanie daje 0 punktów, model ma status not-run.
Audyt nie wywołuje providera. Import i niezależne potwierdzenie kandydatów
nadal podlegają istniejącej granicy weryfikacji Helixa.

Testy syntetyczne mierzą separator: 3/3 podatne stosy i 0/1 fałszywy alarm
w bezpiecznej próbce. To pomiar fixture, nie estymata jakości dla innych repo.
Pełna suita i recenzja są odroczone na polecenie właściciela.
