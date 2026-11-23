# Helix · Referencyjne reguły prostoty Ponytail

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

### Referencyjne reguły prostoty Ponytail

Przypięte źródła `ponytail-review`, `ponytail-audit` i `ponytail-debt` 4.9.0
są w [vendor/ponytail](../vendor/ponytail/4.9.0/VENDORED.json), z oryginalnym
[MIT LICENSE](../vendor/ponytail/4.9.0/LICENSE). Manifest opisuje odczyt lokalnej
dystrybucji i dokładne hashe; nie potwierdza zdalnego commita upstream.
Teksty reguł są materiałem dla wspólnego KISS/YAGNI. Samo ich dostarczenie
nie wykonuje soczewki modelowej.

Przy integracji zachowaj granicę: prostota to sugestia dotycząca złożoności,
a redukcja linii jest szacunkiem. `Lean already. Ship.` nie jest dowodem PASS.
Wymagania właściciela, walidacja granic zaufania, bezpieczeństwo i testy
regresji zachowują swoje kryteria niezależnie od propozycji skrócenia kodu.

`new audit` zbiera deterministycznie komentarze `ponytail:` do
`quality.json`, `audit.json` i raportu właściciela. Zapisz jawny sufit oraz
ścieżkę ulepszenia, na przykład
`// ponytail: ceiling: 50 rows; upgrade: indexed cache`.
Obsługiwany jest też zapis `ponytail: 50 rows, indexed cache`.
Brak części oznacza `no-ceiling` lub `no-trigger`, bez zgadywania intencji.
Rejestr zachowuje każde plik:linia, obszar źródła, hash i luki parsera.
Tekst w stringu lub przykład Markdown nie jest komentarzem kodu.
Niepełny odczyt lub nieobsługiwana składnia nie mogą dać czystego rejestru.

Wiek opisuje ostatnią zmianę linii w HEAD przy odczycie, nie pierwsze
powstanie długu. Odczyt Git nie uruchamia filtrów ani pobierania obiektów;
niezgodność bloba, brak historii lub brak dowodu daty dają nieznany wiek.
Użyj tego samego zewnętrznego `--state-dir` przy audycie i `status`.
Status odczytuje zapisany wynik, bez skanowania, blame i modeli; po zmianie
źródeł zachowuje wynik historyczny jako nieaktualny. Hook pozostaje jedną
linią. Rejestr długu nie daje punktów jakości ani oceny modelowej prostoty.
