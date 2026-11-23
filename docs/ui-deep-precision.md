# UI deep: precyzja i zakres statyczny

VERIFIED: oracle `tests/fixtures/ui-deep/expected.json` opisuje 23 ręcznie zasiane
ustalenia z lokalizacją i identyfikatorem reguły. `tests/test_ui_deep.py`, test
`test_precision_recall_oracle`, porównuje dokładne zbiory: TP=23, FN=0, FP=0,
precision=100%, recall=100% na tym syntetycznym zbiorze. Kontrole negatywne są
w czterech poprawnych plikach Svelte, TSX, Vue i CSS. Nie jest to estymacja jakości
na rzeczywistych repozytoriach; ich FP/FN pozostają ASSUMPTION i nie są mierzone.

Uruchomienie: `python3 -m unittest discover -s tests -p test_ui_deep.py`.
Oracle jest niezależny od wyników analizatora; zmiana reguł nie przepisuje manifestu.
Testy adversarial obejmują cykle i niejednoznaczne motywy tokenów, aliasy,
komentarze, dynamiczne propsy, symlinki, katalogi prywatne, Tailwind arbitrary
values oraz brak zapisu w analizowanym repo. Kontrast czerni i bieli wynosi 21:1.

## Użycie i kontrakt

`bin/helix ui deep /path/to/repo --out /tmp/ui-review` tworzy `ui-deep.json`
i `ui-deep.md` po polsku; stdout domyślnie JSON, opcjonalnie `--format markdown`.
Wyniki muszą znajdować się poza targetem. Polecenie działa bez konfiguracji Helixa,
bez `.git`, Ctx, pinowania wersji, instalowania narzędzi i wykonywania konfiguracji.
Schemat raportu: `schemas/ui_deep.json`. Kontrakt dla frameworka:
`helix_ui_deep.run(repo) -> list[dict]`, `score(findings) -> int`, `checklist()`
z mapą dwóch soczewek `ux_designer`, `ui_designer`.

Identyfikator `id` to stabilny kod reguły; tożsamość wystąpienia jest krotką
(lens, id, file, line). Raport wiodący sortuje severity i grupuje powtórzone
kontrolki oraz literały per plik; maks. trzy przykłady dowodów plus licznik.
JSON zawiera pełne liczniki per plik/komponent; Markdown maks. 30 komponentów.
W pliku z wieloma eksportami liczniki dotyczą całego pliku, nie każdego eksportu.

Raport pokazuje liczbę kandydatów, wzorców potwierdzonych w źródle, niezależnie
zweryfikowanych ustaleń i odroczeń wymagających przeglądarki. Pole `score` oraz
funkcja `score(findings)` pozostają tylko dla zgodności dotychczasowego API;
Markdown nie przedstawia ich jako oceny jakości. `summary.by_area` i pole
`source_area` oddzielają aktywny kod, dokumentację, archiwa oraz testy/przykłady.
Dokumentacja i starsze warianty nie są po cichu wyłączane z odczytu.

## Ograniczenia i adversarial pass

- Własny skaner stdlib, bez Semgrep i bez zależności opcjonalnych. Nie wymaga
  Semgrep; brak tego narzędzia nie jest błędem. Nie importuje kodu targetu.
- Tokeny CSS, konfiguracje Tailwind, pliki theme/tokens i katalogi bazowych
  komponentów są rozpoznawane statycznie. Konfiguracje JS/TS nie są wykonywane.
  Literały CSS oraz Tailwind arbitrary values są liczone. Pełna semantyka
  konfiguracji Tailwind, style obiektowe JSX i interpolacje SCSS są poza zakresem.
- Kontrole podobieństwa porównują klasy/style natywnych button/input/dialog:
  identyczne sygnatury lub co najmniej trzy wspólne klasy i Jaccard >=0.7.
  Porównywanie podobnych sygnatur ograniczone do pierwszych 500.
  Nie dowodzi to identyczności zachowania ani potrzeby abstrakcji.
- Kontrast: jawna para fg/bg w jednym bloku, #RGB/#RRGGBB, rgb integer,
  black/white i jednoznaczne aliasy var(). Warianty tokenów, cykle,
  alpha, gradienty, dziedziczenie oraz pełna kaskada nie są rozstrzygane.
  Wynik to `likely`; 4.5:1 dotyczy zwykłego tekstu, którego faktyczny rozmiar
  i użycie selektora wymagają przeglądu. Nie jest to certyfikat WCAG.
- Brak label, stany danych, klawiatura, focus i usuwanie są heurystykami lokalnymi.
  Wrapper, delegacja i zewnętrzny CSS mogą zmieniać wniosek. Spready propsów
  powodują odroczenie oceny; ich pominięcia są liczone w adversarial pass.
  Zastępcze tło, obramowanie lub cień w tym samym bloku `:focus-visible`/`:focus`
  wyłącza alarm samego `outline:none`, lecz dodaje odroczenie oceny widoczności.
  Style innej kontrolki, `:hover` lub `:focus-visible:hover` nie ukrywają alarmu.
- Copy obejmuje widoczny tekst znaczników i podstawową detekcję PL/EN.
  Nie rozstrzyga i18n ani tekstów generowanych dynamicznie.
- Pomijane: symlinki, ukryte katalogi, zależności/build, katalogi testów,
  nazwy zawierające secret/credential/private/lock. Dopuszczony tekst jest czytany
  w całości, bez limitu 1 MB. `source_coverage` zawiera liczbę odczytanych plików,
  podział zakresów, pominięte pliki i wykluczone poddrzewa z nieznaną liczbą potomków.
  JSON jest czytany wyłącznie dla nazw theme/tokens, bez ogólnych plików danych.
  Rozszerzenia ograniczone do plików UI i konfiguracji. Częściowy skan nie daje
  dowodu kompletności. Nie należy kierować skanera na katalog prywatnych danych.
- Każda soczewka kończy się adversarial pass z checklistą, licznikami odroczeń
  i ograniczeniami. `confirmed` opisuje wyłącznie sprawdzony wzorzec źródłowy
  (np. brak atrybutu alt), nigdy obserwację działającej aplikacji.
