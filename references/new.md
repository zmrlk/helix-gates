# Helix · Helix New: przygotowanie projektu

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

## Helix New: przygotowanie projektu

Przed realizacją nowego projektu lub wejściem w zastane repo użyj
`helix new init --mode greenfield|brownfield --profile S|M|L|XL --risk low|high|regulated`.
Brownfield: `helix new audit --repo PATH --out DIR` czyta repo bez wykonywania
kodu i tworzy propozycje poza nim. Brak zatwierdzonej źródłowej marki blokuje
design/handoff: `helix new brand check`, następnie `helix new check`.
Obowiązkowy projektowy SKILL.md prowadzi dalej przez istniejące G0 i checkpointy.
Walidacja handoffu nie zastępuje tych bramek ani akceptacji właściciela.
Init i audit generują zewnętrzne `helix.proposed.json` oraz `NEW-REPORT.md`:
pin, zachowane jawne role/modele, realne dowody dostępności z cache, UI paths,
środowisko i baza, plan deep oraz harmonogram full/daily/release. Init bez
`--write` umieszcza drafty w `--out/proposed`; repo celu pozostaje bez zmian.
`--write` tworzy tylko nowe pliki i nigdy nie nadpisuje istniejących. Brak
świeżych sond wymaga `providers --refresh --jobs 3` albo jawnego
`new init|audit --refresh-providers --jobs 3`; brak egress pozostawia
puste dozwolone grono dostawców i pytanie do właściciela. Propozycja nie jest
akceptacją konfiguracji ani dowodem recenzji. Dla dużego repo pierwszy full
w nocy z jobs3, następnie daily, a przed wydaniem release; brak historii COMPLETE
nie uruchamia cichego pełnego skanu. `--offline --no-probe` służy odczytowi
bez modeli, aplikacji i lokalnych sond wersji.
Szczegóły: [Helix New](../new/README.md).
