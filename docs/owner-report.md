# Raport właściciela z istniejących dowodów

`owner-report` agreguje raporty bez uruchamiania skanerów, modeli i kodu projektu.
Nie wymaga `owner-input.json`, pliku `helix.json` ani repozytorium Git w katalogu
źródeł dowodów. Wynik to czytelny Markdown oraz towarzyszący JSON ze wszystkimi
ustaleniami, miejscami i odciskami odczytanych artefaktów.

```sh
bin/helix --repo /project owner-report --evidence /audits/run-1 --out /audits/owner.md
bin/helix --repo /project --state-dir /audits/state owner-report --out /audits/owner.md
```

`--evidence` można podać kilka razy. Bez tej opcji używane są katalogi
`evidence` i `runs` z `--state-dir`, a bez zewnętrznego stanu `helix-evidence`
projektu. Znane nazwy raportów są odczytywane rekursywnie; katalogi zależności,
cache, logi i dowiązania nie są przeszukiwane. Niepoprawny rozpoznany raport daje
jawną lukę. Pliki kodu i dowolne pliki JSON nie są wejściem agregatora.

Każdy katalog przebiegu pozostaje osobną grupą, wraz z deklarowaną rewizją
źródła, narzędziami, weryfikacją, pokryciem, stanem bramki i pomiarem kosztu.
Brak rewizji i konflikt rewizji są jawne. Luźny werdykt z innego przebiegu nie
promuje kandydata do potwierdzonego ustalenia. Koszt nieznany nie jest zerem,
a limit i plan wywołań nie oznaczają kosztu poniesionego.

Aktywny kod, dokumentacja, starsze warianty i testy mają oddzielne liczniki.
Raport nie zastępuje ich arbitralną oceną punktową. `AGGREGATED` oraz kod 0
potwierdzają utworzenie zestawienia, także wtedy, gdy zawiera ono bramkę FAIL
lub ERROR. Brak jakichkolwiek rozpoznanych artefaktów daje `INCOMPLETE` i kod 2.
Zawsze należy czytać wyniki bramek i jawne luki wewnątrz raportu.

Jawne `--input helix-contracts.json` zachowuje dotychczasowy tryb walidacji
kontraktu. Przy nieaktywnej polityce ciągłości nie wywołuje kontroli Git.
