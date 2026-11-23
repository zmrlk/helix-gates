# Narzędzia zarządzane przez Helixa

`helix tools plan` pokazuje cały rejestr GROUPS: deklarowane możliwości,
istniejący runner/parser, program znaleziony na PATH i osobno zweryfikowaną
instalację zarządzaną. Plan nie wykonuje programu, nie odczytuje konfiguracji
ani node_modules celu i nie instaluje zależności. Obecność pliku na PATH
nie potwierdza jego wersji ani działania.

```sh
helix tools plan --json
helix tools plan --tool ast-grep --tool knip --out /tmp/helix-tools-plan
helix tools install --yes --tool ast-grep --tool knip --tool jscpd --tool squawk --tool mutmut --out /tmp/helix-tools-install
```

`--tool` można powtarzać. Bez filtra plan obejmuje cały rejestr, a install
zamkniętą listę pięciu obsługiwanych narzędzi. Inne narzędzie nie otrzymuje
przypadkowego instalatora. `--yes` jest konieczne; offline install odmawia
przed pobieraniem i zapisami. Do odczytu istniejących instalacji służy plan.
`--out` wskazuje katalog poza celem; raport ma nazwę `tools-plan.json` albo
`tools-install.json`. Istniejący raport i dowiązania nie są nadpisywane.

Instalacja używa wyłącznie `~/.local/share/helix/tools`, osobnych środowisk
i przypiętych głównych pakietów:

| Narzędzie | Pin | Kanał |
| --- | --- | --- |
| ast-grep | `@ast-grep/cli@0.51.0` | npm w osobnym prefiksie |
| Knip | `knip@6.43.0` | npm w osobnym prefiksie |
| jscpd | `jscpd==5.4.2` | wheel w osobnym venv |
| Squawk | `squawk-cli==2.70.0` | wheel w osobnym venv |
| mutmut | `mutmut==3.8.0` | wheel w osobnym venv |

Nie zmienia globalnego npm/pip, PATH ani repo celu. Nie instaluje Node,
Pythona, kompilatora ani narzędzia zastępczego, gdy środowisko nie pasuje.
Stryker wymaga osobnego przypiętego runnera w kopii projektu i nie należy do
tej listy. svelte-check, tsc i eslint pozostają w precheck projektu.
[Licencje i przypięte źródła](../THIRD_PARTY_NOTICES.md#optional-managed-tools).

Każda nowa instalacja powstaje pod własnym identyfikatorem. Po odczycie
wersji i wykonaniu małego własnego przykładu Helixa atomowo zmienia aktywny
receipt; nie przenosi venv ani nie zastępuje poprzedniej działającej wersji
przed sukcesem. Przerwanie sprząta wyłącznie własny nieaktywny katalog
i procesy. Blokada chroni przed równoległymi instalacjami.

Sondę npm i jego polecenia uruchamia jawnie przez wybrany Node. Konfiguracje
user/global npm to dwa różne własne puste pliki; wskazanie obu na ten sam
plik może zatrzymać npm przed rozpoczęciem instalacji.

Dla mutmut instalator wybiera istniejący CPython w kolejności
`python3.12`, `python3.13`, `python3.11`, `python3.10`, potem `python3`
tylko jeśli odpowiada jednej z tych wersji. Raport zachowuje odrzucone
kandydatury, wybór i rzeczywistą wersję. Jest to zakres tego przypiętego
instalatora, a nie twierdzenie o braku wsparcia upstream dla innych wersji.
Nie pobiera interpretera i nie zmienia wyboru po błędzie rozwiązywania wheels.
Dostępność wheels oraz działanie mutmut potwierdza dopiero wykonana próba.

Instalator czyta zatwierdzone [piny z repozytorium](../data/tool-pins/README.md).
Obecnie obsługiwany zestaw to Darwin arm64, wheels dla CPython 3.12.
Dla jscpd/Squawk preferuje istniejący python3.12. Pozostałe platformy i ABI
bez pinu odmawiają instalacji (`APPROVED_PIN_MISSING`), bez kompilacji i TOFU.
Każde koło, także przechodnie, wymaga tego samego wcześniej zapisanego SHA-256
przy download i install z `--require-hashes --only-binary=:all:`. Lock nie powstaje
z pobranych właśnie bajtów. npm otrzymuje niezmieniony zatwierdzony lock;
instalator sprawdza SRI wszystkich tarballi, napełnia prywatny cache i wykonuje
`npm ci --offline --ignore-scripts`. Nie uruchamia żadnego postinstall.
ast-grep uruchamia się bezpośrednio z natywnego pakietu po porównaniu SHA-256.

Runtime wybiera z absolutnych lokalizacji systemowych, Homebrew i znanych
katalogów menedżerów fnm/nvm/asdf/mise/volta/pyenv/uv. Ścieżki wewnątrz repo
lub cwd, obcy właściciel i zapis dla innych są odrzucane. Na macOS dopuszcza
zapis grupowy admin/wheel/staff tylko dla grupy, do której należy użytkownik;
paragon zachowuje tę obserwację oraz ścieżkę, wersję, SHA-256 i tryb pliku.

Drzewo jest hashowane przed sondami pakietu i smoke, potem porównywane bez
pomijania zależności. Zmiana daje `INSTALLED_TREE_CHANGED`, bez aktywacji.
Receipt zachowuje wcześniejszy obraz i hash pinu; stare receipts bez tej polityki
są nieważne. To kontrola integralności, nie sandbox systemowy: zmienne offline
nie odcinają samodzielnie sieci ani zapisu procesu poza prefiksem. Zatwierdzony
kod pakietów nadal wykonuje się z uprawnieniami użytkownika.

Plan i raport właściciela zachowują osobno brak programu, brak runnera,
niezweryfikowaną zgodność adaptera oraz niewykonany skan. Luka
„zadeklarowane, nieuruchomione: brak narzędzia w sprawdzonych lokalizacjach”
nie jest wynikiem czystego skanu. Narzędzie zarządzane może być dostępne,
choć celowo nie ma go na PATH. Smoke instalatora dotyczy wyłącznie własnego
przykładu Helixa; nie przyznaje punktów za test projektu. Plan całego katalogu
nie przesądza, że każde narzędzie ma zastosowanie do danego repo.

Zarządzany ast-grep jest używany przez review deep i plan ryzyka security deep
zgodnie z [kontraktem AST](security-ast.md). Pozostałe nowe piny mają osobne
kroki kalibracji oraz integracji ze scan. `VERIFIED` instalacji i `UNVERIFIED` adaptera mogą
występować razem. Brak rzeczywistej instalacji pozostaje NOT_RUN; receipt
wytworzony przez atrapę testową ma `usable=false`.

## Diagnoza nieudanej instalacji

Błąd zachowuje etap, kod wyjścia, polecenie i krótki zredagowany ogon
stdout/stderr. Dane uwierzytelnienia, prywatne wartości i nieopisane fragmenty
są pomijane; ścieżki domowe mają postać `~`, a własny katalog roboczy
`<install>`. Znane komunikaty npm/pip o konfiguracji, brakującym programie
lub wheels pozostają czytelne. To diagnostyka awarii, nie dowód udanej
instalacji. Brak wyjścia procesu jest odróżniony od kodu wyjścia 0.

Test Squawk używa dwóch małych migracji z kluczem głównym: niepożądany
`varchar` i poprawiony `text`. Dodatni przykład musi wykazać konkretną
regułę, ujemny nie może zwrócić żadnych diagnostyk. Inny błąd w przykładzie
kontrolnym nie jest podstawą do zaakceptowania instalacji.

Obie migracje używają `CREATE TABLE IF NOT EXISTS`, aby kontrola odporności
instrukcji nie zasłaniała kontrolowanej różnicy typów. Knip 6 zapisuje pliki
w grupach `issues[].files`; własny test wymaga znalezienia wskazanego
nieużywanego pliku oraz braku tej diagnozy po usunięciu kontrolnego pliku. Kod wyjścia 1
przy znalezisku nie jest sam w sobie awarią procesu.

Sonda mutmut odczytuje wersję z metadanych przypiętej dystrybucji, a następnie
sprawdza polecenia we własnym kompletnym projekcie syntetycznym. Sam import
CLI mutmut może wymagać konfiguracji źródeł, zanim obsłuży `--version`.
Metadane pakietu nie zastępują testu działania polecenia i mutacji.
