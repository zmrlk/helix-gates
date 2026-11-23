# Ledger wymagań

Kanon: `requirements/ledger.json`. Udostępniona kopia zawiera trzy przykładowe REQ; własne wymagania projektu dopisujesz przez `helix requirements add`.
JSON działa bez PyYAML. Schemat: `schemas/requirements-ledger.schema.json`;
walidator stdlib wykonuje używany podzbiór JSON Schema i reguły semantyczne.
Źródła/cytaty przeniesiono z dostarczonego REQUIREMENTS.md; nazwy projektów
zamaskowano jako `<projekt-A>` itd., także w ścieżkach. Nie odczytujemy prywatnych
źródeł wskazywanych przez historyczne materiały. Cytaty są dosłowne poza maskowaniem.

```sh
bin/helix requirements check
bin/helix requirements check --run --json
bin/helix requirements check --ledger tests/fixtures/requirements/valid.json --baseline tests/fixtures/requirements/valid.json
bin/helix requirements report > raport-wymagan.md
bin/helix requirements add --group A --text 'Treść wymagania' --source 'docs/owner-statements/001.md:1' --quote 'Dosłowna wypowiedź' --acceptance 'Brak dowodu daje FAIL'
bin/helix requirements check --require-ledger-touch --since HEAD~1
```

`add` nadaje następny numer w grupie, status missing; wymaga cytatu, źródła
i opisu odbioru. Nie zastępuje przeglądu semantycznego właściciela. Każda nowa
normatywna wypowiedź właściciela trafia do ledgeru **w tym samym commicie**.
CI/wrapper powinien uruchamiać ostatnią komendę z zaufanym refem sprzed zmian.
Kontrola bada każdy commit, nie tylko końcowy diff: zmiana `docs/owner-statements`
(pliku, katalogu lub pliku z rozszerzeniem) lub trailer `Owner-Statement:` wymaga
zmiany wskazanego ledgeru w tym commicie. Sprawdza też bieżące zmiany robocze.
Nie rozpoznaje nieoznaczonych wypowiedzi w dowolnych plikach ani ich znaczenia.

`check` odrzuca błędny schemat, duplikaty ID, MUST bez opisu odbioru,
done bez testu i nieistniejące mapowania. AST sprawdza plik, klasę i metodę,
bez importowania kodu. Mapowanie: `tests/test_x.py::Klasa.test_metoda`
(dopuszczalne też `::Klasa::test_metoda`); symlinki i wyjścia poza repo są zabronione.
Wyjście domyślne to tabela; `--json` daje sam JSON, `report` także listę długu MUST.
Kod wyjścia: 0 poprawny kontrakt, 2 błąd/regresja.

Trzy odrębne znaczenia: `covered` liczy REQ z poprawnym mapowaniem, `partial`
obejmuje partial/in-progress, `missing` oznacza brak realizacji. Covered może
przecinać się z partial: test zabezpiecza tylko fragment wymagania. Status done
nie oznacza uruchomienia. Bez `--run`: execution_status=not-run. Pending MUST
pozostają długiem, nie blokują strukturalnego check i nie otrzymują zaliczenia.

`--run` deduplikuje mapowania, uruchamia każdy test unittest osobno, bez shell,
z limitem 120 s i ograniczonym środowiskiem bez dziedziczonych poświadczeń.
FAIL, SKIP, expectedFailure, brak wyniku, discovery=0 i timeout oznaczają regresję
każdego przypisanego REQ. Wyniki w JSON zawierają licznik, exit i status; surowego
stdout testu nie publikujemy. To lokalny executor kodu testów, nie sandbox systemowy;
mapowania muszą przejść przegląd. Unit runtime używa fake executora; nie dowodzi
przebiegu usług na prawdziwym hoście. Check nie instaluje zależności.

Domyślny ratchet porównuje z `requirements/baseline.json`, gdy plik istnieje;
jawne `--baseline` musi wskazywać istniejący plik. Własny ledger wymaga własnego
baseline. Kolejność: missing < in-progress < partial < done. Usunięcie REQ,
spadek statusu lub utrata mapowania wcześniej pokrytego REQ blokuje wynik.
Wyjątek wymaga pola `waiver` z `owner: "Owner"`, niepustym `reason` i datą ISO
`date` (nie przyszłą). Dla usuniętego ID: główne `waivers: {"REQ-X-01": {...}}`.
Walidator sprawdza deklarację właściciela, nie uwierzytelnia jego podpisu.
Agenci nie zatwierdzają waiverów ani zmiany baseline samodzielnie.

Baseline początkowy jest kopią ledgeru do przeglądu właściciela; nie jest zgodą
na historyczny dług. Oceny przeniesione z GAPS są ograniczone zakresem źródła;
fragmenty runtime uaktualniono po odczycie kodu 0.5.x. Jawny pozostały brak:
import raportu runtime nie weryfikuje SHA. Oceny zawierają VERIFIED (odczyt)
i ASSUMPTION (kompletność). Samotest prawdziwego ledgeru jest częścią unittest.
Wartości przypominające klucze/tokeny/hasła są odrzucane bez ich wypisywania;
heurystyka nie gwarantuje wykrycia każdego sekretu.

`add` przyjmuje polskie znaki, przecinki i długie cytaty. Brak lub sam whitespace
w wymaganym polu daje nazwę brakującej opcji, bez zapisu. Historycznego
odrzuconego argv nie dostarczono: jego przyczyna pozostaje ASSUMPTION.

Etap 7: 8 nowych REQ grupy V (215 łącznie). Statusy partial jawnie zachowują
braki adapterów, koordynacji między klonami i starszych formatów raportów.
Kontrola strukturalna nie potwierdza uruchomienia całego pokrycia.

Etap 3: siedem REQ grupy L dotyczących perspektyw, deduplikacji, kalibracji,
wycieków, audit trail i prywatnych ścieżek. Status partial zachowuje brak
wykonania adapterów, pełnego taint i weryfikacji trwałości audytu.

Scalenie S3 z runtime: 255 unikalnych REQ (241 MUST, 14 SHOULD).
Zachowano rekordy obu strumieni bez kolizji ID; kontrola strukturalna
schematu, mapowań AST i baseline przeszła bez wykonania testów (not-run).

Etap 4: 269 REQ (255 MUST, 14 SHOULD). Początkowo 127/242 MUST miało
mapowania; teraz 178/255 (w tym 44 dodatkowe starsze MUST i 7 nowych).
Mapowania wcześniejszych regresji pozostają not-run w tej sesji. Wykonano
wyłącznie 20 testów nowego pliku `test_stage4.py`; wynik OK nie oznacza
wykonania całego ledgera. Naprawiono też mapowanie REQ-R-26 z samego pliku
na trzy konkretne metody. Nie podnoszono statusów przez samo mapowanie.
Baseline zaktualizowano zgodnie z jawnym poleceniem etapu 4, bez waiverów.
Sześć uzasadnionych propozycji rady (W-08–13) pozostaje missing.

Scalenie S4 z runtime: 275 REQ (261 MUST, 14 SHOULD), bez kolizji nowych ID.
Kontrola strukturalna bez uruchamiania testów: FAIL dla REQ-R-27–32,
których odziedziczone mapowania wskazują plik zamiast klasy i metody.
Baseline i statusy pozostawiono bez zmian.
