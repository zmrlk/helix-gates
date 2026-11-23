# Sprawdzian ogólności

REQ-X-75/76: deklaracje i reguły pochodzą z repozytorium albo jawnej konfiguracji projektu. Nazwa klienta ani funkcji nie jest dowodem semantyki.

Sprawdzian z 26.10.2026 używa `helix --repo TARGET --offline --state-dir EXTERNAL/state env --no-probe --out EXTERNAL/env` oraz `new audit --no-probe --out EXTERNAL/audit`. Polecenia nie uruchamiają aplikacji, baz ani modeli. Wersje produkcyjne pozostają nieznane bez osobnych dowodów.

Wyniki i porównanie odczytowych snapshotów celu: zewnętrzny raport (nieudostępniony). Kod bazowy: 2b692d0. `rc3` środowiska może oznaczać niepełny odczyt, a `rc124` przerwanie po 900 sekundach; żaden z nich nie jest zaliczonym sprawdzianem.

## Przyczyny ogólne

- G1: prywatny stan agentów (`.claude`, `.codex`, `.agents`) i przechowywane tam kopie robocze muszą być pomijane przez skanery Git i systemu plików. Polityka jest wspólna, bez nazw projektów. Pominięcia pozostają widoczne w pokryciu odczytu.
- G2: env rozdziela SDK (`global.json`), .NET runtime, .NET Framework i .NET Standard z projektów C#/F#/VB. TFM są alternatywami kompilacji, nie pinem produkcji; brak/zmienna MSBuild pozostaje jawnym nieznanym. Części i pokrycie kodu rozpoznają manifesty i rozszerzenia .NET. Po zgodzie z26.10 katalog `new audit` obejmuje C#/F#/VB, MJS/CJS/MTS/CTS i Svelte/Vue/HTML/CSS oraz manifesty .NET; wspólne rozszerzenia .NET pochodzą z helix_dotnet.
- G3: nazwy guardów nie mają domyślnego znaczenia. Wnioskowanie z ciała funkcji pozostaje aktywne; nieprzezroczyste API wymaga jawnego kontraktu `static_security`. Każdy wynik nadal jest kandydatem, bez potwierdzenia autoryzacji produkcyjnej.
- G4: porównywane są unikalne nazwy kluczy, a ostrzeżenie jest zbiorcze dla jednej pisowni w pliku. 30 tys. powtarzanych pól ma test z limitem10s; pełny odczyt jest zachowany. Pozostały dług: porównanie bardzo dużej liczby różnych nazw nadal ma koszt kwadratowy względem liczby unikalnych nazw, a zakresy obiektów JSON są heurystyką.

Rejestr integracji i strategie runtime są scalone w integracji; konkretne braki parsera bazy i odbioru zapisano w tabeli zewnętrznej. Seria dziewięciu repo pochodzi sprzed scalenia i nie potwierdza działania nowego rejestru na tych projektach.

.NET: nie wykonujemy MSBuild ani importów `Directory.Build.props/targets`; projekt bez lokalnego TFM ma jawny brak. Nie potwierdzamy zgodności SDK z TFM ani uruchomienia serwisu. Testy syntetyczne obejmują SDK, wiele TFM, starszy namespace XML, nierozpoznaną deklarację i osobne części monorepo.

G5: lokalizacje sygnałów checklisty są liczone przyrostowo między kolejnymi trafieniami. Powtórzenia na tej samej linii dają jeden odnośnik; wszystkie różne linie pozostają. Test zachowuje dowód ostatniej z50tys. linii oraz score0/not-run. To naprawa drugiego miejsca kosztu kwadratowego ujawnionego przez pełny audyt projektu D.

## Jawne kontrakty guardów

Przykład w `helix.json` albo zewnętrznym `--config`:

```json
{"static_security": {
  "record_context_guards": ["enforceRecordAccess"],
  "identity_guards": ["assertSignedIn"],
  "middleware_factories": ["signedInMiddleware"],
  "scope_guards": ["assertRecordOwner"]
}}
```

Wszystkie listy są domyślnie puste. `record_context_guards` deklaruje wymuszający, awaitowany kontrakt czterech argumentów: principal, operacja, rodzaj zasobu, obiekt kontekstu rekordu. AST nadal wymaga tego samego rekordu, kolejności i braku przesłonięcia symbolu. `identity_guards` oznacza synchroniczną odmowę przez throw, nie zwrócony boolean/Response ani porzuconą obietnicę. `middleware_factories` deklaruje fabrykę egzekwującego middleware. `scope_guards` jest wyłącznie wskazówką starego skanera leksykalnego; nie omija kontroli AST ani niezależnej weryfikacji.

Kontrakt jest deklaracją projektu, którą trzeba sprawdzić względem implementacji. Importowane aliasy/dynamiczne API poza rozpoznanymi relacjami pozostają nieznane; nie dodajemy globalnych wyjątków nazw. Starsze syntetyczne testy zachowały oczekiwania dla jawnie zadeklarowanego API; nowe kontrole sprawdzają również pustą konfigurację i zmianę nazw. Historyczny benchmark projektu A nie stanowi pomiaru tego nowszego trybu domyślnie nieufnego.

G6: mapa wskazówek importów używa AST Pythona (moduł `from`, nie importowany symbol) oraz tokenów JS/TS z pominięciem komentarzy i zwykłych literałów. Nieobsługiwana składnia i ograniczenia JS/TS trafiają do `system_map.unresolved`. To nadal hipotezy zależności, nie potwierdzone usługi ani topologia runtime. Dynamiczne wyrażenia, template expressions, regex literals i przesłonięcie require pozostają długiem; nie wykonujemy kodu, by je rozwiązać.

G7: wpisy dokumentacji bez rozpoznanej klasy usterki pozostają unknown bez przeszukiwania wszystkich ścieżek repozytorium. Zachowano wcześniejsze łączenie prawdziwych klas usterek z dowodami źródłowymi. Test obejmuje4000 plików i500 niepowiązanych wpisów. Koszt wielu rzeczywiście sklasyfikowanych zgłoszeń nadal zależy od wielkości repo — jawny dług, bez nowych heurystyk naprawy.

## Wynik wykonania

18 poleceń bazowych i rozliczone powtórzenia: najnowszy env 5 rc0 / 4 INCOMPLETE, audit 7 rc0 / 2 timeouty900s. Przerwane audyty projektów D i E zachowały czytelne częściowe audit.json; nie zaliczamy całej komendy. W projektu D pozostało ponowne AST podczas planowania propozycji; w projektu E odrębny skan integracji runtime. Zamiast wyjątków nazw projektów potrzebne współdzielenie snapshotu/wyników i polityki zakresu.

G2 katalog new audit: wdrożony po zniesieniu zakazu edycji. Rzeczywisty publiczny audit na syntetycznym repo sprawdza języki, manifesty, zero modeli/aplikacji/baz i brak zmian plików celu. Test katalogu1 + test_new50 + test_audit_discovery20 =71 PASS. Tabela dziewięciu repo zachowuje wyniki sprzed tej ostatniej poprawki; nie wykonano nowej kosztownej serii. Timeouty projektów D/E pozostają jawnym długiem zgodnie z dopiskiem użytkownika. NuGet, błędna wersja5432 i kopie agentów w odrębnym detektorze runtime są zgłoszone w tabeli dla sesji runtime, bez dublowania jej implementacji.
