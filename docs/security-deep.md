# Statyczny przegląd deep

```sh
helix review deep /path/to/repo --out /tmp/review-output
helix review deep /path/to/repo --format markdown
helix review deep /path/to/repo --advisories /tmp/advisories.json --gitleaks-report /tmp/redacted-scan.json
```

Komenda działa bez `helix.json`, agentów, instalacji, sieci i uruchamiania
analizowanego kodu. Nie zmienia repo. `--out` musi być poza repo i nie może być
jego przodkiem. Zapisuje `review-deep.json` i polski `review-deep.md`.
Istniejące `helix security deep` i `helix ui deep` zachowują swoje znaczenie.
Schema: `schemas/review_deep.json`.

Framework `bin/helix_lenses.py` łączy dziewięć soczewek: Security, Senior developer,
Architect, QA, Product/Project manager, Ops/Data, Tech writer oraz istniejące
UX/UI designer. Każda ma checklistę, findings, liczniki dowodów i adversarial pass. Pole score zachowano dla zgodności API. Wiodąca
lista jest sortowana critical → info i deduplikowana po regule, pliku i linii;
różne problemy na tej samej linii pozostają osobnymi findings. Powtórzone dowody
mają maksymalnie trzy przykłady i licznik. Pełne inwentarze są dostępne w JSON.

Każdy finding zawiera severity, confidence, plik, linię, uzasadnienie, sugerowaną
poprawkę i lokalizacje dowodów. `confirmed` dotyczy wyłącznie potwierdzonego faktu
statycznego, nie zachowania produkcji. Markdown oznacza je VERIFIED; pozostałe
jako ASSUMPTION. Pusty wynik nie jest certyfikatem bezpieczeństwa. Markdown
pokazuje zakres, kandydatów, niezależne potwierdzenia i braki dowodów zamiast
arytmetycznej oceny. Aktywny kod, dokumentacja, starsze warianty i testy mają
osobne liczniki oraz oznaczenia. Wiodąca lista dotyczy aktywnego kodu.

## Zakres Security

- Inwentarz handlerów SvelteKit (`+server`, `+page.server`, hooks), Next app/pages
  API i middleware, Nuxt `defineEventHandler`, Express/Fastify/Hono oraz podstawowych
  dekoratorów Python i Go `HandleFunc`. Guard i rola są rozpoznawane lokalnie;
  brak guarda daje `unknown`, nie dowód publicznej dostępności.
- Brak lokalnego guarda, dostęp do danych przed guardem, ID obiektu bez lokalnego
  owner/tenant/org/user scope, mass assignment, pola roli z inputu, fail-open i
  przełączniki auth developerskie. Deklaracje SQL GRANT/RLS oraz role tras tworzą
  inwentarz RBAC. `SECURITY DEFINER` wymaga jawnego `SET search_path`.
- Dynamiczne SQL, HTML sinks trzech frameworków, ścieżki, shell, przekierowania,
  Host i SSRF; podstawowy ślad jednokrokowego aliasu inputu. Upload wymaga dowodu
  zarówno limitu rozmiaru, jak i sprawdzenia typu. PIN/OTP bez lokalnych dowodów
  ochrony generuje sygnał do ręcznej weryfikacji.
- Raporty Markdown: identyfikator, tytuł, deklarowane severity/status. Typ problemu (np. SQL injection, XSS, IDOR) lub jawny identyfikator
  reguły jest korelowany z nadal wykrytym wzorcem (`open`). Rozpoznany typ i
  wskazane, przeskanowane pliki bez wzorca dają `likely-fixed` z lokalizacją
  dowodu: to heurystyka, nie potwierdzenie naprawy. Brak typu lub dostępnego
  pliku daje `unknown`; deklarowany status nie jest dowodem.

To ograniczony analizator leksykalny, nie pełny interproceduralny taint engine.
Nie rozwiązuje globalnego middleware, dowolnych aliasów routera, dynamicznego
SQL/RLS, delegowanej autoryzacji ani osiągalności bypassu w produkcji. Obecność
słowa owner/tenant nie dowodzi skutecznego scopingu. Nie mierzy entropii OTP ani
rzeczywistego lockoutu. Wzorce wymagają krytycznego przeglądu kontekstu.

## Audyty offline i ochrona sekretów

Domyślnie oba audyty mają `unknown`. Komenda nie otwiera plików sekretów ani `.git`,
nie uruchamia gitleaks/Semgrep i nie wysyła danych do providerów. Skaner stdlib
jest samodzielnym fallbackiem niezależnie od obecności Semgrep. Przygotowany poza
komendą wynik gitleaks można przekazać jako **zredagowane metadane**, bez Secret,
Match, commit message ani fragmentów kodu:

```json
{"redacted": true, "findings": [{"file": "src/config.ts", "line": 12, "scope": "history"}]}
```

`scope` może mieć wartość `directory` lub `history`. Import nie odczytuje wskazanych
plików; raportuje wyłącznie bezpieczne lokalizacje. Surowy format gitleaks jest
odrzucany. Nieznane dodatkowe pola nie są kopiowane do wyjścia. Nie wolno przekazywać
surowych sekretów w tym pliku.

Lokalna baza advisories używa list **dokładnych wersji**, np.:

```json
{"advisories": [{"id": "LOCAL-001", "package": "example-lib", "versions": ["1.0.0"], "severity": "high"}]}
```

Obsługiwane są główne `package-lock.json` (v1/v2/v3), podstawowe wpisy
`pnpm-lock.yaml`, `yarn.lock` i przypięcia `requirements.txt`. Zakresy wersji,
locki binarne, rozwiązywanie zależności i pobieranie bazy nie są obsługiwane.
`checked` oznacza wyłącznie dopasowanie do dostarczonej bazy, nigdy aktualność
bazy ani brak innych podatności.

## Pozostałe soczewki

Senior developer wskazuje puste catch/except, gałęzie `if(false)` i powielone
bloki ośmiu linii. Architect analizuje głębokie importy oraz cykle lokalnych
importów (do 2000 odwiedzonych węzłów na krawędź). QA sprawdza obecność testów
przy handlerach i stałe oczekiwania w testach. PM wskazuje TODO/FIXME i
NotImplementedError. Ops/Data wskazuje destrukcyjne migracje i wrażliwe logi.
Tech writer sprawdza lokalne odnośniki. Te heurystyki nie potwierdzają kompletności
wymagań, backupów, skalowalności ani pokrycia testowego. UX/UI zachowują istniejące
reguły i ograniczenia `helix_ui_deep.py`.

Inwentarz pomija symlinki, ukryte katalogi, zależności, wygenerowane katalogi,
pliki nazwane secret/credential/private. Dopuszczony tekst jest czytany w całości,
bez limitu 1 MB; aktualny manifest pełnego odczytu jest w `source_coverage`. Testy są odczytywane tylko
na potrzeby soczewki QA. Manifest syntetycznych przypadków i pomiar jakości:
[security-deep-precision.md](security-deep-precision.md).

## Kalibracja raportu i pokrycia

Markdown otwiera maksymalnie 10 najpoważniejszych sygnałów, potem pokazuje
pokrycie i wszystkie soczewki. Pełna lista pozostaje w JSON i sekcjach soczewek.
`coverage` zawiera manifest każdego enumerowanego pliku, powód pominięcia,
wykluczone poddrzewa z liczbą potomków `null`, liczbę wykrytych handlerów oraz
pliki SQL. Liczba plików nie obejmuje potomków wykluczonych poddrzew. Nieznany
lub dynamiczny dispatch ma jawnie nieznaną liczbę pominiętych handlerów.
Kandydaci tras obejmują też helpery: brak wykrytego handlera nie oznacza braku analizy.
SQL jest kandydatem migracji, nie dowodem wykonania. Testy obok źródeł są
czytane przez QA, nie traktowane jako wykonywalne trasy Security.

`SEC-OBJECT-CALL` wskazuje delegowany odczyt identyfikatora z trasy bez
rozpoznanego lokalnego guarda zakresu. Ma confidence `possible`; trzeba
przeczytać helper i middleware. Importy `type` nie tworzą cykli wykonania.
Regex `.exec` i lokalna deklaracja funkcji `exec` nie dowodzą uruchomienia
powłoki. Jawnie ukryty honeypot poza tab order nie wymaga etykiety użytkownika.

`DEV-ASYNC-FOREACH` wskazuje nazwaną async function lub inline async callback
(strzałkowy albo function) przekazany do forEach,
który odrzuca zwrócone Promise. Confidence possible wymaga przeglądu
zakończenia, błędów i wspólnego stanu; celowa równoległość nie jest błędem.

Parametryzowany tagged SQL (`sql`/`tx`, także z typami TS) jest uwzględniany
przy sygnałach IDOR. Nie jest przez to klasyfikowany jako SQL injection.
Rozpoznany lokalny scope w WHERE lub jawny checkOwnership/checkTenant ogranicza
sygnał, ale leksykalna obecność tych elementów nie dowodzi skutecznej ochrony.
Niestandardowa nazwa guarda nie wycisza analizy zakresu. Delegowane odczyty
obejmują params, event.params, req.params i request.params.

Rekonsyliacja: SEC-IDOR śledzi proste aliasy tagów SQL `sql`/`tx`, także przez rzutowanie TypeScript. Nadal jest to sygnał `possible`, nie dowód braku autoryzacji; dynamiczne aliasy i shadowing wymagają ręcznego przeglądu.

## Security deep z modelami: plan ról i wznowienie

`helix security deep` jest osobnym przeglądem źródeł z modelami. Korzysta z
planu ról i zapisanych wyników `helix providers --refresh`. Sprawdzenie
availability musi potwierdzać dokładną parę provider/model odpowiedzią JSON
z ostatnich 30 minut. Sam plan, obecność programu lub wcześniejszy cache nie
stanowią dowodu dostępności. `--plan` działa offline, nie wywołuje providerów
i zapisuje także brakujące role jako `LIMITED`.

Hunter może użyć każdego automatycznego providera JSON: `codex`, `claude`,
`claude-via-agy`, `gemini`, `gemini-flash`, `grok-cli`. Weryfikator musi pochodzić
z innej rodziny. Aliasy Claude mają rodzinę Anthropic, Gemini ma Google,
Codex ma OpenAI, a Grok ma xAI. Ręczny handoff `grok` nie spełnia tego kontraktu.

Jawne `--hunter` i `--verifier` mają pierwszeństwo przed konfiguracją providerów.
Konkretny model pochodzi z `models` w `helix.json`; jawna lista modeli przypina
pierwszy model. Niedostępny jawny wybór pozostaje w raporcie, a alternatywy są
wyłącznie propozycjami. Automatyczny plan może wybrać świeżo sprawdzony model,
ale błąd wykonania nigdy nie przełącza providera ani modelu. Po nieudanej
odpowiedzi obowiązuje zwykły błąd przebiegu; poprawa schematu używa tego samego
modelu. Brak świeżej dostępności na początku przebiegu lub drugiej rodziny daje
`limited`, kod wyjścia 3 i jawne jednostki `not_checked`. Model dopuszczony
na podstawie świeżego dowodu może kontynuować zadania po upływie 30 minut
w tym samym przebiegu. Udana odpowiedź odświeża wyłącznie jego lokalny dowód;
błąd po wygaśnięciu dostępności daje `limited`, bez automatycznej zamiany.
Pierwotne dowody są zachowane w `admission_proofs`, a udane odpowiedzi
w `availability_receipts`; nie ma ukrytych sond ani zapisów do globalnego cache.

`run-metadata.json`, `cost-plan.json` i checkpoint zachowują `role_plan` oraz
dokładne przypisania ról. `--resume` odtwarza te przypisania i ponownie sprawdza
ich dostępność, bez automatycznej zamiany. Pusty plan wykonany offline może
uzyskać brakujące przypisania po odświeżeniu providerów, dopóki nie wykonano
żadnej próby modelu. Zmiana źródeł, jawnej konfiguracji lub przypisanego modelu
wymaga nowego przebiegu. Klucze cache obejmują prompt, wersję Helixa i vendora,
źródła, wspólny kontekst autoryzacji oraz dokładne przypisania modeli;
weryfikacja kandydata nadal odbywa się niezależnie w każdym nowym przebiegu.

Hunter z nieznanym modelem domyślnym (`null`/`default`) nie korzysta z cache,
ponieważ klucz nie mógłby przypiąć faktycznej wersji modelu.

## Zasoby, kolejka i przerwanie

Deep sprawdza lokalne zasoby przed pierwszą partią, przed kolejnymi partiami
oraz przed weryfikacją kandydata. `high` zmniejsza liczbę równoległych zadań,
a `critical` wstrzymuje nowe zadania. Już dopuszczone zadania kończą się, a ich
wyniki trafiają do checkpointu w kolejności partii. Po odzyskaniu zasobów
przebieg wznawia się automatycznie. Oczekiwanie jest komunikowane co zmianę
stanu i co 30 sekund; sprawdzenie ponawia się domyślnie co 5 sekund.

`resources.max_pause_s` ma domyślnie wartość 300. Po jej przekroczeniu raport
ma stan `resource_paused`, a niewykonane jednostki pozostają `not_checked`.
`--resume KATALOG` kontynuuje zapisany przebieg po odzyskaniu zasobów; można
zwiększyć limit pauzy w konfiguracji. Pauza zużywa wspólny budżet czasu,
więc wyczerpanie `--budget time=...` daje `budget_exhausted`. Konfiguracja
przeglądu zachowuje requested jobs, a raport zapisuje bieżące effective jobs,
progi, pomiary i decyzje. Dynamiczne decyzje nie unieważniają modelowego
cache ani checkpointu źródeł. Polityka zasobów jest pomijana w odcisku
konfiguracji przebiegu, lecz edycja pliku konfiguracji wewnątrz analizowanego
repo nadal stanowi zmianę źródeł. Do niezależnej zmiany polityki można użyć
konfiguracji zewnętrznej przekazanej przez `--config`.

Rezerwacja wywołania odbywa się przed przekazaniem zadania do workera. Dlatego
`--jobs 3 --budget calls=1` rozpoczyna partię 0 o najwyższym priorytecie.
Limit czasu jest sprawdzany również przed odczytem i przyjęciem wyniku cache.
Równoległe przebiegi aktualizują wspólny indeks w blokowanej transakcji;
atomowy zapis samego JSON nie zastępuje blokady odczytu i scalania.

UX używa tego samego monitora przed etapami i przy dopuszczaniu jednostek
Playwright, eksploratora oraz sędziego. `scan.json`, `flows.json` i raport
zachowują ukończone jednostki i listę `not_checked`; pauza nigdy nie daje PASS.
Po limicie pauzy można ponowić `helix ux all --out KATALOG`, co ponownie
sprawdzi aplikację. UX nie traktuje starych wyników przeglądarki jako cache
niezmienionego stanu aplikacji. Automatyczne wznowienie przed limitem pauzy
odbywa się w tej samej komendzie bez powtarzania ukończonych jednostek.

Budżet czasu jest kooperatywny na granicach etapów. Wywołania modeli
otrzymują pozostały czas, a timeout lokalnego walidatora Node wynosi minimum
z 30 sekund i pozostałego budżetu. Dotyczy to również walidacji cache.
Wyczerpany czas zatrzymuje przebieg przed kolejną poprawą schematu, zachowując
checkpoint do wznowienia. Bez limitu czasu walidator zachowuje timeout 30 sekund.
To nie jest twardy wyłącznik wall-clock całego procesu: obsługa timeoutu i zapis
wyników mogą wymagać dodatkowego czasu.

Runner UX zamyka w `finally` wyłącznie przeglądarki uruchomione przez dany
przebieg, również po błędzie launch, skanowania lub checkpointu. Ukończone
jednostki są zachowane, a artefakt ma stan `error`, jeśli możliwy jest zapis.
Błąd zapisu nie zastępuje pierwotnej przyczyny awarii i nie omija cleanup.

Nieudane ponowienie UX do tego samego katalogu zastępuje wcześniejszy końcowy
PASS raportem częściowym. Raport oraz `ux-latest.json` są oznaczane jako
nieukończona bieżąca próba przed startem runnera, również na wypadek przerwania
procesu bez obsługi wyjątku. `previous_attempt` zachowuje metadane poprzedniej
próby, a `stale_inputs` wskazuje nieodświeżone pliki wejściowe. Nie są dowodem
wykonania ani powodzenia aktualnego przebiegu: raport pomija je w licznikach,
pokryciu i bieżącym provenance, zachowując odnośniki w `historical_sources`.
Dotyczy to także pauzy zasobów przed uruchomieniem pierwszego etapu.
Po udanym wykonaniu również pomijane są stare wyniki niewykonanych etapów.
Samo `ux report` ma zakres `historical_artifact_aggregation`: może podsumować
zapisane wyniki, lecz nie przedstawia ich modeli ani przeglądarek jako
wywołanych podczas generowania raportu.
Przyczyna awarii zawiera etap, typ błędu
i zredagowaną kategorię lub kod wyjścia; zwykłe błędy runnera nie są ukrywane
pod wynikiem PASS. Timeout procesu i błąd jego uruchomienia zapisują raport
częściowy bez kopiowania argumentów polecenia ani stdout do diagnostyki.
