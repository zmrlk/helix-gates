# 0.9.3-beta — 2026-10-26

## Niewydane

- CI na runnerach macOS GitHuba: globalny sterownik filtra Git (błąd odtworzony lokalnie ze sterownikiem git-lfs), którego nie wskazuje atrybut `filter` żadnej śledzonej ścieżki projektu, nie zostawia już stanu dirty jako nieznanego; Git uruchamia sterownik tylko dla ścieżek z takim atrybutem (`.gitattributes`, `.git/info/attributes`, `core.attributesFile`). Sterownik wskazany atrybutem nadal nie jest uruchamiany, a dirty pozostaje nieznane. `git status` dostaje każdy znany sterownik wyzerowany (`clean`, `smudge`, `process` puste, `required=false`), więc atrybut przypisany po sprawdzeniu też niczego nie uruchomi; ponowne sprawdzenie atrybutów po `status` zostawia wtedy dirty jako nieznane. Te same nadpisania dostają diff integralności, `security deep --since` i diff narzędzi advisory (ten ostatni wcześniej mógł uruchomić filtr repozytorium). Ścieżki z indeksu są czytane bajtowo, bo tryb tekstowy skracał CRLF w nazwie do LF. `bin/ux.cjs` bez Playwrighta udostępnia czyste reguły, a błąd brakującej zależności pojawia się przy pierwszym użyciu przeglądarki (CLI nadal kończy się nim od razu). `run_tests_parallel.py` podaje identyfikatory padających testów (`failed_tests`) zamiast etykiety partii; partia, która padła bez nagłówka unittest, jest nazwana jako partia. `executionTools()` w `ux.cjs` nie zgłasza Playwrighta, którego nie wczytano. Test sond dostawców nie wywołuje już prawdziwych CLI modeli.
- CLI modeli (codex, agy, grok, claude oraz `scripts/review-screenshots.py`) działają bez okna: `open` i `xdg-open` w PATH wskazują na `bin/no-browser`, który odmawia otwarcia, gdy CLI bez zalogowania chce otworzyć logowanie w przeglądarce (nie wysyła sygnałów do procesów). Wcześniej `agy -p` bez logowania otwierał kartę OAuth przy każdej rundzie sond; teraz kończy się błędem logowania po własnym limicie 60 s. CLI, które otwiera adres pełną ścieżką `/usr/bin/open` albo przez LaunchServices, nie jest tym objęte.
- 2026-11-02: `SKILL.md` podzielony na rdzeń (135 linii, ok. 3,6k tokenów, poniżej limitu 5 000 tokenów zachowywanych przez Claude Code po kompaktowaniu) i `references/*.md` (11 plików, treść przeniesiona bez zmian, linki poprawione). `name: helix` zgodnie ze specyfikacją Agent Skills (równa katalogowi). Opis przepisany pod wyzwalanie. Pin `helix_version` bez zmian. Powód: w sesjach po 8 h+ końcówka 590-liniowego skilla (G3, reguły) wypadała po cichu.

Wspólne wydanie po scaleniu etapu 2. Opis możliwości nie zastępuje dowodu wykonania.

Poprawki po niezależnej recenzji: zatwierdzone locki/SRI/SHA-256 dla całych
grafów instalacji Darwin arm64 (wheels CPython 3.12), brak postinstall ast-grep,
kontrola niezmienności drzewa przed/po smoke i zaufane ścieżki runtime.
CI wymaga hashy i gotowych wheels; brak locka platformy zatrzymuje instalację.
Preload normalizuje opcje własnych żądań, transport wymaga wszystkich receipts
`ready`, aliasy cookies zachowują wymagania HTTPS, globstar obejmuje zero
katalogów, a zapis planu ról zachowuje rzeczywiście wybrany model fallbacku.

Druga, niezależna recenzja poprawek (Claude, inna rodzina niż autor): wykluczenia
właściciela działają w obu znaczeniach wzorca (`*.csv` i `dir/*` obejmują też
podkatalogi, folder wykluczony obejmuje zawartość), zaufany obszar menedżerów
wersji wynika z bazy kont, nie z `$HOME`, zapis grupowy runtime tylko dla
`admin`/`wheel` (bez `staff`), a CI uruchamia wyłącznie platformy z
zatwierdzonymi pinami (dziś macOS arm64; Ubuntu po zebraniu pinów Linux).

## Audyt i bezpieczeństwo
- AST przez ast-grep dla AUTH/IDOR/OTP/UPLOAD/MASS; guard wynika z kodu lub jawnego kontraktu projektu. Brak domyślnie zaufanych nazw.
- `helix bench` porównuje wyniki z zewnętrznymi etykietami. Historyczny pomiar 9/9 grup IDOR zachowuje regresję FP i nie opisuje nowego kontraktu guardów.

## Deep
- Plan partii, wspólny budżet czasu/wywołań, `--jobs`, kolejność ryzyka, `--since`, cache i resume. Tryby full/daily/release; niepełny przebieg nie przesuwa znacznika COMPLETE.

## Modele
- Dokładny plan ról z dowodów dostępności i niezależnych rodzin; neutralne sondy równoległe. Brak modelu nie powoduje cichej podmiany.
- `data_egress` wymaga zgody na dostawcę; transport przygotowanych źródeł nadal wstrzymany. Receipts zapisują czas, tokeny i koszt rzeczywistych prób; brak danych to null.

## Środowisko
- `env` rozdziela deklaracje, lokalne wersje i dostarczony dowód produkcyjny. Wspólne provenance zachowuje pochodzenie każdego raportu.
- Rozpoznanie SDK/TFM .NET i katalogu C#/F#/VB oraz JS/TS/UI; bez uruchamiania MSBuild.

## New
- Jedno `new audit` tworzy zewnętrzną propozycję konfiguracji i NEW-REPORT: pin, role, środowisko, UI, runtime i harmonogram deep. Zapis do celu tylko przez jawne `--write`.

## Runtime
- Rejestr 50 dostawców i `runtime.integrations.custom`; strategie http-sink, record-replay, container i disable. Syntetyczne wiersze, callbacki i odpowiedzi określa projekt.
- Lokalny Keycloak, HTTPS, osobne sesje/role i WebAuthn mają plany oraz receipts wykonania. Sinki i zaślepione 2xx nie dowodzą doręczenia ani działania dostawcy.
- PDF/Chromium, TZ i UTC, worker Python oraz backup z licznościami i checksum. Obrazy lokalne z pinami; brak automatycznego pobierania. Transport przechwytu Node/Python, rozpoznanie pakietów także Go/PHP/Ruby.

## Narzędzia
- `tools plan/install`: pięć izolowanych instalacji z pinami i testem działania: ast-grep, Knip, jscpd, Squawk, mutmut. Zizmor sprawdza workflowy CI.
- Analiza duplikatów/migracji i mutacje przyrostowe są advisory. Ponytail 4.9.0 (MIT): rejestr długu i soczewka prostoty z planu ról, bez punktów jakości.

## CI i dowody projektu
- Workflow na platformach z pinami (dziś macOS arm64) z akcjami przypiętymi do SHA, Semgrep taint SvelteKit, zizmor offline/pedantic i szybki pre-push. GitHub Actions pozostaje NOT_RUN w dowodach scalenia.
- `pro-evidence.json`, rezerwacje ID i bramki modułów AI/ręcznych. Testy i CI bez wykonania dają tylko przygotowanie; receipts wiążą SHA, źródła i log.

## Ogólność
- Sprawdzian 9 repo: env 5 rc0 / 4 INCOMPLETE, audit 7 ukończonych / 2 timeouty po 900 s. To seria pomiarów, nie jeden benchmark scalonego HEAD.
- Poprawki wspólnej polityki źródeł, kosztów analizy i importów. NuGet, parser wersji bazy, pełne SDK/kontenery i odbiór runtime projektów pozostają długiem. Szczegóły: [stan etapu 2](docs/stage2-completion.md).

# 0.9.2-beta — 2026-10-25

- Advisory: zarządzane Knip/jscpd/Squawk, mutacje z różnicy, raport owner i soczewka Ponytail z planu ról; bez automatycznego wykonania modeli.

- Reguły AUTH/IDOR/OTP/UPLOAD/MASS korzystają z zarządzanego ast-grep i własnego snapshotu. Analiza wiąże guard z rekordem i upload z konkretnym plikiem, rozpoznaje jawne helpery oraz przekazywanie odmowy middleware; zachowuje wszystkie miejsca agregatu, wersję/parser i fallback o niższej pewności. Brak dopasowania nie zalicza bezpieczeństwa produkcji.

- Druga próba instalacji potwierdziła ast-grep i jscpd. Smoke Knip czyta format v6, kontrola Squawk uwzględnia regułę odporności instrukcji, a mutmut sprawdza wersję i działanie we własnym skonfigurowanym projekcie. Niepełne statystyki lub mutant bez testów nie aktywują instalacji; diagnostyka zachowuje bezpieczne liczniki.

- Po rzeczywistej próbie instalacji: npm jest sondowany przez Node z oddzielnymi plikami user/global config; mutmut wybiera istniejący stabilny CPython w jawnej kolejności. Poprawiono kontrolny przykład Squawk i dodano użyteczną zredagowaną diagnostykę polecenia/etapu zamiast samego kodu błędu. Wynik ponownej instalacji pozostaje odrębnym dowodem od testów.

- Tools plan pokazuje cały rejestr, runner, lokalną obecność i osobny dowód instalacji. Jawne install --yes obsługuje pięć przypiętych pakietów w izolowanym katalogu Helixa, z integralnością i własnym testem działania; offline odmawia. Braki narzędzi i runnerów są lukami w raportach, a instalacja nie zalicza skanu klienta.

- Kontrola data_egress obejmuje natywne callery, deep i ręczny eksport: brak zgody daje ERROR przed wysyłką, bez cichego fallbacku. Cache wiąże hash polityki z rzeczywistą rolą/modelem; stała sonda providers ma osobny jednorazowy kontekst. Przeglądy źródeł pozostają przejściowo wstrzymane także po zgodzie, do ukończenia transportu przygotowanych pakietów.

- Dodano czysty kontrakt data_egress: jawne identyfikatory dostawców, wykluczenia, heurystyczną redakcję i manifest ścieżek/hashów NOT_SENT. New zachowuje istniejący config i nie zamienia starej listy ścieżek w zgodę na providera. To przygotowanie pakietu; egzekwowanie przez wszystkie stare transporty pozostaje osobnym krokiem.

- New audit zbiera komentarze Ponytail do wspólnego rejestru długu z sufitem, ścieżką ulepszenia, miejscem i wiekiem ostatniej zmiany linii HEAD. Owner zachowuje wszystkie miejsca i luki, a status odczytuje powiązany zewnętrzny zapis bez skanu i modeli; nieznane lub historyczne dane nie udają bieżącego czystego wyniku. Rejestr nie przyznaje punktów jakości.

- Dodano przypięte teksty reguł Ponytail 4.9.0 review/audit/debt oraz oryginalny MIT LICENSE, pochodzenie i hashe plików. Mały vendor zachowuje zakres autora i oddziela dostarczenie reguł od wykonania przeglądu; modelowa soczewka i rejestr długu mają osobne kroki integracji.

- Runtime dodaje własną skrzynkę i zamknięty katalog operacji wysyłek: Resend, SerwerSMS, PLAY, Meta/TikTok oraz syntetyczny web-push. Adapter Node przekierowuje obsługiwane wywołania do lokalnego odbiornika; luki konfiguracji i transportu pozostają jawne. Raport oraz owner zachowują lokalne przyjęcia i odmowy bez punktów za doręczenie lub trasę; gotowość i żądania kontrolne nie udają wysyłki.

- Runtime wymaga dopuszczenia izolowanych procesów przy instalacji, migracjach, buildzie, starcie i pomiarach. Osobny profil obejmuje własny serwer PostgreSQL; opakowanie klienta nie zalicza serwera. Brak mechanizmu blokuje wykonanie, a raport i owner oddzielają sondę OS, atrapę oraz brak próby. Pierwszy backend macOS zachowuje ograniczony zakres i nie przechodzi na niechroniony proces po odmowie.

- Runtime sprawdza dostępność wymaganych rozszerzeń PostgreSQL przed migracjami każdej własnej bazy i przed restore. Zachowuje deklaracje z liniami, osobne wyniki prób i brakujące pozycje; zły katalog nie daje gotowości. Dostępność nie zalicza instalacji ani działania aplikacji i nie uruchamia automatycznego CREATE EXTENSION.

- Runtime blokuje niezgodną rzeczywistą major PostgreSQL przed migracjami także wtedy, gdy lokalny program deklaruje właściwą wersję. Jawny override zachowuje WARN/DEGRADED; nieznana wersja nie daje zgody na start. Odrzucony własny backend jest sprzątany, a kolejny fallback ma osobny pomiar.

- Runtime wykonuje dodatni przebieg WebAuthn własnym kluczem CDP: rejestrację i logowanie przez UI, przyjęcie przez serwer, odmowę sesji po logout oraz nowe kontrole sesji i GET. Osobny wynik wiąże bieżące plany i próby; owner zachowuje FAIL przy przerwaniu, a brak końcowych dowodów lub cleanup nie daje PASS. Surowe poświadczenia i zdarzenia CDP pozostają prywatne.

- WebAuthn ma jawny plan per część powiązany z rolą, polityką sesji i HTTPS. Zachowuje deklaracje oraz brak przebiegu, wyłączenie i nieznany zakres; owner i Pro nie zaliczają ceremonii na podstawie biblioteki lub profilu urządzenia.

- Ogólny emulator OIDC zachowuje obserwacje nawigacji, ale cookie lub redirect nie zaliczają sesji i uprawnień. Niezweryfikowany storage nie trafia do innych pomiarów ani k6; historyczny auth-flow PASS bez kontraktu jest odrzucany przez import, z konkretną luką w raporcie właściciela.

- Runtime wykonuje jawne kontrole sesji JSON i GET po formularzu Keycloak, z anonimowym porównaniem i osobnym kontekstem każdej roli. Wyniki komórek wiąże z planem i próbą; owner rozdziela wykonany FAIL, niepełny przebieg oraz role poza zadeklarowaną macierzą.

- Jawny plan polityki sesji i tras wiąże role, części i komórki GET z bieżącymi deklaracjami. Plan nie uruchamia aplikacji ani nie przyznaje punktów; publiczne wyniki nie zawierają wartości asercji, a owner i Pro zachowują NOT_RUN oraz nieznane liczniki legacy.

- Keycloak: prywatny adapter formularza planuje osobne konteksty syntetycznych ról i zapisuje fazy OIDC powiązane z planem oraz przebiegiem. Raporty właściciela i import Pro zachowują osobne luki transportu, sesji i uprawnień; obserwacja formularza nie zalicza sesji ani chronionej trasy.

- Plan transportu z pełnego snapshotu rozpoznaje Secure cookies, Keycloak i WebAuthn per część. New audit proponuje HTTPS bez zmiany jawnych ustawień; runtime wiąże publiczny origin przed buildem i IdP, używa własnego CA/SPKI oraz stałego lokalnego proxy bez przepisywania cookies. Brak zaufania k6 i niewykonane logowanie pozostają widocznymi lukami.

- Wspólny lokalny endpoint Docker obsługuje także PostgreSQL, backup i cleanup przy prywatnym HOME. Polecenia silnika mają ograniczone env, a odczyt wersji klienta pozostaje odrębny od dostępności demona i faktycznej wersji bazy.

- Runtime uruchamia rozpoznanego Keycloaka jako własny tymczasowy kontener z lokalnego przypiętego obrazu, syntetycznym realm i jawnym mapowaniem env. Gotowość, cleanup i przerwanie mają receipts; brak usługi nie uruchamia stubu, a readiness nie zalicza logowania ani tras.

- Runtime plan zawiera osobny plan Keycloaka per część: klient aplikacji, callbacki, PKCE, claim i syntetyczne role; braki i konflikty pozostają BLOCKED. READY nie jest dowodem kontenera ani logowania, a prywatny materiał jest odrębny od publicznego planu.

- Runtime plan wykrywa integracje i strategie z podziałem na części i obszary źródeł. Raport, importer Pro i owner zachowują wszystkie luki oraz oddzielają pomiary od pokrycia tras; receipts wiążą plan, przebieg i lokalne artefakty. Readiness nie daje PASS, a FAIL trasy nie znika w agregacji.
- Offline dopuszcza runtime plan/doctor/ci-template; external config wiąże się z --project także spoza repo. Uruchomienia aplikacji i mutacji pozostają jawnie odrębne.

- Wspólny odczyt Git dla provenance, statusu, planu deep i inwentarza blokuje wykonanie filtrów/fsmonitor oraz wpływ GIT_DIR innego repo. Znany SHA zostaje przy nieznanym dirty; cursor COMPLETE wymaga jawnie czystego drzewa, a niebezpieczna różnica kończy się wyjaśnieniem.

- Ręczne recenzje Groka mają osobny request/verdict/receipt per reviewer, checkpoint, rundę i pełny diff; stare wspólne odpowiedzi nie zaliczają dwóch ról. Jawny model pozostaje dokładny, a ręczna deklaracja pochodzenia jest odrębna od sondy. Pełny diff trafia do każdego reviewera, bez cichego limitu 60 tys. znaków; legacy raw i błędne pliki pozostają zachowane.

- Status czyta ostatni COMPLETE bez kontekstu modeli i zapisów, pokazuje zaległe commity oraz zmiany lokalne; brak lub rozbieżny dowód pozostaje nieznany. Jawny post-commit hook tylko przypomina, nie uruchamia skanu ani sieci i nie zastępuje istniejących hooków.

- Budżet deep obejmuje także walidator Node: timeout nie przekracza pozostałego czasu, również przy cache-hit.
- UX domyka własne przeglądarki po błędzie i przed runnerem zapisuje PARTIAL; retry, timeout lub przerwanie nie pozostawiają starego PASS. Historyczne modele, przeglądarki i wyniki nie udają bieżącego wykonania.
- Runtime zwraca 0 tylko dla pełnego PASS, 2 dla pełnego FAIL i 3 dla niepełnego przebiegu. Release/repo-hygiene propagują kod błędu do powłoki zamiast cichego exit 0.

- Providers refresh sonduje modele równolegle (--jobs, domyślnie 3), z neutralnym cwd per próba i trwałym uporządkowanym zapisem. Sonda nie dziedziczy repo ani AGENTS klienta.
- Jawne new init/audit --refresh-providers przygotowuje projekt w jednym kroku; preflight przed sondami, offline odmawia, aktualne availability probes odróżnione od niewykonanej recenzji kodu i cache.

- Wspólny governor zasobów odczytuje load i dostępne pomiary pamięci, obniża jobs przy high i wstrzymuje nowe zadania przy critical; zapisuje decyzje i luki bez ingerencji w cudze procesy.
- Deep, UX, runtime i kolejka szybkich testów respektują dynamiczny limit oraz budżet czasu oczekiwania; niepełne wykonanie nie daje PASS. Parametry eksperymentów obciążeniowych pozostają zachowane.
- Bramka testów wymaga potwierdzenia wszystkich zamówionych test IDs, a nie samego exit 0; przerwany worker bez podsumowania i pusta suita nie są zielone. Skips pozostają osobno widoczne.

- Helix new init/audit przygotowuje zewnętrzną propozycję konfiguracji, pin, zachowane role/modele, UI roots, środowisko/bazę i plan deep z harmonogramem; NEW-REPORT po polsku opisuje także braki dowodów.
- Repo celu pozostaje bez zmian bez jawnego --write; odmowa nadpisania, ochrona ścieżek i osobne metadane planu/wykonania. Offline korzysta tylko z zapisanych sond modeli, brak dowodów daje LIMITED.

- Security deep wykonuje dokładne modele z planu ról, z dowolnym hunterem JSON i niezależnym verifierem; jawne wybory pozostają bez podmiany, brak dowodu daje LIMITED.
- Rodzina wynika także z nazwy modelu, więc alias agy nie pozoruje niezależnego review. Dowody startowe i lokalne odpowiedzi modelu pozostają osobne; pełny przebieg może działać przez noc bez ukrytych probe.
- Cache i resume przypięte do ról/modeli; nieznany model nie zasila cache, a metadane dowodów nie kopiują pól prywatnych. Zewnętrzna konfiguracja `new init --dir` wiąże stan z właściwym celem.

- Odtwarzalność: scan, gate, deep, consistency, UX, runtime, new audit i owner-report zapisują wspólne provenance, SHA/dirty Helixa i celu oraz wersje z rzeczywistych wykonań narzędzi i modeli; brak danych pozostaje jawny.
- Starsze/importowane artefakty zachowują własne metadane. Plan ról, cache i niedostępny model nie są nowym wywołaniem; snapshot Git raz na start deep, bez kosztu per partia.

- Środowisko: `helix env` i doctor porównują deklaracje projektu, lokalne wersje i jawny datowany dowód produkcyjny; klient PostgreSQL i serwer pozostają osobne.
- Nazwy użytych zmiennych porównywane z przykładami/Compose/CI bez odczytu rzeczywistych .env; pełny odczyt, jawne luki i ochrona wyjściowych dowiązań, bez instalacji ani modeli.

- Scalenie audytu terenowego z masterem 0.9.1: jeden raport właściciela zachowuje agregację artefaktów, plan luk, wagi, decyzje i dowody ciągłości.
- Ledger zachowuje wymagania obu strumieni: historyczne W z mastera i terenowe X, bez kolizji identyfikatorów; nowa kolejka runtime i prostoty pozostaje jawnym długiem.
- Zachowane zewnętrzne config/offline, detektory projektu A, consistency i tryby deep oraz nowe raporty kontrolek runtime; regresje merge i pełna bramka offline przed commitem.
- Naprawy przerwanego raportu runtime i porównania ścieżek kopii mutacji na macOS. Wykonanie aplikacji i niezależna recenzja modeli pozostają osobnym dowodem.

# 0.9.1-beta — 2026-10-25

- runtime: każda kontrolka ma konkretny reason i log (auth-flow nie psuje raportu); auth-flow dopuszczona w schemacie raportu; precyzyjne komunikaty walidacji (ścieżka pola); raport niepoprawny zapisywany jako runtime-report.invalid.json do diagnozy. Niezweryfikowane testami.

# 0.9.0-beta — 2026-10-25

- raport właściciela, gap plan, wynik ważony pomocniczo, handoff, obszary prawo/testy/observability/FinOps/dane/SEO, pokrycie ledgera (nietestowane — weryfikacja Claude).

# 0.8.7-beta — 2026-10-25

- Runtime: próbka tras wg profilu, równoległe konteksty, limity per trasa i częściowy JSONL.
- Dowody auth-flow, sesja dla e2e/k6, ranking migracji wg zastosowanych obiektów i plików.
- VERIFIED: regresje offline i sprawdzenie składni; ASSUMPTION: zachowanie aplikacji w kolejnym runtime.

# 0.8.6-beta — 2026-10-25

- Dziewięć perspektyw per część w istniejącym review deep; polityka w danych, wspólne detektory i źródła po deduplikacji.
- Pomocnicza dojrzałość 0–5, N/A, dług wykonania i niezależna bramka severity.
- Statyczna mapa danych, kandydaci wycieków, szkic DPIA i jawne luki audit trail.
- Kontrole pre-push i release check oraz 16 testów higieny release: PASS. Pełna suita zgłasza błędy; niezależna recenzja pozostaje niewykonana.
- Nieużywany numer względem lokalnego origin/master; jawne wyjątki historyczne release i kontrola receipt ograniczona do wskazanych SHA.

# 0.8.5-beta — 2026-10-25

- Runtime: osobne role URL aplikacji, issuer i składników IdP; diagnostyka callbacku na stubie bez wartości zmiennych.
- Testy regresji dodane; walidacja ograniczona do py_compile.

# 0.8.4-beta — 2026-10-25

- Lokalny checkpoint dopracowania: zgodność macOS, syntetyczne regresje security z audytu terenowego, pełne źródła consistency i agregacja raportu właściciela.
- Zewnętrzna konfiguracja, offline, rzeczywista diagnostyka narzędzi i zbiorczy odczyt integrity; jawna wierność wersji bazy.
- Deep: plan, wspólny budżet, checkpoint/resume, jobs, ryzyko, cache/diff i tryby full/daily/release; odrębne statusy niepełnego pokrycia.
- Plan i sprawdzanie modeli po realnej odpowiedzi JSON, zachowanie jawnych wyborów i niezależność rodzin; spięcie tego planu z security deep pozostaje w kolejnym kroku.
- Weryfikacja checkpointu: 739 testów offline OK na macOS. Zapis commitów jest blokowany przez sandbox; przygotowanie następnego wydania zatrzymuje zastana niezgodność historii release 14e38f6, bez akceptacji waivera.

- Pełny ledger wariantów migracji i finding projektu fresh-install-broken w runtime i audycie.
- Rejestr odpowiedzi app/stub; k6 ograniczone do tras potwierdzonych przez e2e, z licznikami kodów per URL.
- OIDC logout/end_session; wykonywalny hook wersji z diagnostyką brakującego kontrolera.
- Walidacja ograniczona do kompilacji i krótkich testów offline.

# 0.8.3-beta — 2026-10-25

- Kolejka release z claimem TTL, kontrola historii/receipt i jawne wyjątki historyczne.
- Higiena repo offline w raportach soczewek; wersja i schemat raportu.
- Testy offline; pełne testy i recenzja odroczone do Claude.

# 0.8.2-beta — 2026-10-25

- Port ze starego Helixa: ui-audit, dom-audit, visual-baseline, raport HTML i zatwierdzane wzorce SHA-256.
- Wbudowany dekoder/diff PNG bez pngjs; istniejący Playwright z projektu, zmiennej lub globalnego npm.
- Perf weight: SvelteKit, Vite, Next pages i statyczny dist; zapadka, świeżość buildu i SSR.
- Przenośna recenzja Gemini w trybie plan/sandbox, kontrola kompletności; zgodne wejścia scripts/ i nowe CLI.
- Raporty UI/review przyjmują dowody runtime; runtime zbiera sweep/DOM i wagę po buildzie.
- Syntetyczne testy offline; przeglądarka i niedostępne procesy Node mają jawne przyczyny skip.

# 0.8.1-beta — 2026-10-25

- Fallback po odmowie wszystkich wariantów runnera wybiera strategie Helixa; wyniki każdego wariantu w raporcie.
- Wąskie zaufanie SPKI stubu w Lighthouse i Playwright, prefiksowe ścieżki OIDC i raport pokrycia logowania syntetycznego.
- Kontrola wersji --pre-push względem origin/master, szablon hooka bez instalacji.
- Testy offline rundy 10 i ograniczona walidacja; bez pełnej suity i przebiegu usług.

# 0.8.0-beta — 2026-10-25

- Inwentarz git i jawne pokrycie odczytu bez limitu rozmiaru pliku; pominięcia dają INCOMPLETE.
- Kandydaci precyzji i czytelności kodu, progi S/M/L/XL, paczka modelu offline.
- Audyt zapisuje coverage.json, quality.json i zadania modelu; wykonanie modeli i adapterów pozostaje not-run.
- Pełne testy i recenzja odroczone na polecenie właściciela.

# 0.7.3-beta — 2026-10-25

- Sugestie komend runnera z dokumentacji i odmowy; pomijanie adopcyjnego baseline, deduplikacja dowodów.
- Zależności env złożonego issuera OIDC, diagnostyka przyczyn fetch i wykonywany podczas runtime test zaufania CA.
- Dodane testy offline; walidacja tej zmiany ograniczona do py_compile, bez wykonania testów.

# 0.7.2-beta — 2026-10-25

- Zduplikowane numery — wyjaśnienie: równoległe strumienie; commity 9723e1d/6dadc58. Jawna lista wyjątków: requirements/release-history.json.

- Generyczne warianty bootstrap runnerów, typowane env i diagnostyka startu z jedną próbą naprawy.
- Kontrola zgodności wersji wydania z changelogiem i historią git; testy offline.
- Pełna weryfikacja odroczona na polecenie właściciela.
- Obowiązkowa granica weryfikacji review: import niezależnych werdyktów JSON,
  hashe źródeł, zagregowane candidate i 0 punktów bez wykonania.
- Trwała precyzja per detektor/projekt i globalnie, konfigurowalna degradacja.
- Mapa selektorów guardów dla dziewięciu adapterów frameworkowych, z jawnym unknown.
- Siedem sygnałów zakresu rekordów, fixtures podatne/bezpieczne dla trzech stosów;
  pytanie do właściciela o konta ograniczonego zakresu. Pełna weryfikacja odroczona.

# 0.7.1-beta — 2026-10-25

- Zduplikowane numery — wyjaśnienie: równoległe strumienie; commity b26bf2a/48a4105. Jawna lista wyjątków: requirements/release-history.json.

- Połączenie adapterów OSS i poprawki `requirements add` z runtime 0.6.3-beta: wersje silnika bazy, DEGRADED i instrukcje backendu.
- Zachowane wymagania obu wydań bez duplikatów ID; wspólny kontrakt wersji 0.7.1-beta.
- Pełna weryfikacja odroczona do właściciela.

- Drugi strumień 0.7.1-beta (scalony pod wspólnym nagłówkiem): statyczne authz: kandydaci guardów projektu, łańcuchy dowodów i dziedziczenie granic frameworka.
- Agregacja tras bez rozpoznanego guarda, konfigurowalny próg sanity; possible najwyżej medium.
- Kontrola TOCTOU jednorazowych tokenów i regresje offline; nieznane ścieżki nie dają punktów.

# 0.7.0-beta — 2026-10-25

- Opcjonalny rejestr OSS w `tools adapters` i skan kopii w `tools scan`; niezaimplementowane wykonanie jawnie not-run.
- Kalibracja narzędzi lokalnych i regresje parserów; precyzyjne błędy `requirements add`.
- Uzupełnienie ledgeru o zakres etapu 0; pending pozostaje długiem.

# 0.6.3-beta — 2026-10-25

- Repository database version evidence, conflicts, versioned container images and native toolchain selection.
- Actual server version in runtime reports; WARN/DEGRADED on mismatch, excluded from audit credit.
- Actionable backend recovery instructions and explicit default assumptions.
- Offline regression tests added; full suite deferred.

# 0.6.2-beta — 2026-10-25

- Prefer project migration runners with isolated candidate trials, explicit selection and fallback counts.
- Expand issuer discovery and HTTPS substitutions; report authentication bypass flags without enabling them.
- Explain accessibility violations, HTTP failures and performance budgets; preserve Lighthouse application failures as FAIL.
- Add offline regression fixtures for shell migration loops and SvelteKit dynamic private environment imports.

# 0.6.1-beta — 2026-10-25

- Połączenie runtime 0.5.4-beta z 0.6.0-beta: strategie migracji, stub OIDC HTTPS, healthcheck HTTP, backup/restore i fixtures oraz ledger wymagań, ciągłość agentów i deep static security.
- Zachowane funkcje i sekcje obu wydań; wspólny kontrakt wersji 0.6.1-beta.

# 0.6.0-beta — w przygotowaniu

- Ledger 152 wymagań ze źródłami, opisami odbioru i mapowaniem rzeczywistych testów.
- `requirements check/add/report`: walidacja offline, runner unittest, ratchet i jawny dług MUST.
- Kontrola wypowiedź właściciela → ledger w tym samym commicie; fixtures i samotesty.

- Moduł ciągłości: generator instrukcji z pinem i hashem polityki, handoff sesji z ack, claims z TTL/lease, append-only decyzje i dryf w raporcie właściciela.
- Kontrole offline i regresje na tymczasowych repozytoriach git; bez nowych zależności.

# 0.5.4-beta — 2026-10-25

- Compare isolated schema strategies, detect duplicate creators, apply only up migrations and summarize SQL failures.
- Recognize HTTP error responses as running apps; report 5xx as E2E failures. Add synthetic HTTPS OIDC with scoped CA trust.
- Verify backup fidelity independently of schema completeness; expand runtime integration fixtures.
- Exclude Flyway undo scripts from deployment and isolate HTTP health evidence between application parts.

# 0.5.3-beta — 2026-10-25

- Detect baseline-dependent SQL chains, retain all migration numbers and seed-named DDL, retry failed SQL once and report duplicate conflicts.
- Ignore SQL comments and synthetic email domains in personal-data checks; permit single explicit service accounts.
- Require pg_isready and SELECT 1 readiness with retries; mark backups partial after schema failure and reduce imported data scores.

# 0.5.2-beta — 2026-10-25

- Select coherent schema chains, exclude archived sources, and report schema-apply failures while continuing SQL files in separate transactions.
- Preserve application checks and independent backup after partial schema application; empty databases fail with schema context.
- Permit audit output alongside runtime/state artifacts; report exception messages and protect existing audit artifacts.

# 0.5.1-beta — 2026-10-25

- Runtime environment classification is advisory: dummy SDK credentials and loopback endpoints; startup failures include application logs.
- Associate shared database sources with monorepo apps; continue after unavailable extension migrations with explicit limitations. Backup runs independently of app startup.
- Conservative synthetic SQL seed policy, public-route coverage and split-database/OIDC regression fixtures.

# 0.5.0-beta — 2026-10-25

- Add offline runtime discovery and disposable execution with PostgreSQL engine fallback, synthetic environment, bounded tools, retained check logs and report schema.
- Add Playwright/axe, Lighthouse, k6 and PostgreSQL restore measurements; import measured controls into offline audits.
- Add synthetic fixtures, fake-executor unit tests and explicit integration runner; GitHub Actions template.
- Bound human-readable evidence lists to a count and five examples; preserve JSON detail.

# Changelog

## 0.4.1-beta — 2026-10-25

- Remove custom authorization-name suppressions from object scope checks; cover
  request parameter variants and inline async forEach callbacks. Correlate security
  report issue types and source references, with evidence for heuristic likely-fixed.

- Calibrate static deep reports: ten leading findings, per-lens details and explicit
  file/handler/SQL coverage with exclusion manifests. Reduce regex-exec, type-only
  cycle, colocated-test, SQL upload and hidden-honeypot false positives; flag
  delegated object reads and tagged SQL for scope review, and async forEach. Add synthetic regression cases.

- Add offline `helix review deep <repo>` with nine shared lenses, ranked and
  deduplicated evidence, route/RBAC inventory, security signals, Polish Markdown
  and JSON schema. Preserve agentic security and standalone UI commands.
- Add synthetic cross-framework security precision/recall oracle and safe
  counterparts; support exact-version local advisories and redacted scanner
  metadata without reading secrets or invoking target code.

- Ignore unfinished Markdown lines rather than rejecting unrelated completed
  sections; preserve evidence line positions and strict structured contracts.
  Explicit draft documents and generated starter READMEs remain insufficient.
- Recognize architecture diagrams in deployment documents, including fenced
  box/arrow diagrams; keep prose-only deployment notes insufficient. Add
  Svelte, React/Next and Vue regression coverage for both outcomes.

- Share one bounded, read-only inventory across New audit, maturity and profile
  inference; include shell/IaC/schema files and keep sensitive/generated paths,
  symlinks, special files, lockfiles and oversized files outside evidence.
- Discover code/SQL/worker/operations parts and apps/packages/services layouts,
  including workspace exclusions, without assuming a frontend framework.
- Find recursive, case-insensitive architecture, OpenAPI, SLO, runbook,
  security and recovery document variants; retain content predicates, scores,
  runtime requirements and brand validation. Reject empty/headings-only drafts.
- Record each selector's candidates and rejection reasons, distinguishing
  insufficient evidence from missing candidates. Profile reasons cite sources;
  test/example signals and document counts do not establish project scale.
- Add synthetic SvelteKit, React/Next and Vue/Nuxt with nx/turbo/workspaces,
  SQL/Prisma/Alembic, CI, privacy boundary and provenance regressions.

## 0.4.0-beta — 2026-10-25

- Resolve review-1: align CLI/docs/templates on 0.4.0-beta; require project pins
  before commands; retain pins and domain maps when regenerating New contracts.
- Validate documentation owners/review dates and per-document code freshness,
  with explicit stale warnings, external metadata and documentation custom gates.
- Validate external populated observability/postmortem contracts; reject incomplete
  field contracts and infer UI conflicts requiring before/after screenshots.
- Require design decisions by default; isolate New test fixtures in system temp,
  fix module-mode Sweep imports, remove obsolete merge/test working artifacts.

- Add ninth Pro area `documentation`: eleven weighted offline controls, profile targets,
  external docs_paths, mtime freshness heuristic, remediation and documentation pack.
- Require multi-product platform programs for XL or `new init --platform`: portfolio,
  capability/context ownership, modular monolith ADR, APIs/apps, tenancy, identity,
  shared design system, team boundaries and validated milestone dependency graph.
- Add structured privacy, AI eval/token budget, license/asset inventory,
  observability and incident/postmortem contracts with neutral draft templates.
- New projects require approved design alternatives before checkpoint implementation;
  validate change explanations and emit static brownfield component/dependency maps.
- Add 19 offline regression tests and a synthetic commerce-platform XL scale fixture.
  Preparation contracts do not certify runtime outcomes or approver identity.

## 0.3.2-beta — 2026-10-25

- Offline field contracts: owner decisions, reviewed merge inventory, host execution
  evidence, rule-change self-tests, gate budgets and affected-component batches.
- ID reservations, many-to-many domain map, configurable-product matrix and
  equal catalog-module gates for manual and AI work.
- Single owner report, version stamps/pins and documentation freshness foundation.
- Unexecuted custom gates earn zero points; neutral unittest regressions and EN/PL docs.

## 0.3.1-beta — 2026-10-25

- Fix review blockers: external selector paths and YAML/SQL discovery, validated
  project gates with normalized scoring, Playwright projects detection, per-part
  remediation priorities/visual review and profile-specific artifact gaps.

- Read-only external docs, project gates and explicit or inferred audit profiles.
- Concise output, complete remediation plans and per-part monorepo scoring.
- Sharded CI with artifacts, failed-shard resumption and merged reports.
- Seven neutral unittest regressions; bilingual usage and skip accounting.

## 0.3.0-beta — 2026-10-25

- Helix Pro standard: eight separate profile-based offline maturity scores and top gaps.
- M+ PostgreSQL integration, Playwright and k6 CI checks with dated exceptions;
  L/XL reliability evidence requirements. Existing UX/consistency and brand contracts.
- Neutral CI templates, bilingual documentation and offline unittest coverage.

## 0.2.0-beta — 2026-10-25

- Helix New: offline greenfield/brownfield init, read-only audit with evidence,
  palette statistics and draft reconstruction, source brand gate and handoff check.
- Versioned templates/schemas and full S/M/L/XL preparation contracts with
  independent risk profiles, required project running skill, owner acceptance
  and SHA-256 manifest validation. No new runtime dependencies.
- Documentation and offline unittest contracts; production, load/DR and expert
  compliance acceptance remain separate from preparation validation.

## Unreleased

- Helix New: fixed S/M feature negation and malformed architecture FAIL handling;
  expanded build/dependency inventory and Alembic migration classification.
  Palette scanning excludes comments, separates declarations and var references,
  records token values and font expressions; audit gaps now use explicit S/low/brownfield scope.
  Added offline regression tests and clarified PASS/FAIL/ERROR in the running skill template.

- Domknięto odpowiedzi sond HTTP visual/UX (także HTTPError) i sockety serwerów testowych consistency, również po błędzie setupu; dodano testy offline cyklu zasobów.
- Semgrep wymaga list `results`, `errors` i `paths.scanned`; błędy skanowania przy rc=0 i niepełny JSON dają ERROR zamiast PASS. Dodano kontrprzykłady oraz test poprawnego pustego skanu.
- Zaktualizowano status obu ulepszeń w polskim backlogu z 2026-10-25; niezależny przegląd pozostaje do wykonania przez innego recenzenta.

## 0.1.0-beta — 2026-10-24

Initial private beta: checkpoint workflows with truth, behavior, visual and independent review gates; UX device matrices, accessibility and persona flows; static/runtime consistency; security scanners and independently verified deep source reviews; performance budgets; integrity ratchets, baselines and coverage ledgers; resumable cached units; local tasks, boards, tools, scoped rules and session audits; installation diagnostics and fast-forward updates.

Beta hardening: incomplete scans fail closed, worker policy errors return nonzero, repository prechecks require explicit trust and strip credential environment variables, deep gates use the selected state and require complete coverage, deletion citations retain uncertainty, binary integrity gaps block acceptance, session costs accumulate, and symlinks disable cache reuse. Private examples and working artifacts removed; bilingual onboarding and third-party attribution added.

## Pro maturity catalog and offline improvement plans (2026-10-25)

- Extend the existing catalog with thresholds, sources, remediation steps and weights.
- Separate offline and preparation scores; runtime-dependent controls stay needs-runtime.
- Add `helix new plan --to pro` with security/data-first schema-compatible checkpoints.
- Add readiness, recovery, ASVS, WCAG, CWV, design-reference and UX-review templates.
- Preserve existing CI jobs and source brand gates; add offline unittest coverage.

### Statyczne UI deep

- Dodano niezależny moduł UX/UI i `helix ui deep <repo>` (stdlib, bez wykonywania targetu).
- Raport JSON/Markdown: tokeny i kontrolki, kontrast, a11y, stany danych i copy;
  schema, syntetyczny oracle precision/recall i jawne ograniczenia heurystyk.

- Security deep: preserve object-scope review signals for simple transaction SQL tag aliases, including TypeScript casts; add positive and negative synthetic regression cases.
