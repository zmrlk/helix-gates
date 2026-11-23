# Integracje w runtime

```sh
helix --config /audits/app/helix.proposed.json --offline runtime plan --project /code/app --json
```

Plan odczytuje źródła i zewnętrzną konfigurację przypisaną do `--project`, także
gdy bieżący katalog jest innym repozytorium. Nie uruchamia aplikacji, usług,
modeli ani instalacji. `runtime run` i `runtime mutation` pozostają niedostępne
w trybie offline; plan, doctor i ci-template mogą działać bez sieci.

Każda wykryta zależność ma provider, część monorepo, obszar źródeł, miejsca
plik:linia, nazwy zmiennych, ścieżki i wzorce tras oraz proponowaną strategię.
Aktywny kod jest oddzielony od testów, przykładów, docs i legacy. Nieznane
połączenia i nierozwiązane importy są lukami; brak wykrycia nie jest dowodem
braku integracji. Statyczny graf importów nie potwierdza wykonania trasy.

| Strategia | Co musi potwierdzić wykonanie |
|---|---|
| `container` | Uruchomiona własna tymczasowa usługa, readiness, wersja i logi. |
| `emulator` | Faktycznie skonfigurowany lokalny emulator i dowody operacji. |
| `replay` | Jawne lokalne odpowiedzi oraz dowód ich użycia. |
| `disabled` | Dowód egzekwowania wyłączenia; zachowanie integracji pozostaje nieprzetestowane. |

Konfiguracja `runtime.integrations` pozwala wskazać provider albo konkretny
identyfikator inwentarza i `strategy`. Jawnego wyboru Helix nie zastępuje
nieobsługiwanym wariantem. Pole `implemented` opisuje dostępność adaptera,
a nie jego wykonanie. Receipts mogą pochodzić z PostgreSQL przez docker/podman,
lokalnego kontenera Keycloaka i ogólnego emulatora OIDC. Redis, sinki i replay
wymagają kolejnych adapterów. Keycloak nie otrzymuje cichego potwierdzenia
na podstawie ogólnego stubu OIDC.

Raport zachowuje `measurement_status` i wyniki konkretnych pomiarów. Osobne
`coverage_status` opisuje luki integracji. Gotowa baza albo odpowiedź HTTP 200
nie potwierdza przejścia przez integrację: potrzebny jest receipt związany
z bieżącym `plan_id`, `run_id`, trasą i metodą, z `integration_exercised=true`
oraz niepustym lokalnym artefaktem. Parametry tras dynamicznych wymagają
osobnego dowodu wariantów. Stare, obce lub niepoprawne receipts nie zaliczają
pokrycia. Raport bez inwentarza zachowuje stan `NOT_RECORDED`.

Kompletny PASS zwraca 0, kompletny wykonany FAIL zwraca 2, a luki, legacy lub
niepełny przebieg zwracają 3. Wykonany FAIL trasy jest dowodem wykonania testu,
ale blokuje PASS. Import do Pro zachowuje konkretne metryki i dodaje blokadę
pokrycia całości oraz właściwej części. Raport właściciela pokazuje wszystkie
miejsca, trasy i przyczyny nieprzetestowania zamiast ukrywać je za wynikiem
udzielonej przez emulator odpowiedzi.

## Plan tożsamości Keycloak

`runtime plan` zawiera również publiczny `identity_plan` z tych samych źródeł
i efektywnej konfiguracji. Dla każdej części opisuje klienta, dokładne ścieżki
callbacków, PKCE, claim ról i syntetycznego użytkownika na rolę. Dodaje także
wariant bez roli aplikacji i z niezweryfikowanym adresem email. Wszystkie konta
i hasła są syntetyczne; plan nie zawiera haseł, sekretów ani eksportu realmu.

`READY` oznacza kompletny plan deklaracji. `BLOCKED` wymienia braki i konflikty,
a `NOT_DETECTED` oznacza brak rozpoznanego Keycloaka. Żaden z tych statusów
nie potwierdza uruchomienia serwera, importu realmu ani logowania. Klient
administracyjny nie zastępuje klienta aplikacji. Wartości rzeczywistych plików
`.env` nie są odczytywane; dynamiczna wartość bez dowodu pozostaje luką.

Brakujące niesekretne deklaracje można uzupełnić w zewnętrznym `--config`:

```json
{
  "runtime": {
    "keycloak": {
      "parts": {
        "frontend": {
          "client_id": "synthetic-app",
          "client_type": "confidential",
          "callback_paths": ["/auth/callback"],
          "login_path": "/login",
          "pkce": "S256",
          "role_claim": "realm_access.roles",
          "roles": ["reader", "editor"]
        }
      }
    }
  }
}
```

To przykład dla syntetycznego projektu, nie konfiguracja projektu A. Sprzeczne
deklaracje wymagają rozstrzygnięcia; wpis w config nie ukrywa konfliktu
w źródłach. Obsługiwany kontrakt realmu jest przypięty do Keycloak 26.8.1;
inna zadeklarowana wersja nie zostaje po cichu zastąpiona. Przy braku deklaracji
wersja domyślna jest oznaczona jako ASSUMPTION. Prywatny materiał przebiegu
zawiera świeży realm i odrębne hasła, a callbacki wiążą się z faktycznym
lokalnym portem aplikacji.

### Ekrany chronione: `screen_role`

Domyślnie sesja z logowania nie opuszcza obserwacji formularza i przebieg ocenia
tylko ekrany publiczne. Właściciel może wskazać jedną z zadeklarowanych ról:

```json
{"runtime": {"keycloak": {"parts": {"frontend": {"roles": ["reader", "editor"], "screen_role": "editor"}}}}}
```

Po udanym logowaniu syntetycznej tożsamości tej roli e2e zapisuje jej sesję
w katalogu tymczasowym przebiegu. Używają jej trasy e2e, a11y i przegląd tras
tej samej części (przegląd tras idzie wtedy po logowaniu). Lighthouse, k6 i inne
części jej nie dostają. Plik jest usuwany po zakończeniu części, a raport
zapisuje `screen_session` (rola i stan `USED` albo `NOT_ESTABLISHED`).

Przegląd tras mierzy też widoczne ramki tej samej aplikacji (ten sam origin, np.
powłoka z kartami, która pokazuje ekran w `iframe`) i zapisuje ich liczbę w polu
`frames`. Ramka obca (inny origin albo `sandbox`) pozostaje błędem pomiaru. Trasa,
która z sesją odsyła na inny ekran, dostaje w e2e i a11y błąd z celem odesłania.

Aplikacja, która wymaga istniejącego profilu w bazie (projekt A odmawia sesji
niezatwierdzonemu kontu), dostaje go przez `runtime.adapters.synthetic_rows`:
jawne wiersze dla adresów `helix-role-<id>@example.invalid` z planu tożsamości.
Wynik dotyczy jednej roli; nie zastępuje jawnej polityki ról i tras.

## Wykonanie lokalnego Keycloaka

Adapter wymaga lokalnego obrazu 26.8.1 oraz Docker albo Podman. Nie pobiera
obrazu automatycznie. Odczytuje ID obrazu, uruchamia właśnie ten niezmienny ID
i zapisuje rzeczywistą wersję serwera, health, discovery, JWKS i próbę TLS
z Node. Do kontenera trafiają tylko syntetyczny realm i własne pliki TLS.
Sprzątanie sprawdza losową etykietę własności, zanim usunie własny kontener.

Konfiguracja `runtime.keycloak.parts.<część>.env_roles` mapuje nazwy zmiennych
na role: `issuer`, `idp_origin`, `realm`, `client_id`, `client_secret`,
`app_origin` i `callback_uri`. Nazwy pochodzą z rozpoznanych odczytów albo jawnej mapy w config; plan
zachowuje tę podstawę, a sam wpis nie jest dowodem użycia. Wartości dla
procesu kopii powstają dopiero w prywatnym materiale przebiegu.
Przykładowo `ACME_KC_URL: idp_origin` wskazuje origin IdP, a `ACME_APP_URL:
app_origin` wskazuje aplikację. Nie są wymienne z issuer zawierającym realm.
Zmienne sterujące procesem, modułami, proxy, bazą i zaufaniem TLS nie mogą
zostać przypisane przez ten mechanizm.

Klient publiczny nie otrzymuje losowego sekretu zmieniającego tryb logowania.
Confidential używa świeżego sekretu tylko w prywatnym środowisku. Audience
mapper dotyczy wyłącznie syntetycznego klienta aplikacji. Pełny publiczny
receipt lifecycle i jego projekcja do inwentarza rozdzielają gotowość usługi
od pokrycia tras; przerwanie, pauza i błąd zachowują próbę oraz cleanup.
Żadne z tych pól nie zastępuje rzeczywistego testu formularza i callbacku.

Znany Keycloak nie spada na ogólny stub OIDC. Brak planu, mapowania, obrazu,
silnika lub poprawnej gotowości pozostaje jawnym BLOCKED/INCOMPLETE.
`--no-oidc-stub` dotyczy ogólnego emulatora, nie stanowi zgody na pominięcie
rozpoznanej integracji. HTTPS aplikacji, Secure cookies i scenariusze ról
pozostają osobnymi pomiarami.

Ogólny emulator dla nieznanego dostawcy zachowuje wyłącznie obserwacje
nawigacji. Bez jawnego kontraktu tożsamości ma
`BLOCKED/NO_EXPLICIT_IDENTITY_POLICY`, a sesja i uprawnienia pozostają
`NOT_RUN`. Cookie preferencji, przekierowanie 301 lub odpowiedź 200 nie
dowodzą zalogowania właściwego użytkownika. Emulator nie eksportuje
`storageState` ani `.session`; kolejne kontrole i k6 nie otrzymują tego stanu.
Pomiary publicznych tras zachowują własny wynik.

Historyczny `auth-flow PASS` oparty na dawnych heurystykach nie daje punktów
przy imporcie. Walidator zgłasza `legacy_auth_claim_unverified`, a raport
właściciela wskazuje brak dowodu sesji i wymagany test jawnej polityki.
Źródłowy plik, jego skrót i metadane pozostają zachowane. To granica dowodu
emulatora, nie stwierdzenie błędu aplikacji ani zamiennik adaptera Keycloak.

Polecenia silnika i cleanup używają ograniczonego środowiska, bez sekretów
aplikacji ani jej ustawień proxy/context. Dla Docker adapter sprawdza znany
lokalny socket systemowy lub Docker Desktop w katalogu użytkownika procesu
Helixa. Brak potwierdzonego socketu daje BLOCKED przed wywołaniem CLI; nie
czyta konfiguracji zdalnych kontekstów. Receipt ujawnia rodzaj i źródło
endpointu, bez kopiowania prywatnego środowiska.

Surowy log aplikacji pozostaje w prywatnym katalogu runtime. Raport i logi
wskazane w raporcie redagują znane credentials wygenerowane przez Helixa.
Ta kontrola nie polega na odczytywaniu rzeczywistych .env ani na założeniu,
że aplikacja nigdy nie wypisze konfiguracji.

Ten sam selektor lokalnego endpointu Docker służy PostgreSQL, backupowi,
cleanup i Keycloak. Wybrany transport jest zapamiętany na przebieg, a polecenia
nie dziedziczą credentials aplikacji. Samo `docker --version` pozostaje
odczytem wersji klienta bez wymogu działającego socketu; nie dowodzi gotowości
demona ani uruchomienia bazy. Wybór backendu i kontrola faktycznej wersji
PostgreSQL zachowują swoje dotychczasowe warunki, także przy fallbacku.

## Lokalny HTTPS i cookies

`runtime plan` dodaje `transport_plan` z tych samych pełnych źródeł, które
służą inwentarzowi integracji. Deklaracje Secure cookies, Keycloaka i WebAuthn
mają miejsca plik:linia i zakres części monorepo. Nierozwiązane dynamiczne
opcje są luką. Docs, legacy, testy i rzeczywiste `.env` nie aktywują propozycji.

```json
{"runtime": {"https": {"enabled": true, "public_host": "localhost"}}}
```

Jawne `enabled: false` pozostaje zachowane, razem z informacją o niewykonanym
sprawdzeniu wymagającym HTTPS. `helix new audit` proponuje powyższe ustawienie
w zewnętrznej konfiguracji tylko przy wykrytej potrzebie i braku jawnego
wyboru. `NEW-REPORT.md` oddziela stan obserwowany od propozycji i wykonania.
`new init` bez snapshotu źródeł podaje NOT_RECORDED.

Runtime ustala publiczny origin przed buildem i utworzeniem klienta IdP.
Port aplikacji HTTP jest osobny od portu frontu HTTPS, a callbacki pozostają
związane z publicznym origin. Zmiana portu przez aplikację daje BLOCKED,
zamiast automatycznie poprawiać kontrakt. Certyfikaty powstają na ten przebieg;
Node i health probe otrzymują własny CA, Chromium i Lighthouse dokładne SPKI.
Nie ma globalnego ignorowania TLS.

Front łączy się wyłącznie ze stałym adresem loopback, sprawdza Host i odrzuca
CONNECT, WebSocket oraz URL do zewnętrznego hosta. Usuwa podszyte nagłówki
proxy. Zachowuje wszystkie Set-Cookie i Location bez przepisywania, dzięki
czemu błąd aplikacji pozostaje mierzalny. Limit czasu i cleanup obejmują
tylko własne procesy i połączenia.

Gotowość TLS nie zalicza logowania, polityki cookies, ról ani WebAuthn.
Localhost nie odtwarza produkcyjnego cross-site SameSite ani izolacji cookies
między portami. Test load na HTTPS pozostaje BLOCKED do czasu potwierdzenia
prywatnego zaufania CA przez k6. Pełny raport zachowuje `transport_coverage`
i luki nawet wtedy, gdy pozostałe pomiary są PASS.

## Fazy formularza Keycloak

Adapter formularza korzysta wyłącznie z prywatnego materiału syntetycznego
realmu i własnego HTTPS. Każda pozytywna tożsamość ma nowy kontekst Chromium.
Przed wprowadzeniem hasła sprawdzane są własny issuer i realm, client_id,
dokładny callback, state, wymagany PKCE oraz action formularza. Właściwe
żądanie wysłania danych również podlega sprawdzeniu; sama zgodność DOM nie
jest wystarczająca. Nie ma password grant ani dodawania cookie przez Helixa.

Publiczny zapis zawiera powiązanie z planem i przebiegiem oraz statusy faz
authorization, formularza i callbacku. Hasła, code, state, nonce, tokeny,
wartości cookies i surowe adresy z query nie trafiają do raportów. Błąd HTTP
callbacku lub odpowiedź OIDC error nie stają się udanym callbackiem.

W tym etapie `form_status=PASS` oznacza tylko zaobserwowane fazy formularza.
`session_coverage` i `authorization_coverage` pozostają NOT_RUN. Warianty
bez roli i bez zweryfikowanego email zachowują osobne NOT_RUN, dopóki brak
jawnej polityki i testu oczekiwanego zachowania. Readiness kontenera,
formularz, sesja oraz dostęp do chronionej trasy nie są wymienne.

Importer i owner-report korzystają ze wspólnych projekcji `runtime_transport`
oraz `runtime_identity`, z pełnymi lokalizacjami deklaracji transportu.
Starszy raport bez tych danych ma NOT_RECORDED. Nowy plan bez wykrytego
Keycloaka ma NOT_DETECTED; brak deklaracji nie jest dowodem testu logowania.
Niewykonane fazy i przerwane tożsamości pozostają widoczne, bez punktów.

HTTP routing przeglądarki nie stanowi izolacji sieci całego procesu aplikacji
ani dowodu kontroli WebSocket. Zewnętrzne integracje i ich sinki mają osobny
kontrakt. Testy offline na atrapach nie zastępują rzeczywistego smoke
Keycloak plus Chromium ani przebiegu na projekcie A.

Jawne oczekiwania sesji i dostępu do tras mają odrębny
[plan polityki](runtime-identity-policy.md). Deklaracje rola/trasa, obserwacje
formularza i wykonanie testów są osobnymi dowodami; sam plan nie zalicza sesji.

WebAuthn ma osobny [jawny plan ceremonii](runtime-webauthn.md), powiązany
z tą polityką oraz transportem. Zależność bez przebiegu i jawne wyłączenie
pozostają lukami; deklaracja profilu wirtualnego klucza nie jest wykonaniem.

## Lokalne skrzynki wysyłek

Własny odbiornik runtime służy do emulacji obsługiwanych operacji Resend,
SerwerSMS, PLAY, Meta i TikTok oraz syntetycznego web-push. Wymaga granicy
[izolacji procesów](runtime.md#process-network-admission). Gotowość odbiornika,
przekierowanie żądania, lokalne przyjęcie i wynik trasy aplikacji pozostają
osobnymi dowodami. Lokalna odpowiedź sukcesu nie potwierdza doręczenia maila,
SMS lub push ani publikacji w zewnętrznym serwisie.

Katalog zamyka metody, hosty i operacje. Obejmuje przyjęcie maila Resend,
SMS SerwerSMS, lokalny token i wysyłkę SMS PLAY, zdarzenia Meta CAPI oraz
przyjęcie materiału Meta/TikTok. Odpowiedź statusowa publikacji pozostaje
oczekiwaniem. Odbiornik nie pobiera adresów mediów, nie wywołuje webhooków
potwierdzających i nie jest proxy. Inne operacje, w tym WhatsApp Cloud,
click2call i API poza katalogiem, pozostają nieobsługiwane.

Podmiana samego env nie obejmuje adresów zapisanych na sztywno w kodzie.
Własny adapter Node przeadresowuje obsługiwane wywołania do dokładnego
lokalnego odbiornika przed startem aplikacji, bez zmiany źródeł klienta,
MITM TLS ani wyłączania walidacji certyfikatów. Niewspierany SDK lub
transport nie otrzymuje automatycznie statusu obsługi. Systemowa odmowa
pozostaje osobną granicą także dla potomków i pominiętego adaptera.

Walidacja domeny przed Resend ma lokalny wariant tylko dla dokładnych domen
syntetycznych Helixa. Nie udaje DNS rzeczywistych odbiorców. Web-push wymaga
własnego syntetycznego endpointu i materiału kluczy; nie przechwytuje dowolnego
adresu z subskrypcji. Ustawienia integracji w bazie i brak subskrypcji pozostają
lukami. Helix nie kopiuje konfiguracji produkcyjnej i nie zgaduje potrzebnych
wierszy na podstawie nazw tabel.

Plan i obserwacje zachowują powiązanie z częścią, bieżącym inwentarzem oraz
próbą. Publicznie dostępne są identyfikatory operacji, przyjęcia/odmowy i
liczniki. Nie ma adresatów, treści, nagłówków uwierzytelnienia, query, kluczy,
załączników ani surowych wyjątków SDK. Prywatna konfiguracja i token odbiornika
znikają ze zwykłym cleanup katalogu tymczasowego. Payloady skrzynki i wygenerowany
materiał syntetyczny pozostają w `out/private/sinks/<attempt>` z uprawnieniami
0700 dla katalogu i 0600 dla plików, do usunięcia przez właściciela wraz z
katalogiem wyników. Skrzynka nie jest dodatkowym zapisywalnym katalogiem
procesu projektu; publiczny raport zachowuje osobny bezpieczny snapshot.
Gotowość oraz kontrolne
żądania odbiornika nie uzupełniają `tested_routes`.

Testy syntetyczne wykonują rzeczywiste helpery adaptera i odbiornika na
atrapie transportu, bez listenerów i sieci. Potwierdzają implementację tego
kontraktu, a nie działanie rzeczywistych wersji SDK, dostawców lub projektu A.
Brak historycznych obserwacji pozostaje nieznany; bieżący niewykonany plan
nie daje punktów ani dowodu doręczenia.

Pokrycie transportu całego planu wymaga receipt dla każdej zaplanowanej
części i stanu `ready` zarówno HTTP, jak i HTTPS. Pominięta część oraz stany
`blocked`, `starting`, `not_checked` pozostają `INCOMPLETE`. Projekcja jednej
części liczy tylko jej zakres, po sprawdzeniu raportu całego przebiegu.
Aliasy `event.cookies`, `req.cookies`, `(await) cookies()` zachowują wymagania
Secure cookies; nierozstrzygnięty setter z prefiksem lub dynamicznymi opcjami
zostawia jawną lukę. To nadal deklaracja źródłowa, nie wynik logowania.

Preload HTTP przekazuje natywnej funkcji ten sam znormalizowany URL i kopię
danych opcji, które sklasyfikował. Odrzuca akcesory, obce prototypy i opcje
niestandardowego socketu, połączenia lub agenta. Nie przekazuje surowego
obiektu wywołującego, także dla ruchu do własnego originu.

## Stan ekranu a pomiar: `env_unset`, odesłania, tempo pomiaru

- `runtime.env_unset` (do 20 nazw) wskazuje zmienne, których Helix nie wypełnia
  wartością zastępczą. Dotyczy zmiennych opcjonalnych, których sama obecność
  zmienia ekran (np. baner „stara wersja”).
- Z sesją ekranów trasa, która odpowiada 2xx pod adresem innego oglądanego
  ekranu tej samej aplikacji, dostaje status `REDIRECTED` (e2e, a11y) albo
  `redirected` (przegląd tras) z celem odesłania. Nie jest usterką ani
  zaliczeniem. Odesłanie bez sesji, na logowanie, na stronę błędu albo na adres
  spoza listy tras pozostaje usterką. e2e i a11y nie przechodzą, gdy żadna
  trasa nie odpowiedziała pod własnym adresem.
- `runtime.rate_limited_paths` (do 10 dokładnych ścieżek) wskazuje adresy, na
  których aplikacja ogranicza liczbę zapytań jednego konta. Odpowiedź 429 z
  takiej ścieżki jest w przeglądzie tras ostrzeżeniem; każda inna 429 obciąża
  ekran.
- Obciążenie przy `runtime.https` idzie na port aplikacji za własną warstwą TLS
  przebiegu, z tymi samymi nagłówkami przekazania. Raport zapisuje to w polu
  `transport`; czas zestawienia TLS nie jest mierzony.

## Czy pomiar opisuje ekran: kontrola własna

Przegląd tras i sprawdzenia przeglądarkowe same wykrywają sytuacje, w których
wynik nie opisuje ekranu aplikacji:

- **Okno otwarte od wejścia** (modalne): jest mierzone raz jako osobny stan
  (`arrival`), potem zamykane klawiszem Escape, a gdy to nie działa, własnym
  przyciskiem okna (zapisy są na ten moment odcięte). Bramkę zgody bez
  przycisku zamknięcia (wiek, regulamin, pliki cookie) przegląd przechodzi
  potwierdzeniem („Tak…”, „Akceptuję”, „Zgadzam się”), tak jak człowiek.
  Dopiero okno, którego nie da się zamknąć, daje trasie status `obscured`.
- **Stany po kliknięciu**: w najszerszej i najwęższej szerokości przegląd klika
  każdy widoczny wyzwalacz (przyciski, zakładki, elementy z `aria-haspopup` i
  `aria-expanded`), mierzy i fotografuje to, co się otworzy, i wczytuje ekran
  od nowa. Żądania inne niż GET są odcinane, więc kliknięcie niczego nie
  zapisze. Wyzwalacze wspólnej powłoki są oglądane raz na przebieg. Raport
  podaje, ile wyzwalaczy znaleziono, kliknięto i pominięto.
- **`self_check`** w `legacy_audits`: ocena `SUSPECT`, gdy ekran zasłania okno
  albo gdy to samo znalezisko powtarza się na większości tras, a prawie żadna
  nie przechodzi. Powód stoi w `runtime.md`.
- **Trasy z parametrem** (`/leads/[id]`): e2e bierze konkretny adres z
  odnośników na obejrzanych ekranach, po jednym na wzorzec; a11y i przegląd tras
  oglądają go jak każdą inną trasę. Wzorce bez odnośnika są w
  `unresolved_patterns`. Gdy lista otwiera rekord kliknięciem wiersza (bez
  odnośnika), przegląd stanów klika pierwszy taki wiersz każdej listy, a ekran
  szczegółów, na który trafił, dostaje własny pomiar: po jednym na wzorzec, w
  `legacy_audits.reached_by_click`.
- **Sesja wygasająca w trakcie przeglądu** (token aplikacji na kilkadziesiąt
  minut): gdy trasa z sesją kończy odesłaniem, Helix powtarza scenariusz
  logowania, z którego sesji korzystała ta trasa, i mierzy ją ponownie
  (`session_renewals`). Powtarzany jest tylko scenariusz oznaczony przez
  właściciela `"renewable": true`, bo scenariusz może zapisywać dane. Odesłanie
  w ciągu dwóch minut od odnowienia jest zachowaniem samej trasy. Realm
  Keycloaka tworzony na przebieg trzyma sesję 12 godzin.
- **Żądania z danych syntetycznych**: 404 na adresie kończącym się wartością
  zastępczą Helixa (`synthetic-item`) nie obciąża aplikacji.
- **a11y** wstrzykuje axe także do ramek aplikacji; bez tego sprawdzana byłaby
  sama powłoka.
- **Lighthouse**, który wylądował na innym originie (logowanie u dostawcy
  tożsamości), i **obciążenie**, które dostało same odpowiedzi 3xx, dają
  `BLOCKED` z powodem zamiast liczb opisujących nie tę stronę.
- Sygnał zatrzymania (`SIGINT`, `SIGTERM`) przerywa przebieg od razu; pętle
  sprawdzeń i przeglądu tras go nie połykają.

Wyzwalacze znalezione w otwartym oknie albo menu są klikane po ponownym
otwarciu tej warstwy (jeden poziom w głąb, do 6 na warstwę i 30 na pomiar;
przyciski zamykania są pomijane), więc okno otwierane z okna też jest mierzone.

Granice: głębsze zagnieżdżenie niż jeden poziom nie jest oglądane; zapisy i
formularze sprawdzają scenariusze właściciela (`runtime.scenarios`), nie
przegląd stanów.

Od 14.11.2026 (decyzja właściciela) sesję roli ekranów dostają także
Lighthouse i obciążenie (k6) tej samej części: tylko ciasteczka hosta
aplikacji. Lighthouse dostaje je jako zwykłe ciasteczka wstawione do
przeglądarki pomiaru (`bin/runtime-lighthouse-session.cjs`), więc przeglądarka
pilnuje ich zakresu, a wynik Lighthouse nie zawiera wartości; dotyczy to
przeglądarki uruchamianej przez Helix. k6 dostaje je w prywatnym skrypcie
(`0600`), usuwanym po pomiarze także po błędzie. Raport zapisuje
`authentication_scope` i ścieżkę, na której Lighthouse wylądował.

## Stany danych: skąpy i przepełniony

Jeden przebieg ogląda ekrany w dwóch stanach danych:

- **Skąpy**: po zasiewie podstawowym (jeden syntetyczny wiersz na tabelę, część
  tabel pusta) e2e loguje role i odkrywa trasy, a każdy ekran dostaje jedno
  zdjęcie w szerokości 1440 (`data_states.sparse`, katalog `visual/<n>/sparse`).
- **Przepełniony**: `templates/runtime-seed-volume.sql` mnoży syntetyczne wiersze
  do `runtime.seed_rows` na tabelę (domyślnie 60, zakres 2–500). Raport podaje
  faktyczny wynik (`data_states.volume`): ile tabel doszło do celu, które nie
  doszły i ile wierszy ma wartości skrajne; niepełny zasiew to `INCOMPLETE`.
  Liczby są mierzone w tabelach po zasiewie, nie wyliczane. Słowniki i
  ustawienia (statusy, role, uprawnienia, jednostki, kategorie, magazyny) są
  rozpoznawane po nazwie i pomijane; własne tabele do pominięcia podaje
  `runtime.seed_skip_tables`.
  Tabele łączące dostają kolejne rekordy nadrzędne w drugim przejściu. Co piąty wiersz
  ma długą nazwę i dużą kwotę. Zmieniane są tylko wartości zastępcze Helixa i
  klucze. Tabele kont, sesji i tokenów oraz tabele z obowiązkową kolumną
  logowania zostają nietknięte i są wymienione w wyniku (`skipped_login_data`);
  opcjonalna kolumna logowania w tabeli roboczej zostaje w kopiach pusta. Na tym stanie idą
  a11y, Lighthouse, obciążenie i pełny przegląd tras ze stanami po kliknięciu,
  więc widać ucinanie tekstu, łamanie liczb, sortowanie i stronicowanie.

Zasiew próbuje każdy wiersz w trzech wariantach, od najbogatszego: z polami
opcjonalnymi i kwotami zerowymi (co siódmy wiersz zostaje pusty, pola o
znaczeniu formalnym jak e-mail, kod czy status są pomijane), tylko pola
obowiązkowe, kopia różniąca się kluczem.

Granice: stan całkowicie pusty (zero wierszy we wszystkich tabelach) nie jest
osobno odtwarzany; wiersze potomne wskazują ten sam rekord nadrzędny; wartości
z ograniczeniami tabeli (CHECK, enum) zostają kopią bez zmian.

Kliknięcie w przeglądzie stanów dostaje rodzaj skutku: `dialog`, `menu`, `tab`,
`expanded`, `toggled`, `file-chooser`, `download`, `write-cut` (zapis odcięty),
`navigation`, `no-change`. Uwaga pokazana już przez wcześniejszy stan tego
przebiegu jest liczona raz (`repeated`). Raport HTML trasy ma tabelę stanów.

## Scenariusze właściciela: `runtime.scenarios`

Samo oglądanie ekranów nie sprawdza zapisu ani nie wejdzie tam, gdzie aplikacja
ma własne logowanie (PIN, kod). Do obu służą scenariusze: krótkie ścieżki
wykonywane po logowaniu ról, w jednorazowej kopii, z prawdziwymi zapisami.

```json
{"runtime": {"scenarios": [{
  "id": "note-save", "session": "screen",
  "steps": [{"goto": "/notes"}, {"fill": "input[name=text]", "value": "Notatka"},
            {"click": "button[type=submit]"}, {"expect_text": "Notatka"}]
}]}}
```

Kroki (do 40, scenariuszy do 20): `goto`, `click`, `fill` z `value`, `press`,
`wait_for`, `expect_path`, `expect_text`, `request` (metoda, ścieżka, `json`;
z opcjonalnym `capture` wartości z odpowiedzi przez JSON Pointer) i `capture`
(wartość z atrybutu albo tekstu elementu, pierwsza grupa wyrażenia). Przechwycona
wartość wraca jako `{nazwa}` w późniejszych ścieżkach i wartościach. Elementy są
szukane także w ramkach tej samej aplikacji. Żądania poza adres aplikacji są
odcinane.

`session`: `screen` (domyślnie, sesja roli ekranów) albo `none`. Pole
`save_session.routes_prefix` oddaje sesję po scenariuszu przeglądowi tras o tym
początku (np. ekrany hali po logowaniu PIN-em); plik sesji jest prywatny i
usuwany po części. Wynik (`data_states.scenarios`): `PASS`, `FAIL` z numerem
kroku i powodem bez wpisywanych wartości, `BLOCKED` bez wymaganej sesji; zrzut
ekranu w `visual/<n>/scenarios/<id>.png`.

## Projekt z frontendem i osobnym API, własne logowanie, role, worker

- **Zaplecze frontendu.** Gdy konfiguracja frontendu (vite, next, nuxt) przekazuje
  wskazane ścieżki do drugiej usługi, a w projekcie jest jedna część serwerowa w
  Pythonie, Helix uruchamia ją przed frontendem (instalacja, migracje na tej
  samej bazie, start) i daje obu wspólny adres przez rozdzielacz ścieżek na
  pętli zwrotnej. Raport części ma pole `backend`.
- **Część API** (FastAPI, Flask, Django bez ekranów): dostępność, Lighthouse i
  przegląd tras mają status `SKIPPED`.
- **Paczki Pythona** są instalowane w izolacji przez pośrednika, który
  przepuszcza tylko rejestr PyPI; interpreter w wersji deklarowanej przez projekt.
  Bez deklaracji, gdy paczka nie ma wydania dla domyślnego interpretera, Helix
  próbuje starszych zainstalowanych wersji.
- **Katalog główny**, którego skrypty tylko przekazują pracę do podkatalogu
  (`npm --prefix apps/web run dev`), nie jest osobną częścią.
- **Ustawienia z kodu.** Zmienna z wartością domyślną w klasie ustawień zostaje
  nieustawiona, wymagana dostaje wartość zgodną z typem, adres zewnętrznej
  usługi zastępuje zaślepka o tym samym schemacie.
- **Własne logowanie aplikacji.** Scenariusz z `save_session.as_screen_session`
  oddaje sesję wszystkim sprawdzeniom, gdy nie ma roli z Keycloaka; scenariusze
  idą wtedy przed sprawdzeniami. Scenariusz bez pola `part` dotyczy części z
  ekranami i nie biegnie dla części, która jest samym API. `after_sql` (do 10 poleceń) wykonuje krok w
  jednorazowej bazie po udanym scenariuszu, np. założenie konta syntetycznego.
- **Role.** Przy zadeklarowanej `screen_role` Helix zapisuje sesję każdej
  zalogowanej roli i ogląda te same trasy z każdą z nich
  (`data_states.roles`): ile tras rola otwiera, ile ją odsyła, ile odmawia,
  oraz lista różnic wobec roli ekranów. `denied_roles` wskazuje role, którym
  aplikacja ma odmówić sesji; wynik logowania każdej roli jest w `roles.login`.
  Różnica niesie kod odpowiedzi (`role_code`). Identyczny wynik wszystkich
  porównywanych ról na każdej trasie daje status `SUSPECT`: sesje ról mogły
  nie działać.
- **Worker** (część w Pythonie bez serwera HTTP): zależności instalowane w
  izolacji i własne testy części (`worker-tests`); demon nie jest uruchamiany.
  Gdy runner nie zbierze żadnego testu, wynik to `BLOCKED`; pliki testów będące
  zwykłymi skryptami właściciel wskazuje w `runtime.worker_scripts` (zaliczenie =
  kod wyjścia 0 każdego z nich).
- **`runtime.ui`** (`ladder`, `tap`, `tap_desktop`, `space`, `lead_max`):
  ustawienia wyglądu projektu dla przeglądu tras.
- **`runtime.seed_skip_tables`**, **`runtime.seed_rows`**: sterowanie zasiewem
  przepełnionym.
- **`runtime.setup_commands`** (`part`, `argv`): własne skrypty projektu tworzące dane startowe (role,
  uprawnienia), uruchamiane w izolacji po migracjach tej części; do 10 poleceń, tylko python, node, npm, pnpm, yarn.

## Przebieg próbny: `--quick N`

`helix runtime run --quick N` wykonuje wszystkie etapy (instalacja, baza, logowanie, scenariusze, przegląd
tras, role, Lighthouse, obciążenie, kopia) na `N` trasach każdej części plus po jednej trasie na każdą sesję
zapisaną przez scenariusz (`save_session.routes_prefix`). Tras ze wzorców nie odkrywa. Służy do sprawdzenia w
kilka minut, czy Helix przechodzi projekt od początku do końca, zanim ruszy pełny przebieg na godziny. Raport
ma wtedy pole `quick` (`routes_per_part`, `omitted` z liczbą pominiętych tras na część) i nie jest oceną projektu.

Scenariusz właściciela ma test uruchamiany pod strażą sieciową przebiegu
(`tests/node/scenarios.test.mjs`): żądania do aplikacji muszą wychodzić z przeglądarki, bo proces Node pod
strażą ich nie wyśle.

## Aplikacja na Supabase

Część z `supabase/config.toml` i klientem `@supabase/supabase-js` dostaje lokalny stos Supabase (baza, logowanie,
API, pliki, realtime) zamiast własnego PostgreSQL przebiegu. Plan pokazuje to w polu `supabase` części.

- **Bez wyjścia na zewnątrz.** Kontenery stoją w sieci Dockera `--internal`; przed startem Helix sprawdza z tej sieci,
  że połączenie z adresem publicznym się nie udaje, i bez tego dowodu stosu nie uruchamia. Dostęp z hosta dają dwa
  przekaźniki portów na pętli zwrotnej. Powód: migracje projektów często planują zadania `pg_cron`, które wołają
  produkcję po adresie wpisanym na stałe.
- **Migracje.** Adresy zewnętrzne i tokeny JWT w kopii migracji są zaślepione. Pliki idą w kolejności znacznika czasu
  niezależnie od formatu nazwy, każdy błąd jest zapisany przy pliku (`supabase.migrations`), a stosowanie biegnie dalej.
- **Schemat spoza migracji.** Tabele i typy, których nie tworzy żadna migracja, Helix odtwarza z typów aplikacji
  (`src/**/supabase/types.ts`); po migracjach dokłada kolumny i powiązania znane typom. Wynik to przybliżenie
  (`fidelity: approximate`): bez ograniczeń, funkcji i polityk spoza migracji. Konto syntetyczne czyta wtedy dane z
  pominięciem polityk dostępu, więc raport nie mówi nic o uprawnieniach ról.
- **Kod aplikacji.** W kopii roboczej adres projektu i jego klucz publiczny wpisane na stałe wskazują lokalny stos
  pod tym samym adresem co ekrany (rozdzielacz ścieżek `/auth/v1`, `/rest/v1`, `/storage/v1`, `/functions/v1`,
  `/realtime/v1`). Adres produkcji pozostały w kodzie zatrzymuje przebieg.
- **Logowanie.** Helix zakłada konto syntetyczne, wiersz w `profiles` (identyfikator, adres, pola zgody; pozostałe
  wartości z `runtime.supabase.profile`, np. `{"role": "it"}`) i oddaje sesję wszystkim kontrolom.
- **Funkcje serwerowe** nie startują (wołają systemy zewnętrzne); kontrola kopii bazy ma status `SKIPPED`.
- **Zależności.** Paczki spoza rejestru npm tylko z hostów znanych Helixowi albo z `runtime.dependency_hosts`. Gdy
  `npm ci` pada na konflikcie zależności równorzędnych, Helix instaluje wersje z pliku blokady plus brakujące paczki
  i zapisuje ustalenie w `logs/dependencies-*.log`.
