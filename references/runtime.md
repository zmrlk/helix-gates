# Helix · Runtime: UX PASS, kody wyjścia, Keycloak, HTTPS, WebAuthn, polityka tożsamości

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

Nie opieraj akceptacji na starym UX PASS po rozpoczęciu nowej próby. Bieżący
raport ma PARTIAL do ukończenia, a `historical_sources` nie dowodzą aktualnych
wywołań. Samo `ux report` agreguje historię. Dla runtime rozróżniaj kody 0
(pełny PASS), 2 (pełny wykonany FAIL) i 3 (niepełny przebieg). Kod błędu release
i repo-hygiene jest wiążący także wtedy, gdy raport udało się wydrukować.

Przypomnienie o audycie działa bez modeli i sieci: `helix --repo /code/app
--state-dir /audits/app/state --offline status --reminder-only` pokazuje liczbę
commitów od ostatniego kompletnego przeglądu i polecenie `daily`/`release`.
Brak poprawnego dowodu oznacza nieznaną zaległość i zalecenie `full`, nigdy zero.
`status --json` udostępnia szczegóły; lokalne zmiany pozostają widoczne nawet
przy tym samym SHA. Tylko jawne `helix hooks install --post-commit` instaluje
odczytowy hook, bez zastępowania istniejącego pliku i bez uruchamiania skanu.
Przekaż ten sam zewnętrzny `--state-dir`, którego używasz do deep.

Metadane i plan deep używają wspólnego odczytu Git, który nie uruchamia
filtrów ani fsmonitor i nie dziedziczy `GIT_DIR`/`GIT_WORK_TREE` innego repo.
Przy filtrach lub podmodułach znany SHA pozostaje w raporcie, a stan zmian
ma `dirty=null` i wyjaśnienie. Taki wynik nie przesuwa kursora COMPLETE;
plan przyrostowy odmawia niebezpiecznej różnicy i wskazuje pełny plan.
Inwentarz źródeł zachowuje odczyt nazw bez wykonania kodu celu.

`helix --config /audits/app/helix.proposed.json --offline runtime plan
--project /code/app --json` pokazuje mapę integracji, strategie i miejsca
w kodzie bez uruchamiania usług. Raport runtime oddziela konkretne pomiary
od pokrycia zależności; readiness nie zalicza trasy, a jawne luki lub brak
starego inwentarza dają kod 3. Pełny wykonany FAIL daje 2. Szczegóły i kontrakt
dowodów: [integracje runtime](../docs/runtime-integrations.md).

Izolacja procesów runtime: kod projektu, instalatory, migracje i pomiary wymagają
osobnego admission. Sonda lokalna i hash polityki to dowód mechanizmu w jej zakresie;
`synthetic_test` nie daje potwierdzenia OS ani pełnego PASS. Serwer bazy wymaga własnej
izolacji niezależnie od `psql`; nie przechodź na niechroniony backend po odmowie.
Brak lokalnych pakietów nie zezwala na sieć instalatora. Historyczny brak dowodu
pozostaje nieznany. [Kontrakt i ograniczenia](../docs/runtime.md#process-network-admission).

Lokalne wysyłki: `sink_plan` i `sink_observations` rozdzielają plan,
odbiornik oraz zarejestrowane przyjęcia i odmowy. Odpowiedź emulacji nie
zalicza doręczenia ani trasy aplikacji. Zachowuj braki konfiguracji w bazie,
DNS odbiorcy, syntetycznej subskrypcji i niewspieranych transportów; nie
uruchamiaj prawdziwych webhooków potwierdzających ani pobierania mediów.
[Zakres adapterów](../docs/runtime-integrations.md#lokalne-skrzynki-wysyłek).

Keycloak: `runtime plan` exposes a public `identity_plan` per part from the already-read sources. READY is a complete blueprint only, never a login receipt. Keep dynamic values, conflicts, unknown role claims and unsupported server versions BLOCKED; never reuse an admin client as the application client, import real users or read actual .env values. External `runtime.keycloak.parts` can supply non-secret declarations; [contract](../docs/runtime-integrations.md#plan-tożsamości-keycloak).

Keycloak execution: require the local pinned image, READY blueprint and valid per-part `env_roles`; never replace a known Keycloak with the generic OIDC stub. Keep synthetic credentials private, distinguish IdP origin/issuer from app origin, record actual readiness and owned cleanup, and retain incomplete route coverage. `keycloak-readiness` does not run the emulator auto-login flow or establish a login result. [Contract](../docs/runtime-integrations.md#wykonanie-lokalnego-keycloaka).

Lokalny HTTPS: czytaj `transport_plan` i zachowuj jawne `runtime.https`.
`new audit` zapisuje propozycję poza celem, bez zaliczania wykonania. Publiczny
origin musi być ustalony przed buildem i klientem IdP; zmiana callbacku lub
portu jest blokadą, nie automatyczną naprawą. Używaj wyłącznie własnego CA/SPKI.
Gotowość frontu nie jest dowodem logowania, Secure cookies ani WebAuthn;
[zakres i ograniczenia](../docs/runtime-integrations.md#lokalny-https-i-cookies).

Keycloak form phases: accept only receipts bound to the current plan/run and
synthetic identity, with a fresh browser context per role. `form_status=PASS`
never establishes an application session or protected-route authorization.
Keep negative variants and missing phases NOT_RUN without an explicit policy
test, and preserve transport/identity gaps through Pro and owner reports.
Never publish private credentials, OAuth query values or storage state.
[Phase contract](../docs/runtime-integrations.md#fazy-formularza-keycloak).

Polityka sesji i tras: `runtime.identity_policy` jest jawnym kontraktem, nie
wnioskiem z nazwy roli lub URL. `runtime plan` zachowuje osobne komórki ról,
luki i config_pointer; PLANNED nie oznacza wykonania. Nie przyjmuj receipts
wykonania bez obsługiwanego kontraktu i nie zamieniaj nieznanych liczników
historycznych w zero. [Konfiguracja i granice](../docs/runtime-identity-policy.md).

Wykonanie polityki ma osobny `identity_policy_executions`: porównaj aktualne
plany i próbę, anonimową odmowę, tożsamość i role sesji oraz oczekiwanie każdej
komórki GET. Zachowaj jednocześnie wykonany FAIL i niepełne pokrycie. Wynik
wybranej macierzy nie zamyka tożsamości bez przypadków ani innych tras.
Nie publikuj odpowiedzi JSON, danych logowania lub stanu przeglądarki.

Ogólny emulator OIDC daje obserwacje, nie dowód sesji: dowolny cookie,
przekierowanie lub 200 nie zaliczają tożsamości ani uprawnień. Bez jawnej
polityki zachowaj BLOCKED/NO_EXPLICIT_IDENTITY_POLICY. Nie przenoś dawnego
storageState lub `.session` do innych pomiarów ani k6; historyczny auth-flow
PASS bez powiązanego kontraktu jest jawną luką, bez punktów przy imporcie.

WebAuthn: deklaracja biblioteki lub profilu urządzenia nie dowodzi ceremonii.
Czytaj `webauthn_plan`, zachowuj brak jawnego flow, wyłączenie i nieustaloną
część jako luki. PLANNED nadal ma NOT_RUN, a legacy liczniki nieznane.
Nie wymyślaj tras lub locatorów ani nie zmieniaj jawnego `enabled:false`.
Wykonanie czytaj osobno z `webauthn_executions`: własny klucz CDP, przyjęta
rejestracja, logout i świeża odmowa sesji, logowanie tym samym kluczem oraz
nowe sondy sesji i wybranych GET. PASS wymaga końcowych dowodów formularza,
polityki i cleanup; przerwane obserwacje nie zaliczają pełnego przebiegu.
Wykonany FAIL zachowaj także przy INCOMPLETE. Wariant dodatni application RP
localhost i verify POST nie potwierdza negatywnych prób UV ani fizycznego klucza.
[Konfiguracja i granice dowodu](../docs/runtime-webauthn.md).
