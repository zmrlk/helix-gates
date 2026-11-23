# Adaptery runtime

Helix wykrywa integracje z repozytorium i konfiguracji projektu. Nie zna tabel,
tras mostka ani nazw tokenów konkretnej aplikacji. Plan jest deklaracją;
przechwyt lokalny, działający kontener i test rzeczywistego dostawcy to różne dowody.

## Rejestr i konfiguracja

[data/integrations.json](../data/integrations.json) zawiera 50 dostawców i trzy
presety kontenerów. Wpis ma `provider`, `family`, `packages` (npm/pypi/go/composer/gem),
`hosts` (hosty lub globy), `env_patterns` (ograniczone regex), `default_strategy`.
Rodziny: payments, storage, email, sms, push, ai, identity, queue, scheduler,
erp, observability, chat. Opcjonalne `code_patterns` i `file_patterns` pozwalają
wykryć deklaracje schedulerów. Manifesty i kod są czytane, nigdy importowane.
Rejestr jest ładowany raz na proces; jego SHA-256 jest częścią powiązania planu.

Przykład rozszerzenia bez zmiany kodu Helixa:

```json
{
  "runtime": {
    "integrations": {
      "learning": true,
      "custom": [{
        "provider": "acme-payments", "family": "payments",
        "packages": {"npm": ["acme-sdk"], "pypi": ["acme-payments"]},
        "hosts": ["api.acme.invalid"], "env_patterns": ["^ACME_"],
        "default_strategy": "http-sink"
      }],
      "acme-payments": {"strategy": "http-sink", "response": {"status": 201, "body": {"id": "synthetic"}}}
    }
  }
}
```

Jawny wpis custom oznacza akceptację; `accepted:false` pozostawia go nieaktywnym.
Nie można nadpisać istniejącego provider przez custom; strategię zmienia się
kluczem provider albo id integracji. Nazwy środowiska są sygnałem wykrycia,
nie automatycznym potwierdzeniem obsługi danej biblioteki.

## Cztery strategie

- `http-sink`: jeden silnik dla dowolnego API. Odpowiedź z `response` albo
  domyślne HTTP 200 `{}` z obserwacją `zaślepione`. Nie daje zaliczenia integracji.
- `record-replay`: `recordings` pod wybraną integracją; każde nagranie ma
  `synthetic:true`, `request:{url,method,body}` i `response:{status,body}`.
  Dopasowanie dokładnego URL, metody i treści JSON. Brak dopasowania: 502,
  bez przekazania do zewnętrznej usługi. Streaming/binary nie są obsługiwane.
- `container`: wspólny interpreter presetów `redis`, `mailpit` (SMTP), `minio`
  (S3). `preset` w ustawieniu albo `container` we wpisie rejestru. Wyłącznie
  lokalny obraz z przypiętym SHA-256, `--pull=never`, wewnętrzna sieć Dockera,
  port na loopback, tmpfs i usunięcie po przebiegu. Brak obrazu: BLOCKED.
  Jawna strategia lub `required_for_startup:true` zatrzymuje część aplikacji;
  sama propozycja pozostawia lukę usługi i pozwala sprawdzać niezależne trasy.
  Weryfikowane są proces i sieć; gotowość protokołu pozostaje `not_checked`.
  Zmienne endpointów/portów pochodzą z danych presetu. Aplikacja musi je
  respektować; minio nie tworzy automatycznie bucketów. Nic nie jest pobierane.
- `disable`: raport wymienia wyłączone integracje. Puste wykryte `CRON_*`,
  odmowa importu pakietów CommonJS/Python; hostowe schedulery nie są uruchamiane.
  ESM, bundlowane zależności i schedulery aplikacji wymagają osobnego dowodu.

Dawne nazwy `emulator`, `replay`, `disabled` pozostają zgodne ze starszą
konfiguracją i istniejącymi adapterami protokołów. Nowe integracje korzystają
z powyższych czterech strategii. Starsze tabele operacji też są danymi rejestru.

Transport Node: `fetch`, `http.request`, `https.request`; Python: `requests`.
Własne agenty/sockety, httpx, urllib, Go/PHP/Ruby i bezpośrednie gniazda nie
mają pełnego przechwytywania. Wykrywanie ich pakietów jest obsługiwane, wykonanie
pozostaje nietestowane. Nadal obowiązuje izolacja sieci systemu operacyjnego.
Nie należy traktować preload jako samodzielnej zapory.

Presety zawierają źródła digestów:
[Redis](https://hub.docker.com/layers/library/redis/7-alpine/images/sha256-fc0099e9af31874b5520788cf428630f72d82fa44cb775dcbebb382d803b8175),
[Mailpit](https://github.com/axllent/mailpit/pkgs/container/mailpit),
[MinIO](https://hub.docker.com/layers/minio/minio/RELEASE.2025-09-07T16-13-09Z-cpuv1/images/sha256-e08497cde44985e0c36cacd391c9723831293d789d569cc967685f2fe17a7463).
Dostępność obrazów i zgodność ich architektury nie są potwierdzone samym wpisem.

## Nieznany HTTP: nauka

`runtime.integrations.learning:true` przechwytuje obsługiwane wywołania na
nieznany host, zwraca 503 i zapisuje `generic-*.json`: host, metodę, kształt
ścieżki oraz nazwy pól query/body/headers. Wartości nie są utrwalane;
każdy segment ścieżki staje się `{segment}`, bo może zawierać identyfikator
lub sekret. Host pozostaje wymaganym kluczem rozpoznania. Maksymalnie 1000
obserwacji; żądania ograniczone rozmiarem. Brak odpowiedzi dostawcy i brak
połączenia do niego.

`observations[].proposal` jest propozycją wpisu `runtime.integrations.custom`
z `accepted:false`. Człowiek ustala rodzinę (domyślny placeholder: chat), hosty,
strategię i odpowiedź, następnie akceptuje wpis w konfiguracji. Samo wklejenie
propozycji nie aktywuje adaptera. Raport ma `nietestowane` / `not_checked`, także
po lokalnym 2xx. Akceptacja umożliwia użycie strategii, nie zalicza dostawcy.

## Pozostałe adaptery

- PDF: istniejące Chromium Linux/macOS, bez pobierania. `pdf-render` sprawdza
  syntetyczny HTML i sygnaturę PDF. Brak przeglądarki daje CHROMIUM_MISSING.
- TZ: `runtime.adapters.timezone`, jednoznaczna deklaracja Dockerfile/Compose,
  następnie UTC. Konflikt jest luką. Dodatkowy `timezone-utc` to osobny proces
  i smoke do trzech publicznych tras; `--keep` pozostawia NOT_RUN_KEEP.
- Manifest Python bez rozpoznanej części HTTP tworzy osobną część
  `python-worker`, niezależnie od nazwy katalogu. Helix instaluje jej zależności
  w izolacji i uruchamia jej własne testy (`test_*.py`, sprawdzenie
  `worker-tests`); demon workera nie jest uruchamiany, a sprawdzenia ekranowe
  i HTTP mają status SKIPPED. Nie dziedziczy testów frontendu.
- `sharp`/`satori`: ostrzeżenie o zależnościach renderera i platformie binariów.
  Obecność pakietu nie potwierdza zgodności architektury.

## Ustawienia i wywołania zwrotne projektu

`runtime.adapters.synthetic_rows` zawiera wyłącznie jawne rekordy
`{synthetic:true,table:"schema.table",values:{...}}`. Brak konfiguracji oznacza
brak dodatkowych INSERT. Nie ma wbudowanych nazw firm, tabel ani dostawców.
Dotychczasowy ogólny seed na podstawie schematu pozostaje oddzielnym krokiem.

`runtime.adapters.inbound_replay` to lista syntetycznych żądań do własnego
loopback aplikacji: `synthetic`, `path`, `method`, `body`, `expected_status`
i `headers:{"nazwa":{"env":"NAZWA_ZMIENNEJ"}}`. Bez przekierowań, produkcyjnych
adresów i domyślnych tras. Wynik `inbound-replay` potwierdza tylko HTTP;
trwały zapis/semantyka biznesowa wymagają asercji projektu. HTTPS tego helpera
pozostaje nieobsługiwany. Poprzednią konfigurację mostka konkretnego projektu
trzeba przenieść do tych jawnych pól; nie ma automatycznej migracji.

Przykład: [runtime-adapters.example.json](../templates/runtime-adapters.example.json).
Starsze `runtime.adapters.recordings` nadal obsługuje syntetyczny Node fetch;
provider musi pochodzić z rejestru. Nie ma ograniczenia do jednej firmy/API.

## Dowód testowy

`tests/test_runtime_generic.py` buduje dwa repozytoria w katalogach tymczasowych:
Django/Celery/Stripe/S3 i Node/Paynow/B2/BullMQ. Sprawdza rozpoznanie i strategie,
pięć ekosystemów, rozszerzenie custom, naukę bez wartości, silnik sink/replay,
komendy kontenerów i transporty Node/Python. Są to testy narzędzia, bez prawdziwych
SDK dostawców ani kontenerów. Osobny opt-in test loopback uruchamia rzeczywisty
serwer przechwytu i Node:

```sh
HELIX_RUNTIME_ADAPTER_TESTS=1 python3 -m unittest discover -s tests/integration -p test_runtime_generic_http.py
```

## Backup

`pg_dump --format=custom` → `CREATE DATABASE` z losową nazwą → `pg_restore
--exit-on-error --no-owner`. Dla każdej tabeli: liczba wierszy oraz MD5
posortowanego multizbioru MD5 kanonicznych JSONB wierszy. Ustawienie UTC
stabilizuje timestamptz; duplikaty wierszy wpływają na liczbę i checksum.
Równe liczności przy zmienionej treści dają FAIL. Brak tabel lub niepoprawny
odczyt też nie daje PASS. Stare wyniki bez checksum nie zaliczają restore
przy imporcie. MD5 służy wykryciu różnicy danych, nie dowodowi kryptograficznemu.
Agregacja jest przeznaczona dla małej syntetycznej bazy; duże tabele wymagają
strumieniowego porównania. Sekwencje/ACL/duże obiekty nie są objęte checksum.

Test rzeczywistej własnej bazy przez Unix socket (bez TCP):

```sh
HELIX_RUNTIME_PG_TESTS=1 python3 -m unittest discover -s tests/integration -p test_runtime_adapters_pg.py
```

Domyślnie pomijany w suite. Wymaga istniejących narzędzi PostgreSQL; test nie
instaluje pakietów i nie łączy się z bazą aplikacji. Wersja lokalnego serwera
jest dowodem testu narzędzia, nie zgodności z wersją projektu.
