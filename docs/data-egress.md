# Polityka wysyłki danych projektu

Decyzja właściciela z 15.11.2026: bez deklaracji
`data_egress` albo przy `status=pending_owner` Helix wysyła treść projektu do wszystkich dostawców ze swojej
konfiguracji. `helix new init/audit` nie dopisuje propozycji ani pytania. Istniejący obiekt konfiguracji pozostaje
niezmieniony; stara `allowlist` ścieżek nie jest ani zgodą, ani ograniczeniem i daje błąd do poprawienia.

Właściciel może ograniczyć dostawców jawną deklaracją, np.:

```json
{
  "data_egress": {
    "schema_version": 1,
    "status": "approved",
    "allowed_providers": ["codex", "grok-cli"],
    "exclude_paths": ["customer-data/**", "exports/**"]
  }
}
```

Identyfikatory dostawców są dokładne, takie jak w konfiguracji ról. Rodzina
`openai` ani wildcard nie zastępują `codex`. Fallback do innego dostawcy
wymaga osobnego dopuszczenia. Pusta zatwierdzona lista oznacza odmowę dla
wszystkich dostawców. Opcjonalne `approved_by` i `approved_at` są deklaracją,
bez niezależnego potwierdzenia tożsamości osoby zatwierdzającej.

Własne wykluczenia rozszerzają obowiązkowe wykluczenia plików środowiska,
sekretów, poświadczeń, seeds, fixtures, dumpów, kopii baz i kluczy. Dotyczą
także nazw w podkatalogach. Obsługiwane wzorce to względne ścieżki POSIX z
`*`, `**` i `?`; nie są poleceniami ani wyrażeniami regularnymi. Każde
wykluczenie pozostaje luką przeglądu, nawet gdy reszta pakietu jest gotowa.

Przygotowanie pakietu korzysta z już odczytanego snapshotu źródeł i jego
pokrycia. Manifest przechowuje dostawcę, hash polityki, ścieżki, hashe wersji
oryginalnej i po redakcji oraz powody pominięć. Nie zawiera treści źródeł,
wartości sekretów, danych dopasowanych przez redaktor ani nazwiska z pola
`approved_by`. Zmieniony hash źródła uniemożliwia przyjęcie jego treści.

Redaktor heurystyczny zachowuje numery linii. Maskuje wykryte poświadczenia
oraz dane osobowe; niejednoznaczne wartości wieloliniowe mogą wyłączyć cały
tekst. Dotyczy to również usuniętych linii dostarczonej różnicy. Nie daje
gwarancji wykrycia wszystkich nazwisk, adresów, kodowania lub składanych
wartości. Zredagowanych fragmentów nie wolno zaliczać jako przejrzanego kodu.

## Granica bieżącego kroku

Stan `PREPARED` opisuje przygotowanie pakietu. `INCOMPLETE` zachowuje luki,
a `delivery: NOT_SENT` oznacza brak wysłania przez ten etap. Liczniki wykonania
tego czystego helpera wynoszą zero: nie otwiera plików, nie uruchamia procesów,
modeli ani sieci. Nie opisują historycznych wywołań innych części Helixa.

Wspólna kontrola działa przed natywnymi wywołaniami Codex, Claude, Grok CLI
oraz aliasami AGY, a także przed ręcznym eksportem i wykonaniem deep.
Błąd deklaracji daje `ERROR`; przy jawnym ograniczeniu konkretny dostawca musi być na liście. Odmowa nie
uruchamia innego dostawcy. Tryb `--offline` odmawia. Cache deep jest powiązany ze skrótem obowiązującej polityki
(także domyślnej) i dowodem faktycznie użytej roli, dostawcy oraz modelu. Stary wpis bez tych pól nie jest przyjmowany.

Do 15.11.2026 obowiązywała tu przejściowa odmowa każdej wysyłki źródeł (`TRANSPORT_NOT_ADMITTED`,
`SOURCE_INPUT_NOT_ADMITTED`, commit `c256c96` z 26.10.2026). Była decyzją agenta, nie właściciela, i wyłączała
sędziego zrzutów, eksploratora UX, sprawdzenie prawdy i recenzje; została usunięta.

`providers --refresh` może nadal wykonać stałą neutralną sondę JSON bez
źródeł projektu. Korzysta z własnego jednorazowego kontekstu: dokładny
prompt, dostawca, model i tymczasowy katalog. Taki kontekst nie dopuszcza
źródeł, obrazów, innego katalogu ani ponownego wywołania. Dopuszczenie sondy
nie dowodzi odpowiedzi modelu ani systemowej izolacji CLI. Planowanie
`security deep --plan` i offline `new audit` nie wymagają zgody na wysyłkę.

Wykluczenia ścieżek mają segmentową semantykę POSIX: `**` dopasowuje zero
lub więcej katalogów w każdym miejscu wzorca, a `*` pozostaje w jednym
segmencie. `apps/**/internal/**` obejmuje też `apps/internal/file.ts`.
Domyślne wykluczenia sekretów/fixtures chronią również potomków katalogu,
którego nazwa pasuje do wzorca. Wykluczenie nadal pozostaje luką pokrycia.
