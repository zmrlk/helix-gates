# WebAuthn w lokalnym runtime

Deklaracja SimpleWebAuthn oznacza zależność projektu. Nie dowodzi, że aplikacja
wykonuje rejestrację lub logowanie kluczem. `runtime plan` zachowuje miejsca
tej deklaracji, wersje zadeklarowane oraz jawne braki. Nie uruchamia przy tym
przeglądarki, modeli ani kodu projektu i nie czyta wartości rzeczywistych .env.

## Jawny przebieg

Konfiguracja `runtime.webauthn.parts` odwołuje się do już zaplanowanej roli,
sesji i przypadków GET z `runtime.identity_policy`. Wskazuje dokładne strony,
identyfikatory przycisków `test_id`, endpointy opcji i weryfikacji oraz
oczekiwany JSON akceptacji serwera. Sam status 200 nie jest takim dowodem.
Identyfikatory `policy_cell_ids` należy wziąć z bieżącego planu tej samej
części i tej samej roli.

Poniższy przykład jest syntetyczny. Nie opisuje tras projektu A:

```json
{
  "runtime": {
    "webauthn": {
      "schema_version": 1,
      "parts": {
        "frontend": {
          "enabled": true,
          "rp_owner": "application",
          "rp_id": "localhost",
          "role": "operator",
          "policy_cell_ids": ["cell-0123456789abcdef"],
          "registration": {
            "path": "/settings/passkeys",
            "action": {"test_id": "register-passkey"},
            "options": {"method": "POST", "path": "/api/passkeys/register/options"},
            "verify": {
              "method": "POST", "path": "/api/passkeys/register/verify",
              "http_status": 200,
              "json": [{"pointer": "/verified", "equals_literal": true}]
            }
          },
          "logout": {
            "path": "/account",
            "action": {"test_id": "logout"},
            "request": {"method": "POST", "path": "/auth/logout"}
          },
          "authentication": {
            "path": "/login",
            "action": {"test_id": "login-passkey"},
            "options": {"method": "POST", "path": "/api/passkeys/login/options"},
            "verify": {
              "method": "POST", "path": "/api/passkeys/login/verify",
              "http_status": 200,
              "json": [{"pointer": "/verified", "equals_literal": true}]
            }
          }
        }
      }
    }
  }
}
```

Pierwszy wariant dotyczy aplikacji jako RP `localhost`, z własnym lokalnym
HTTPS. Profil wirtualnego urządzenia jest stały: CTAP2/internal, resident key
i user verification. To **zadeklarowany profil**, a capabilities pozostają
`not_checked`, dopóki przeglądarka ich rzeczywiście nie potwierdzi. Wskazanie
innego RP lub WebAuthn obsługiwanego przez Keycloaka daje jawną lukę;
Helix nie przepisuje origin ani właściciela uwierzytelniania.

Wyłączenie można zapisać jako `{"enabled": false}`. Jest zachowane dokładnie,
ale nie stanowi zaliczenia pokrycia. Nieznane lub niebezpieczne pola są
odrzucane; brakujące deklaracje wskazują konkretne miejsce konfiguracji.
Nie ma eval, kodu JS z config, wildcard ani autoryzacyjnych nagłówków/body.

```sh
helix --config /audits/app/helix.json --offline runtime plan --project /projects/app --json
```

## Granice dowodu

Plan wiąże źródła, statyczny inwentarz, tożsamość, politykę sesji i transport.
Publiczne asercje mają tylko skróty oczekiwanych wartości. Projekcja sprawdza
członkostwo roli, części i komórek również po przeliczeniu hash, zanim przyjmie
plan do raportu. Wszystkie miejsca deklaracji pozostają zachowane.

| Sytuacja | Plan | Wykonanie i pokrycie |
|---|---|---|
| Zależność bez przebiegu | BLOCKED, część NOT_CONFIGURED | NOT_RUN, INCOMPLETE |
| Jawne wyłączenie | DISABLED | NOT_RUN, INCOMPLETE |
| Pełny spójny kontrakt | PLANNED | NOT_RUN, INCOMPLETE |
| Brak aktywnej deklaracji i konfiguracji | NOT_DETECTED | Brak nowego wymagania |
| Historyczny raport bez zapisu | NOT_RECORDED | Nieznane liczniki |

Aktywna deklaracja bez przypisanej części pozostaje widoczną luką. Deklaracje
z dokumentacji, legacy, testów i przykładów są zachowane osobno i same nie
wymuszają pomiaru aplikacji. Brak wykrycia w źródłach nie dowodzi nieobecności
funkcji w produkcji.

Raport zawiera `webauthn_plan` i puste `webauthn_receipts`. Te pola zachowują
znaczenie planu. Osobne `webauthn_executions` zapisują wykonanie, a wspólna
projekcja dla runtime, owner i Pro sprawdza jego powiązanie z planem oraz
bieżącą próbą. Nowy plan ma znane zero wykonanych ceremonii; brak historycznych
danych pozostawia liczniki nieznane. Biblioteka, plan lub profil urządzenia
nie przyznają punktów. Niepełny przebieg zachowuje `measurement_status`
pozostałych pomiarów, lecz ogólny runtime pozostaje INCOMPLETE.

`helix new audit` pokazuje stan obserwowany i proponowany z tego samego
snapshotu. Nie dopisuje domyślnie enabled=true, tras, locatorów ani ról. Brak
snapshotu podczas przygotowania nowego projektu oznacza NOT_RECORDED.

## Wykonanie dodatniego przebiegu

Własny wirtualny klucz Playwright działa w kontekście wskazanej syntetycznej
roli, po jej formularzu i kontroli sesji. Wykonawca używa tego samego budżetu
i pozwolenia zasobów, także przy jobs=1. Przechodzi przez zadeklarowane UI:

1. Rejestracja tworzy poświadczenie przez prawdziwe WebAuthn aplikacji.
2. Odpowiedź jej serwera spełnia jawne asercje akceptacji rejestracji.
3. Wylogowanie wysyła wskazane żądanie, a świeża kontrola sesji potwierdza odmowę.
4. Logowanie używa tego samego klucza i wymaga akceptacji serwera.
5. Nowe sondy sesji oraz wybranych przypadków GET potwierdzają właściwą
   tożsamość, dokładny zbiór ról i oczekiwany dostęp.

Obsługiwany format to bezpośredni standardowy JSON WebAuthn/SimpleWebAuthn,
z weryfikacją przez POST. Plan dopuszcza także GET, lecz wykonawca zapisuje
dla niego jawną lukę `UNSUPPORTED_REQUEST_FORMAT`. Nie zgaduje opakowanych
formatów odpowiedzi ani scenariusza z nazw plików. RP obsługiwany przez
Keycloaka, conditional UI i negatywne próby challenge, podpisu lub UV pozostają
poza tym dodatnim przebiegiem.

Opcje, zdarzenie własnego urządzenia i żądanie weryfikacji muszą zgadzać się
co do RP, origin, challenge, rodzaju ceremonii i poświadczenia. Samo HTTP 200
lub zdarzenie CDP nie wystarcza. Limit 1 MiB dotyczy JSON przyjętego do
weryfikacji, nie stanowi twardego limitu pamięci lub ruchu przeglądarki.
Wirtualne UV nie dowodzi, że serwer odrzuca błędne UV ani że użyto fizycznego
klucza lub biometrii.

Checkpointy zachowują wykonany FAIL i przerwane obserwacje. Dodatni wynik
wymaga końcowych dowodów formularza i polityki oraz usunięcia własnego
urządzenia, odłączenia CDP i zamknięcia strony oraz kontekstu. Niepotwierdzony
cleanup nie daje PASS i zatrzymuje nowe próby. Raport rozdziela wykonanie,
pokrycie oraz wynik, także dla FAIL przy niepełnym przebiegu. Wynik dotyczy
wybranej roli i tras, bez zaliczania pozostałych integracji.

Prywatne wejście ma uprawnienia 0600 i jest usuwane po wykonaniu. Publiczny
raport zawiera statusy, powiązania planu i losowy alias poświadczenia, bez
credentialId, userHandle, challenge, podpisu, clientData, tokenów lub cookies.
Zdarzenia CDP mogą zawierać klucz prywatny i nigdy nie są zapisywane w całości.
