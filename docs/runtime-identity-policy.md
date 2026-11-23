# Jawna polityka sesji i tras

Plan polityki jest odrębny od faz formularza Keycloak. Sam callback, cookie
lub odpowiedź 200 nie potwierdza zalogowanej sesji ani poprawnych uprawnień.
Konfiguracja `runtime.identity_policy` opisuje oczekiwania właściciela dla
syntetycznych tożsamości. Nie powstaje automatycznie z nazwy roli lub trasy.

Przykład do zewnętrznego pliku wskazanego przez `--config`:

```json
{
  "runtime": {
    "identity_policy": {
      "schema_version": 1,
      "parts": {
        "frontend": {
          "basis": "explicit_config",
          "session": {
            "path": "/api/session",
            "method": "GET",
            "http_status": 200,
            "anonymous": {"kind": "status", "codes": [401]},
            "assertions": [
              {"pointer": "/user/name", "equals_identity": "username"},
              {"pointer": "/user/roles", "equals_identity": "app_roles", "comparison": "set_exact"}
            ]
          },
          "cells": [{
            "id": "reader-items",
            "identity": {"role": "reader"},
            "request": {"method": "GET", "path": "/api/items"},
            "anonymous": {"kind": "status", "codes": [401]},
            "expected": {
              "access": "allow", "http_status": 200,
              "json": [{"pointer": "/kind", "equals_literal": "sample-list"}]
            }
          }]
        }
      }
    }
  }
}
```

To syntetyczny przykład, nie konfiguracja projektu A. Wskazana rola musi istnieć
w bieżącym planie tożsamości tej części. Plan sesji wymaga identyfikatora
powiązanego z syntetyczną tożsamością i dokładnego zbioru ról. Brak takiego
mapowania pozostawia BLOCKED, bez dopisywania endpointu do aplikacji.

```sh
helix --config /audits/app/helix.json --offline runtime plan --project /projects/app --json
```

Planer używa już odczytanych źródeł i niczego nie uruchamia. Zachowuje każdą
komórkę rola/trasa, także zablokowaną, oraz tożsamości bez zadeklarowanych
przypadków. Dwie różne role na tej samej trasie dają osobne komórki. Dla jednej
roli i dokładnego GET obowiązuje jedna komórka; kilka asercji należy zebrać
w jej tablicy. Kontrakt nie definiuje scenariuszy zależnych od kolejności.

Pierwszy wariant obsługuje GET bez body/query/fragmentu i anonimową odmowę
401/403. Odmowa roli używa `expected.access: deny` oraz
`denial: {"kind": "status", "codes": [403]}`. Pola JSON wskazuje dokładny
JSON Pointer, bez wildcard, eval, skryptów i nagłówków uwierzytelniających.
Redirect, UI assertions i tożsamości negatywne wymagają osobnego kontraktu;
nie są po cichu interpretowane jako poprawny test.

Publiczny `identity_policy_plan` wiąże skróty źródeł, planu tożsamości i jawnej
polityki. Oczekiwane wartości literalne mają tylko skróty; surowa konfiguracja
pozostaje poza raportem. `config_pointer` wskazuje konkretne pole konfiguracji,
a nie zmyśloną linię kodu. Walidator sprawdza również przynależność roli,
części i identyfikatora, ponieważ sam zgodny hash nie dowodzi spójności.

| Stan planu | Znaczenie |
|---|---|
| PLANNED | Jawny kontrakt skompilowany; testy niewykonane |
| BLOCKED | Kontrakt ma nierozwiązane role, części lub wymagania sesji |
| NOT_CONFIGURED | Wykryto Keycloak, brak jawnej polityki |
| NOT_DETECTED | Brak deklaracji wymagającej tego adaptera w sprawdzonym zakresie |
| NOT_RECORDED | Historyczny artefakt nie zawiera planu |

W etapie planowania wykonanie i pokrycie są NOT_RUN, a liczba wykonanych
komórek wynosi znane zero. Dla historycznego braku danych liczniki pozostają
nieznane. Raport właściciela oraz import Pro pokazują tę różnicę i nie dają
punktów za sam plan. Projekcja samego planu odrzuca niepuste receipts;
obserwacje wymagają osobnej walidacji wykonania. Testy kompilatora nie
potwierdzają działania aplikacji.

Jawnie zamówiona polityka bez wykonania utrzymuje ogólny wynik runtime
INCOMPLETE. Wyniki już wykonanych kontroli pozostają osobno w
`measurement_status`; plan nie może przykryć niewykonanego zakresu przez PASS.

## Wykonanie sesji JSON i dokładnych GET

Wykonawca wymaga zgodnego bieżącego planu i prywatnej konfiguracji. Przed
logowaniem sprawdza anonimową odmowę na dokładnej trasie sesji i każdej
zadeklarowanej trasie zasobu. Następnie korzysta z nowego kontekstu formularza
Keycloak dla jednej syntetycznej roli. W tym samym kontekście porównuje JSON
sesji z syntetycznym identyfikatorem i dokładnym zbiorem ról, a potem wykonuje
przypisane tej roli GET. Konteksty i cookies nie przechodzą między rolami.

Allow wymaga sesji właściwej tożsamości, oczekiwanego statusu, asercji JSON
zasobu i anonimowej odmowy tej samej trasy. Deny dla zalogowanej roli wymaga
najpierw dowodu jej sesji. Nieudany login i późniejsze 403 nie są dowodem
poprawnego RBAC. Redirect, 404, 5xx, błąd TLS oraz strona logowania z 200 nie
zastępują jawnego 401/403. Ten wariant nie realizuje kontraktów UI ani kont
negatywnych.

Wynik zapisuje osobne obserwacje sesji i komórek, powiązane z przebiegiem,
częścią, planami i świeżą próbą. Wyliczone pokrycie oznacza wykonanie wybranej
macierzy, a nie wszystkich ról i tras aplikacji. Tożsamości bez przypadków
pozostają widoczną luką. Wykonany FAIL pozostaje w raporcie również wtedy,
gdy inne przypadki przerwał limit czasu. Formularz ma nadal własny wynik
opisujący wyłącznie jego fazy.

Publiczny zapis nie zawiera odpowiedzi JSON, wartości asercji, haseł, tokenów,
cookies ani parametrów OAuth. Limit rozmiaru JSON ogranicza dane przyjęte do
asercji, a nie całkowitą alokację przeglądarki: Playwright buforuje odpowiedź
przed jej odczytem. Content-Length pozwala wcześniej odrzucić zadeklarowaną
zbyt dużą odpowiedź. Budżet czasu obejmuje oczekiwanie na zasoby, formularz,
sesję i trasy; cleanup własnych kontekstów jest wykonywany także po błędzie.
