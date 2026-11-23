# Helix · Duże repo: plan, modele, skan przyrostowy, obciążenie maszyny

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

## Duże repo: plan, modele i skan przyrostowy

Konfigurację można przechowywać poza projektem: `--config /audits/helix.json`.
Pin `helix_version` musi odpowiadać uruchomionej wersji. `--state-dir /audits/app`
przechowuje dostępność modeli, postęp, cache i ostatnią kompletną rewizję.
`--offline` nie pobiera reguł ani danych, nie wywołuje modeli i nie uznaje
pominiętej kontroli za PASS. `doctor --offline` sprawdza rzeczywiste `--version`
narzędzi i podaje zredagowaną przyczynę awarii, np. `ca-certs: empty trust anchors`.

```sh
helix --repo /code/app --config /audits/helix.json --state-dir /audits/app providers --refresh
helix --repo /code/app --config /audits/helix.json --state-dir /audits/app providers --plan
helix --repo /code/app --config /audits/helix.json --state-dir /audits/app --offline security deep --mode full --plan
# Pierwszy pełny przebieg, np. na noc, po odczytaniu planu:
helix --repo /code/app --config /audits/helix.json --state-dir /audits/app security deep --mode full --yes
helix --repo /code/app --config /audits/helix.json --state-dir /audits/app security deep --mode daily
helix --repo /code/app --config /audits/helix.json --state-dir /audits/app security deep --mode release
```

`full` czyta cały plan, domyślnie z trzema hunterami i bez limitu czasu;
szacunek ponad godzinę wymaga `--yes`. `daily` bierze różnicę od ostatniego
kompletnego commita, bez limitu czasu. `release` bierze tę różnicę w kolejności
ryzyka z domyślnym limitem 30 minut. Jawne `--since REF`, `--jobs N` i
`--budget time=10m,calls=50` nadpisują ustawienia trybu. Bez kompletnej bazy
i bez jawnego `--since` daily/release proponuje full zamiast uruchamiać go po cichu.
Znacznik kompletnej rewizji nie jest przesuwany po partial, przerwaniu ani dla
niezatwierdzonego drzewa, którego HEAD nie opisuje analizowanych źródeł.

Plan podaje partie, bajty, przedział liczby wywołań, priorytety i szacowany czas
na podstawie wcześniejszego tempa. Bez pomiaru czas jest nieznany. Budżet obejmuje
łącznie huntery, weryfikatorów, próby błędne i ponowienia. Zapis odbywa się po
każdej próbie i partii; `--resume /audits/run` wznawia zgodny checkpoint.
Cache dotyczy zwalidowanych odpowiedzi hunterów, treści i kontekstu źródeł oraz
wersji promptu/modelu. Weryfikator pracuje ponownie; cache nie dowodzi bezpieczeństwa.
Raport rozróżnia `not_checked`, `blocked`, `inconclusive` i ukończone jednostki.

`providers --refresh` wykonuje krótką odpowiedź JSON każdego skonfigurowanego
modelu, z datą i diagnostyką. Login ani katalog dostawcy nie są dowodem.
`providers --plan` czyta zapisane wyniki i wyjaśnia przydział ról.
Jawne role i modele pozostają niezmienione; brak dostępności daje propozycję,
bez cichego przełączenia. Rodziny to OpenAI (codex), Anthropic (claude,
claude-via-agy), Google (gemini, gemini-flash) i xAI (grok-cli).
Weryfikator i recenzenci muszą być z innej rodziny niż autor. Brak niezależnej
rodziny daje LIMITED i nie zalicza wymaganej bramki review.
Kolejność preferencji jest polityką Helixa, nie wynikiem benchmarku:
planista Claude → Codex → Gemini → Grok; implementer/hunter Codex → Claude →
Gemini → Grok; verifier Grok → Gemini → Claude → Codex; review Gemini → Claude →
Grok → Codex; visual judge Gemini → Codex → Claude → Grok. Warianty via-agy
są po natywnym Claude; gemini-flash jest na końcu z wyjątkiem visual judge,
gdzie poprzedza Groka. Nazwy modeli bierze konfiguracja.
Security deep korzysta z tego samego planu: każdy dostępny provider JSON może
być hunterem, a verifier musi należeć do innej rodziny. Jawne `--hunter`
i `--verifier` zachowują wybrany model; brak świeżego dowodu przed startem
lub wznowieniem daje LIMITED i propozycję `providers --refresh`.
Alias agy nie zmienia rodziny modelu Claude/Gemini. Model agy bez znanej nazwy
nie potwierdza niezależności. W długim przebiegu dopuszczony na starcie model
może dalej pracować, a poprawna odpowiedź odświeża tylko jego lokalny dowód.
Raport zapisuje plan, dowody początkowe i rzeczywiste wykonania osobno.

`owner-report --evidence /audits/runs --out /audits/OWNER.md` agreguje skany,
bramki, weryfikację, pokrycie i koszt bez ręcznego owner-input. Przebiegi i rewizje
pozostają osobne; nieznany koszt nie jest zerem. Tryb walidacji starego kontraktu
jest dostępny przez jawne `--input helix-contracts.json`.

## Obciążenie maszyny

Respektuj `resources` oraz raportowane skuteczne jobs w deep/UX/runtime/testach.
Critical wstrzymuje nowe partie, nie zabija aktywnych procesów. Czas pauzy
zużywa budżet; po domyślnych 300 s powstaje częściowy wynik do wznowienia.
Nie uznawaj przerwanych/niesprawdzonych jednostek za PASS i nie zmieniaj
VUs, czasu pomiaru ani progów SLO z powodu obciążenia. Zapisy decyzji,
konfiguracja i brakujące pomiary: [resources](../docs/resources.md).
