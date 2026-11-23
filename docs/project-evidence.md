# Dowody bramek projektu i moduły AI

`pro-evidence.json` mapuje wymagania Pro na własne bramki zadeklarowane
w `helix.json.custom_gates`. Nazwa bramki i obszar muszą pasować. Przykład:

```json
{
  "schema_version": 1,
  "controls": [{
    "requirement": "design-contract",
    "gate": "brand",
    "evidence": ["tests/brand.test.ts:1"]
  }]
}
```

To daje poziom **dowód lokalny, nieuruchomiony**, 0 punktów i widoczne
przygotowanie. Nie wymaga kopiowania selektorów consistency/design-contract
do projektu. Niezależnie od mapowania, pliki testów i konfiguracja CI bez
wykonania dają tylko preparation_score; wykonana punktacja testing/CI wynosi 0.

Opcjonalne `run` przy kontroli lub bramce modułu:

```json
{
  "status": "passed",
  "exit": 0,
  "who": "operator",
  "where": "local fixture",
  "command": "npm run test:brand",
  "sha": "pełny bieżący SHA Git",
  "log": "evidence/brand.txt",
  "log_sha256": "SHA256 bajtów logu UTF-8",
  "files": {"tests/brand.test.ts": "SHA256 pliku UTF-8"}
}
```

Wartości opisowe SHA powyżej należy zastąpić rzeczywistymi hashami. Każdy
cytowany plik musi występować w `files`; zmiana pliku, SHA, logu, brak pola
lub wynik nieuruchomiony/błędny odbiera punkty. Helix odczytuje lokalny Git,
ale nie wykonuje `command`. Importowane potwierdzenie nie dowodzi autentyczności
gospodarza ani produkcji; hashe obejmują jawnie wymienione pliki, nie pełny
niezależnie zaufany snapshot. Akceptacje brandu i waiverów pozostają osobne.

`helix new modules --input ai-modules.json` sprawdza:

```json
{
  "catalog": ["Button", "Table"],
  "modules": [{
    "id": "orders",
    "path": "src/Orders.tsx",
    "components": ["Button", "Table"],
    "gates": {}
  }]
}
```

Ten przykład ma FAIL/0 punktów: `gates` wymaga wykonanych `contract`, `tests`,
`permissions`, `appearance` oraz wszystkich własnych bramek projektu. Każde
`run.files` musi zawierać moduł. Moduły AI i ręczne mają ten sam kontrakt.
Komponent spoza katalogu blokuje. Inwentarz komponentów jest deklarowany;
kompletność importów i zgodność implementacji musi sprawdzić bramka contract.
`new audit` pokazuje stan modułów, `new check`/`handoff` blokują niespełnione
bramki, jeśli `ai-modules.json` istnieje. Brak pliku to NOT_CONFIGURED.

# Rezerwacje identyfikatorów

```sh
helix new ids reserve --prefix RULE --type rule --owner agent-a --purpose 'Kontrola brandu'
helix new ids list
helix new ids check
```

Domyślny rejestr to `helix-id-registry.json`, przeznaczony do wersjonowania.
Rezerwacja używa blokady systemowej i atomowej wymiany JSON; równoległe procesy
otrzymują kolejne numery. `--id RULE-0020` żąda konkretnego numeru i odrzuca
kolizję. Prefix ma jeden typ. Brak właściciela/celu, duplikat lub symlink
kończy się błędem bez zmiany danych. Plik `.lock` ma pozostać na miejscu;
zakończenie procesu zwalnia blokadę. Nie usuwamy ani nie odzyskujemy numerów.

Dla kilku worktree wszyscy autorzy wskazują ten sam absolutny `--registry`.
Oddzielne kopie rejestru nie dzielą blokady: po scaleniu trzeba wykonać `check`.
`new check` kontroluje również domyślny rejestr, jeśli istnieje. Rezerwacja
jest lokalnym zapisem danych; nie robi commita, push ani akceptacji właściciela.
