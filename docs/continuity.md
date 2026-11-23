# Ciągłość agentów i środowisk

Stan należy do repo projektu. Skopiuj `templates/continuity/agent-policy.json`
do `.helix/agent-policy.json`, ustaw pin **uruchamianej** wersji (`helix --version`),
konwencje, bramki, komendy testów i zakazy. Alternatywnie użyj YAML; bez PyYAML
plik `.yaml` musi zawierać JSON. Nie instalujemy parsera automatycznie.
W `helix.json` można ustawić `continuity.directory` na katalog pod repo.
Nie używaj zewnętrznego `--state-dir` do synchronizacji ciągłości.

```sh
helix agents generate
helix agents check
helix handoff read --agent agent-b --env mac
helix claim take task-1 --agent agent-b --ttl 3600
helix claim list
helix claim release task-1 --agent agent-b --lease IDENTYFIKATOR_Z_TAKE
helix claim check
helix decisions add --agent agent-b --decision 'Używamy plików JSON' --rationale 'Przenośność'
helix decisions add --agent agent-b --decision 'Zmiana decyzji' --rationale 'Nowe dowody' --supersedes DEC-0001
helix decisions list
helix decisions check --base REF
helix handoff write --agent agent-b --env mac --done 'Dodano walidację' --evidence 'tests/test_module.py' --next 'Recenzja' --risks 'Odbiór oczekuje'
helix handoff check
helix continuity report --json --base REF
```

Generator nadpisuje AGENTS.md, CLAUDE.md i GEMINI.md: edytuj źródłową politykę.
Hash źródła i pełna zgodność treści wykrywają dryf; inny pin blokuje check.
Włącz `agents check` i pozostałe kontrole w istniejącym CI. Helix nie instaluje
hooków ani nie zmienia uprawnień. Sekcja „Dryf i ciągłość” trafia również do
`owner-report`; bez polityki pokazuje `NOT_CONFIGURED`.

Handoff sesji: `.helix/handoffs/<UTC>-<agent>.json` oraz `LATEST`.
`write --file templates/continuity/handoff.json` przyjmuje pola sesji z JSON
pod repo; CLI dopisuje czas i HEAD. `read` wyświetla stan, claims, decyzje i dryf,
a następnie zapisuje ack z hashem handoffu, agentem, środowiskiem i HEAD.
Nowy handoff unieważnia poprzednie ack. Check odrzuca brak ack i commity po
zapisanym HEAD, poza commitami samych handoffów/ack. Zapisz handoff po kodzie.
Zapis ten jest odrębny od `new handoff` (manifest produktu) oraz starego
`handoff --run-id ID [--out PLIK]` (HANDOFF.md przebiegu); obie komendy pozostają.

Claims mają TTL i losowy lease; release wymaga aktualnego lease i agenta.
Jeśli istnieje handoff, take wymaga ack tego agenta po `handoff read`.
Lokalne take używa wyłącznego pliku blokady. Domyślnie nie commituje;
`--commit` jawnie zapisuje wyłącznie plik tego claimu. `.helix` może być ignorowany:
trzeba świadomie wersjonować politykę, handoffy, ack, claims i decyzje (`git add -f`).
Nie wersjonuj całego lokalnego cache ani pamięci Helixa.
Po awarii lokalny `.lock` usuń dopiero po sprawdzeniu, że proces już nie działa.

Różne klony nie mają wspólnego atomowego locka. Przed implementacją: pull,
take, commit, zwykły push. Wygrywa przyjęty push; odrzucony non-fast-forward
wymaga pull, sprawdzenia claims i rezygnacji z kolizyjnej pracy. **Nigdy force**.
`claim check` wykrywa także dwa aktywne lease w rodzicach merge, nawet jeśli
rozwiązanie konfliktu zostawiło tylko jeden plik. TTL ogranicza czas ochrony;
lease nie jest blokadą systemu plików ani zdalnym koordynatorem.

Decyzji nie zmieniaj ani nie kasuj. Nowa decyzja wskazuje `supersedes`.
Check porównuje pliki z dostępną historią git (również zmiany potem cofnięte).
Pełny klon jest konieczny: przepisanej lub niedostępnej historii nie da się dowieść.
Reguły polityki: `rules: [{id, kind, glob, pattern}]`, gdzie `kind` to
`forbidden_file`, `forbidden_pattern` lub `required_pattern`; wzorce są regexami,
glob wybiera pliki, id może wskazywać DEC. Kontrola pokazuje commit i autora.
`--base REF` wybiera zakres; bez niego reguły używają `diff_base` z polityki lub
pierwszego osiągalnego commita. Sprawdzane są też zmiany śledzone w worktree.
To jawne reguły, nie semantyczny dowód przestrzegania dowolnego tekstu decyzji.

Między maszynami: zwykły git bez force; dostawy poza git wyłącznie jawnie wskazanym
kanałem, na żądanie. Konwencja paczki: unikalne ID, kierunek i czas UTC,
allowlista oraz manifest SHA-256; incoming → kontrola hashy, dodatkowych plików
i symlinków → releases + receipt + CURRENT. Kolizja ID oznacza nową paczkę,
bez nadpisywania. Ten moduł nie kopiuje danych do tego kanału i nie przyjmuje
paczek automatycznie. Nie eksportuj SSH/VPN, sekretów ani prywatnej pamięci.
Walidacja odrzuca typowe formaty kluczy, tokeny, hasła i URL z poświadczeniami;
heurystyka nie stanowi gwarancji wykrycia każdego sekretu.
