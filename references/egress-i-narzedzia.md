# Helix · Deklaracja wysyłki danych; plan i instalacja narzędzi

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

### Deklaracja wysyłki danych

Decyzja właściciela z 15.11.2026: bez deklaracji
`data_egress` albo przy `status=pending_owner` Helix wysyła treść projektu do wszystkich dostawców
ze swojej konfiguracji i nie pyta o zgodę. `helix new` nie dopisuje pytania o wysyłkę.
Jawnie zatwierdzona deklaracja właściciela (`status=approved`, `allowed_providers`) ogranicza dostawców:
odmowa zapada przed procesem, budżetem i pamięcią podręczną, bez cichego zapasowego dostawcy.
Tryb `--offline` odmawia wywołań modeli. Pliki z sekretami nie trafiają do promptów
(`helix_audit_context.DENY`). Nie reinterpretuj starej listy ścieżek `allowlist` jako zgody ani ograniczenia;
niepoprawna deklaracja daje błąd do poprawienia. Cache wymaga aktualnego skrótu polityki i dowodu użytej roli/modelu.
Nie zakładaj nowych blokad wysyłki bez polecenia właściciela.
[Kontrakt i przykład deklaracji](../docs/data-egress.md).


### Plan i instalacja narzędzi

Zacznij od `helix tools plan`: deklaracja w GROUPS, kod runnera, program na
PATH, zarządzana instalacja i wykonanie skanu to osobne stany. Plan działa
bez pinu/configu projektu i nie uruchamia programów. Brak narzędzia lub
runnera zachowaj jako lukę pokrycia, również w owner-report.

`helix tools install --yes --tool ast-grep --tool knip --tool jscpd --tool squawk --tool mutmut`
używa pięciu przypiętych pakietów, wyłącznie w `~/.local/share/helix/tools`.
Bez jawnego --yes oraz w offline odmawia przed instalacją. Nie dodawaj
programów do PATH, nie instaluj ich w celu i nie uruchamiaj npx z automatycznym
pobieraniem podczas skanu. Stryker tylko w kopii z osobnym runnerem;
svelte-check/tsc/eslint pozostają w precheck. Smoke instalacji nie oznacza
wykonania projektu ani zgodności nowego pina z adapterem.
[Kontrakt, piny i granice dowodu](../docs/tools-install.md).


Nieudana instalacja narzędzi: czytaj `diagnostic` (etap, polecenie, kod
wyjścia i zredagowana przyczyna) oraz `runtime_selection`. Nie zamieniaj
awarii wheels w instalację toolchainu ani zmianę interpretera po cichu.
Sonda npm używa jawnego Node i osobnych pustych configów. mutmut wybiera
istniejący CPython3.12/3.13/3.11/3.10, z jawnym wynikiem wyboru; producent
raportu może sam działać na innej wersji. Brak dowodu wheels pozostaje
nieznany do rzeczywistego wykonania. Po poprawce wystaw nowe polecenie
instalacji dopiero po zielonej bramce i commicie, zachowując poprzedni raport.
