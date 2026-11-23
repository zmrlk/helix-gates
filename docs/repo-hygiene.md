# Higiena repo i kolejka wydań

`helix repo-hygiene` czyta wyłącznie śledzone pliki bieżącego repo.
`--require-exact` włącza profil dokładnych wersji produkcyjnych Node.
Raport JSON i soczewka `repo_hygiene` zawierają wersję Helixa, schemat,
severity, pewność, przyczynę, poprawkę i dowody plik:linia. Kandydaci mają
zero punktów. Brak parsera lub wykonania daje not-run; nie oznacza N/A.

Kontrole: markery konfliktów, manifest/lockfile Node, obecność lockfile Python/Go,
numery migracji (osobno katalogi; timestampy bez kontroli luk), ID w tablicach JSON,
.gitignore, duże pliki, backupy, mieszane końce linii, .editorconfig, CODEOWNERS,
licencja, TODO/FIXME bez ticketu na potencjalnie krytycznych ścieżkach, toolchain.
Zgodność semantyczna pnpm/yarn/Python/Go pozostaje not-run.
Markery i duplikaty są błędami; brak konfiguracji jest kandydatem do sprawdzenia
w profilu. Brak pliku wskazuje oczekiwaną ścieżkę:1, nie istniejący dowód.

## Wydanie

Źródłem wersji wykonawczej jest `bin/helix_contracts.py:VERSION`.
Generator projektu i jego schemat rozwiązują token `{{HELIX_VERSION}}`.
Istniejące piny projektów/przykładów są snapshotami; nie aktualizujemy cudzych repo.

- `helix release --dry-run --offline`: propozycja bez zapisów i sieci.
- `helix release --bump patch|minor --agent NAZWA`: claim release z TTL, fetch,
  kontrola historii origin/master, lokalnych tagów i zdalnego CHANGELOG,
  przygotowanie wersji i wpisu z commitów od ostatniego tagu.
- `--offline`: jawny snapshot lokalny, bez dowodu aktualności serwera.
- `helix release check --staged`: kontrola hooka przed commitem.
- `helix release check`: kontrola CI/wrappera; nie pobiera sieci.
- Po commicie wrappera: `helix release tag`; annotated tag lokalny.
  Tylko jawne `--push-tag` wysyła tag. W tym etapie nie wykonano tagowania.

Claim pozostaje aktywny do zakończenia przez wrapper/zwolnienia lub TTL.
Blokada modułu ciągłości serializuje wspólny checkout; nie dowodzi blokady
między niezależnymi klonami. Publikacja claimu między klonami oraz automatyczne
wpięcie hooków/CI pozostają długiem. Hook powinien wywołać powyższy check;
wrapper musi wymagać go przed scaleniem. Dokumentować wymagane kontrole i ochronę
gałęzi w repo projektu; zdalna konfiguracja nie jest weryfikowana offline.
Podpisy i konwencjonalne tematy commitów są SHOULD; weryfikacja podpisów oraz
semantyka rozwiązań merge pozostają not-run. Duże merge (30 plików lub 1000 linii)
są kandydatami do ręcznego przeglądu; próg nie dowodzi sposobu rozwiązywania konfliktów.

Lista `requirements/release-history.json` podaje dokładne SHA i powód dla
historycznych powtórek. Kolejny SHA tej samej wersji znów daje FAIL.
Nie zmieniono baseline wymagań ani nie zatwierdzono nowych waiverów.

Szablon hooka: `templates/hooks/pre-commit-release.sh` (nie zainstalowano).
Pin w `helix.json` jest sprawdzany w raporcie higieny; raport ciągłości ponadto
sprawdza istniejący pin w polityce agentów. Ostrzeżenia nie zmieniają pinów.

Przygotowanie wydania zapisuje snapshot claimu w `requirements/releases/VERSJA.json`.
Wrapper musi commitować ten plik z bumpem. Kontrola historii od jawnego
`_enforcement_base` wymaga takiego dowodu w każdym commicie zmieniającym wersję;
czas commita musi mieścić się w TTL. Dla wcześniejszych commitów obowiązuje
jawna historyczna lista powtórek. Snapshot nie uwierzytelnia autora: chronią go
przegląd i required checks. Po wygaśnięciu TTL trzeba przygotować nowy claim.
