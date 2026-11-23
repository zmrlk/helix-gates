# Security deep — precision/recall

VERIFIED: lokalny test `python3 -m unittest discover -s tests -p test_static_security.py`
przechodzi dla ręcznie oznaczonego manifestu `tests/fixtures/security-deep/expected.json`.
Analizator nie generuje etykiet oczekiwanych.

| Korpus | TP | FP | FN |
|---|---:|---:|---:|
| SvelteKit | 3 | 0 | 0 |
| React/Next | 5 | 0 | 0 |
| Vue/Nuxt | 3 | 0 | 0 |
| Express + SQL | 16 | 0 | 0 |
| Bezpieczne odpowiedniki | 0 | 0 | 0 |
| Razem | 27 | 0 | 0 |

Precision = 100%, recall = 100% **wyłącznie w tym syntetycznym korpusie**.
FN=0 i FP=0 są egzekwowane przez test; to nie estymacja jakości na obcym projekcie.
Jednostką jest trójka (plik, linia, reguła), nie liczba exploitable podatności.
Manifest obejmuje brak guarda, późny guard, IDOR, mass assignment, role, fail-open,
bypass developerski, SQL/HTML/shell/path/SSRF/redirect/Host, upload, OTP,
GRANT/RLS/SECURITY DEFINER. Bezpieczne warianty obejmują guard i owner scope,
parametryzację SQL, stałe cele sinków, escapowany tekst i bezpieczny search_path.

Dodatkowe testy sprawdzają dziewięć soczewek z istniejącym UX/UI, deduplikację,
ranking, izolację guardów między handlerami, brak wykonywania kodu celu, symlinki,
ukryte/prywatne pliki, komentarze, częściową walidację uploadu, cykle importów,
TODO i martwe linki, lokalne advisory/lockfile oraz redakcję metadanych skanu.
Nie wlicza się ich do powyższej macierzy, bo nie są oznaczonym korpusem precision.
