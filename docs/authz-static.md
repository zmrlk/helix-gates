# Statyczne authz — 0.7.2-beta

`helix review deep PATH --auth-sanity-percent 30` używa wspólnego detektora,
bez wykonywania kodu projektu. `effective_guard` zawiera stan i lokalizacje,
wykluczone selektory oraz nierozstrzygnięte granice frameworka.

VERIFIED (fixtures w `tests/fixtures/authz-precision/frameworks.json`): adaptery
obejmują literalne Next matcher (prefiksy, globy, parametry), SvelteKit hooks
z sequence i grupami route.id, granice Nuxt server middleware, kolejność i prefiksy
Express/Hono, Fastify preHandler, NestJS UseGuards, lokalne Django urls→views
z dekoratorami i grupy middleware Laravel. Dynamiczne selektory i regexy
pozostają unknown. Kandydat guarda nie dowodzi ochrony; wykluczony matcher
nie oznacza automatycznie braku innych guardów.

`+layout.server` nie chroni endpointu ani akcji; dla load zależność od parent
pozostaje unknown. Nie wnioskujemy ochrony API z renderowania layoutu Next.
`proven-guarded` oznacza wyłącznie wąski dowód lokalnej, bezpośredniej odmowy
braku użytkownika na początku handlera; nie jest dowodem zakresu wierszy.
`unknown` to brak rozstrzygającego dowodu. `unguarded` jest zarezerwowane dla
potwierdzonego braku guarda (import niezależnego werdyktu trasy); sama
nieobecność dopasowania nie nadaje tego stanu.
Odrzucenie alarmów ≠ dowód poprawności authz. Brak dowodu daje 0 pkt.

ASSUMPTION: kompletność poza fixtures. Brak pełnej analizy AST/dominacji,
dynamicznych rejestracji, dowolnych matcherów SvelteKit i grafu importów
między aplikacjami. Nie nadajemy im pozornej pewności. Brak kandydatów nadal
daje jeden alarm z licznikiem, przykładami i sanity gate, bez masy HIGH.

SEC-TOKEN-TOCTOU nadal wskazuje oddzielony odczyt, sprawdzenie zużycia i zapis;
heurystyka atomowości nie zastępuje testu równoległego zużycia tokenu.
Format weryfikacji i trwałe statystyki: [precyzja review](review-precision.md).
