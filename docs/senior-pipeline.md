# Perspektywy, dojrzałość i dane

`helix review deep <ROOT> --format json` rozszerza istniejący raport o
`senior_pipeline` i `data_leak_audit`. Nie wykonuje kodu badanego projektu.
Macierz obejmuje dziewięć ról dla każdej wykrytej części i plików wspólnych.
Checklisty, narzędzia i hipotezy nadużyć: `data/senior-pipeline.json`.
Wspólne detektory działają raz; wyniki są przypisywane do części i ról.
Deduplikacja plik:linia/reguła zachowuje źródła i najwyższą severity.

Dojrzałość 0–5 i ocena pomocnicza są oddzielone od wykonania (0 bez logu).
Dowód częściowy ze struktury daje najwyżej 2. Brak dowodu to `not-run`,
bez poziomu dojrzałości, bez punktów i z długiem wykonania. N/A wymaga
powodu i wypada z mianownika. Kara severity obniża ocenę; HIGH/critical
blokują niezależnie. Brak blokera daje UNKNOWN, nigdy automatyczny PASS.
Fixture kalibracji poziomów nie dowodzi dojrzałości rzeczywistego produktu.

Mapa danych zwraca kategorie i lokalizacje, bez wartości pól, hostów i kodu.
Logi, URL, cache, eksport, odbiorcy zewnętrzni, bundle, błędy, overfetch,
debug i sourcemapy są kandydatami ASSUMPTION do weryfikacji. IDOR nadal
obsługuje istniejąca analiza security. Szkic DPIA wymaga potwierdzenia celów,
odbiorców i środków przez właściciela; nie stanowi oceny prawnej.
Audit trail pokazuje wrażliwe akcje, unknown dla kto/co/kiedy oraz trwałości.
Brak lokalnego wywołania audytu daje kandydata; obecność nie dowodzi pokrycia.

Adaptery nie są uruchamiane automatycznie: status `not-run` i powód są jawne.
`helix tools scan` korzysta z istniejącego runnera na kopii; narzędzia wymagające
bazy online pozostają pominięte z powodem. Nie instalujemy zależności.
Ograniczenia: brak pełnego taint między plikami, dowodu WORM i wykonania
scenariuszy adversarial. Prywatne ścieżki i symlinki wyklucza wspólny inwentarz.

Fixtures projektów surowy/średni/dojrzały mierzą wyłącznie dostępność dowodów
statycznych (senior dev: 0/8/24). Osobna kalibracja poziomów 0–5 ma wyniki
0/27/87; wysoka dojrzałość wymaga dowodów egzekwowania i pomiarów.
Przykłady w docs/testach nie są traktowane jako przepływ produkcyjny.
