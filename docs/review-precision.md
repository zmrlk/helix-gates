# Precyzja review — 0.7.2-beta

VERIFIED (kod: `bin/helix_lenses.py`, `bin/helix_verification.py`): review offline
ma obowiązkową granicę weryfikacji. `findings` w JSON zachowuje pełny inwentarz
z `verification_status`; raport właściciela i `owner_findings` obejmują potwierdzone.
Pozostałe hipotezy to zagregowany załącznik candidate, odrzucone zostają w JSON.
Bez werdyktu HIGH/critical spada do medium. Statyka i import nie dają punktów
wykonania (0, not-run); nie oznacza to N/A. Dokładne dopasowanie wersji zależności
do lokalnej bazy jest dowodem dopasowania, nie dowodem exploitability.

```sh
helix review deep PATH --out /tmp/helix-review --state-dir /tmp/helix-state
helix review deep PATH --verdicts /tmp/verdicts.json --state-dir /tmp/helix-state --precision-threshold 0.3 --precision-minimum 10
```

Stan musi być poza analizowanym repo. Wspólny katalog stanu przechowuje wyniki
per projekt (hash ścieżki) i łącznie. Brak `--state-dir` oznacza raport nietrwały.
Nie wykonujemy kodu projektu ani dostawców modeli. Import to jawny interfejs
zewnętrznej weryfikacji; deklaracja `hunter != verifier` nie uwierzytelnia modelu.
Werdykty Markdown należy jawnie przekonwertować do JSON, bez zgadywania treści.

```json
{"schema_version":1,"hunter":"model-A","verifier":"model-B","verdicts":[
  {"finding_id":"ID_Z_RAPORTU_JSON","verdict":"confirmed","reason":"Dowód i uzasadnienie bez sekretów"}
]}
```

Opcjonalne `routes` zawiera `route_id` z raportu, `auth_status`
(proven-guarded/unknown/unguarded) i `reason`; wiązanie z aktualnym źródłem
obowiązuje również dla tras. Pozwala zapisać potwierdzony brak guarda
bez wnioskowania z samego braku dopasowania.

Werdykty: confirmed/rejected/unclear. ID wiąże detektor, plik, linię i hash
całego źródła; zmiana pliku unieważnia ponowny import. Nieznane i powtórzone ID
blokują import. Ponowny import aktualizuje próbkę, nie zwiększa licznika.
Precyzja = confirmed / wszystkie ocenione (także unclear), bez nieocenionych.
Po minimum próbek wynik poniżej progu per projekt **lub** globalnie obniża
severity o poziom i oznacza `detector_degraded`. Dopasowania deterministyczne
nie uczą statystyki niezależnych weryfikacji. Historyczne próbki pozostają historią.

VERIFIED (test nowego pliku): fixtures zawierają pary podatne/bezpieczne dla
asymetrii metod, późnego sprawdzenia zakresu, pominięcia guardów rekord+użytkownik,
liczników, usuwania w oknie czasu, rotacji linków i zmiany celu potwierdzenia,
każdy w SvelteKit, Express i Next. Raport pyta właściciela o konta z ograniczonym
zakresem; odpowiedzi nie wnioskujemy z kodu.

ASSUMPTION: kompletność detekcji poza fixtures. To heurystyki, nie pełny parser
ani analiza przepływu. Nazwy parametrów pomagają inferencji funkcji zakresu;
dowolne aliasy, wrappery ORM i dynamiczne dispatch mogą pozostać niewykryte.
