# Obciążenie maszyny i dopuszczanie zadań

Helix odczytuje lokalne obciążenie przed rozpoczęciem oraz między partiami
security deep, urządzeniami UX, kontrolami runtime i partiami własnych testów.
Pomiar nie uruchamia obciążenia, nie odczytuje argumentów cudzych procesów
i nie wysyła im sygnałów. Aktywne zadania mogą się zakończyć; decyzja dotyczy
przyjmowania nowych zadań.

`resources` w konfiguracji projektu przyjmuje poniższe progi:

```json
{
  "resources": {
    "high_load_ratio": 1.5,
    "critical_load_ratio": 3.0,
    "high_memory_available_ratio": 0.15,
    "critical_memory_available_ratio": 0.05,
    "critical_psi_full_avg10": 10,
    "sample_s": 5,
    "poll_s": 5,
    "max_pause_s": 300,
    "stale_after_s": 15
  }
}
```

- `normal`: do zadanej liczby zadań, np. `--jobs 3`.
- `high`: najwyżej połowa zadanej liczby, co najmniej jedno zadanie.
- `critical`: nowe zadania czekają na poprawę pomiaru. Po `max_pause_s`
  wynik pozostaje niepełny, z przyczyną i listą niesprawdzonych jednostek.
- `unknown`: ostrożny limit jednego zadania i jawny brak danych.

Load jest dzielony przez dostępną liczbę CPU. Na Linux używane są także
MemAvailable/MemTotal, PSI pamięci, affinity i dostępny limit pamięci cgroup v2.
Na macOS odczytywane są `getloadavg`, systemowy poziom presji przez `sysctl`
i liczniki `vm_stat` z rzeczywistym rozmiarem strony. Liczba wolnych stron
nie jest utożsamiana z dostępną pamięcią. Odmowa odczytu systemowego oznacza
pomiar częściowy, nigdy fikcyjne zero. Polecenie `memory_pressure` nie jest
wywoływane, ponieważ dostępna lokalnie dokumentacja nie potwierdziła trybu,
który wyłącznie odczytuje stan i nie wytwarza obciążenia.

Pauza zużywa istniejący budżet czasu. Deep zachowuje checkpoint do `--resume`.
Nie zmienia planowanych modeli, zakresu skanu ani tożsamości cache. Runtime
nie obniża liczby użytkowników k6, długości pomiaru, progów SLO ani liczby tras,
aby nie zmienić znaczenia eksperymentu. Brakujący/stary monitor przeglądarki
nie pozwala uznać nieuruchomionych tras za sprawdzone.

Wyniki zawierają decyzje, zadany i skuteczny limit oraz źródła pomiaru.
`resource-decisions.jsonl` przechowuje zmiany i okresowe potwierdzenia;
`resource-current.json` jest atomowym stanem dla procesów przeglądarki.
Przyczynę pauzy widać także w konsoli. Żaden z tych plików nie zawiera
sekretów ani pełnych danych o procesach.

Testy Helixa przyjmują osobny JSON samych progów:

```sh
python3 scripts/run_tests_parallel.py -j 6 --resource-config /audits/resource-policy.json --resource-report /audits/helix-tests-run1
```

Bez wskazania katalogu zapisują raport w nowym katalogu tymczasowym poza repo
i wypisują jego ścieżkę. Można też użyć `HELIX_TEST_RESOURCE_REPORT_DIR`.
`test-summary.json` zapisuje niewykonane partie, a częściowy przebieg kończy
się kodem 2. Wspólne fixtures klas nadal pozostają w jednym procesie.

Exit0 workera bez prawidłowego podsumowania unittest nie zalicza partii.
Liczba zakończonych test IDs musi odpowiadać zleceniu; pusta suita daje
INCOMPLETE. Zwykłe pominięte testy są osobno policzone i nie stanowią dowodu
wykonania. Pominięcie całej klasy w setUpClass nie potwierdza wykonania jej IDs.
