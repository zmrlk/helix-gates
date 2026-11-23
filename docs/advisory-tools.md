# Narzędzia advisory i prostota

Przykłady (stan i wyniki poza repo celu):

```sh
helix --repo /code/app --state-dir /audits/app-state tools scan knip --out /audits/knip-1
helix --repo /code/app --state-dir /audits/app-state tools scan jscpd --since HEAD~1 --out /audits/duplicates-1
helix --repo /code/app --state-dir /audits/app-state tools scan squawk --since HEAD~1 --out /audits/migrations-1
helix --repo /code/app --state-dir /audits/app-state tools scan mutmut --since HEAD~1 --out /audits/mutation-1
helix --repo /code/app --state-dir /audits/app-state tools scan stryker --since HEAD~1 --out /audits/mutation-js-1
helix --repo /code/app --state-dir /audits/app-state tools simplicity --since HEAD~1 --out /audits/simplicity-plan-1
```

Każdy zapis tworzy nowe `advisory-tools.json` i `.md`; agregator owner odczytuje
statusy i kandydatów. `quality` wskazuje niewykonane adaptery i prostotę.
Wszystkie wyniki są advisory, z `score=0` i `execution_credit=0`.
Brak programu, odmowa, timeout, niepoprawny raport i N/A pozostają rozróżnione.
Żadne polecenie nie instaluje programu.

Knip6.43.0, jscpd5.4.2 i Squawk2.70.0 używają zweryfikowanych receipts
zarządzanej instalacji. Dostają filtrowany snapshot, własne konfiguracje i HOME.
Knip ocenia pliki/eksporty/typy z syntetycznym manifestem, bez zależności,
konfiguracji i pluginów projektu. Wymaga weryfikacji dynamicznych wejść;
nie jest pełnym audytem zależności pakietowych. jscpd zachowuje oba miejsca
duplikatu i filtruje zmianę po dowolnej stronie pary.

Squawk wymaga `--since`: analizuje wyłącznie zmienione i nowe SQL w katalogach
migration/migrations/sql. Nie wykonuje SQL. Mutacje również wymagają `--since`,
kopiują projekt i ograniczają mutowane źródła do zmienionych plików. Testy projektu
mogą wykonać się wyłącznie przy działającym `unshare --net`; brak izolacji daje
not-run, bez natywnego fallbacku. Mutmut korzysta z zarządzanej instalacji,
Stryker z istniejącego programu. Limit obejmuje wspólny czas procesu, a błędny
lub niepełny raport nie daje wyniku sukcesu. Konfiguracja projektu i dostępność
lokalnych zależności nadal mogą uniemożliwić przebieg; nie są automatycznie naprawiane.

Prostota używa przypiętych instrukcji Ponytail4.9.0 oraz dokładnego modelu
`review_architecture` z planu ról (pierwszego reviewera, jeśli brak tej roli).
Samo polecenie zapisuje plan bez modelu. `--execute-model` wymaga wspólnej zgody
`data_egress`, dostępnego przypisanego modelu i dopuszczonego transportu źródeł.
Obecna granica transportu może odmówić z `SOURCE_INPUT_NOT_ADMITTED`; nie jest to
wykonany przegląd. Brak modelu nie uruchamia zamiennika. Zużycie i koszt nieznane
pozostają null. Sugestie modelu nie otrzymują statusu confirmed ani punktów.

Kalibracja tej zmiany: rzeczywiste dodatnie i ujemne kontrole trzech narzędzi
na własnych źródłach Helixa, bez instalacji/modeli/projektu A. Testy mutacji i modelu
są syntetyczne; nie stanowią wykonania aplikacji ani rzeczywistej recenzji.
