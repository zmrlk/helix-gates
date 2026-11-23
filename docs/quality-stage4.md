# Raport właściciela i dodatkowe obszary

`helix new audit --repo REPO --out KATALOG_POZA_REPO` dodaje
`owner-current.md` i pełny `owner-current.json`. Reużywa soczewek, audytu
wycieku, ciągłości, inwentarza czytania i oceny Pro. MD pokazuje najwyżej
5 problemów i 5 decyzji, liczniki oraz link do JSON. Plan luk w JSON zawiera
owner, due_date, effort, dependencies i closure. Braki pozostają „do przypisania”
lub „do oszacowania”; brakująca kontrola ma pusty dowód, bez zmyślonej lokalizacji.
`owner-report --input KONTRAKT --out RAPORT.md` zachowuje dotychczasową
walidację i zapisuje taką samą projekcję z sąsiednim JSON.

`data/quality-domains.json` definiuje checklisty testów, compliance EU/PL,
obserwowalności, FinOps, danych i SEO. Audyt eksportuje je w `quality.json`.
Sygnał plik:linia oznacza przygotowanie, nigdy wykonanie ani zgodność prawną.
Piramida liczy pliki według ścieżek unit/integration/e2e, bez uniwersalnej proporcji;
pozostałe testy pozostają unclassified. Retry/sleep to podejrzenie, nie dowód flaky.
Historia wykonań i pełna interpretacja kontraktów API pozostają do dostarczenia.
Tracker w statycznym tagu bez jawnego warunku zgody daje ASSUMPTION z poprawką;
zewnętrzny CMP wymaga testu kolejności żądań, nie automatycznego uznania naruszenia.

W `helix.json` profil dziedziny jest jawny, niezależny od stosu:

```json
{"domain_profile":{"ecommerce":true,"invoicing":true,"ai":true,
 "public_web":{"applicable":false,"reason":"Prywatne API"},
 "controls":{"obs-otel":{"applicable":false,"reason":"Biblioteka bez procesu serwerowego"}}}}
```

Niepotwierdzony profil to not-run i 0 pkt; N/A wymaga powodu i jest wyłączone
z mianownika. Checklisty obejmują EAA, konsumenta, Omnibus, cookies/ePrivacy,
RODO, licencje, KSeF i przejrzystość AI. Nie wykonują aktualnej analizy prawnej.
OTel i logi bez PII korzystają też z istniejącego audytu wycieku. Dane obejmują
jakość, retencję i expand/contract; kontrolę SQL wykonuje istniejący adapter squawk.
FinOps wymaga kosztu jednostkowego, modelu wzrostu i budżetów/alertów IaC;
SEO — meta, sitemap, robots, structured data i analityki zgodnej z decyzją zgody.

Wagi są pomocnicze. HIGH/critical oraz niewykonanie blokują osobno, niezależnie
od średniej. Konfiguracja `owner_report.profiles.M.weights` (analogicznie S/L/XL)
przyjmuje `parts`, `areas`, `controls`: mapy dodatnich wag. Waga kontroli to
iloczyn trzech wag, domyślnie 1. Kontrole źródłowe mają 0 pkt wykonania.
Kontrakt może przekazać `assessment.controls` z id, part, area, status, score, run;
zaliczenie wymaga dotychczasowego kontraktu wykonania, logu oraz zgodności SHA
projektu, kontroli i bieżącego HEAD. To walidacja deklaracji, bez podpisu runnera.
`owner_report.gap_assignments.ID` w helix.json pozwala podać owner, due_date,
effort, dependencies, closure. Identyfikatory kontroli są w pełnym JSON.

`helix handoff run --run-id ID` jawnie generuje raport przebiegu.
Dotychczasowe `helix handoff --run-id ID` nadal działa;
`handoff write/read/check` obsługuje ciągłość sesji.

`helix runtime mutation --project REPO --tool stryker --budget-seconds 60`
(lub `--tool mutmut`) działa wyłącznie na kopii tmp, z oczyszczonym środowiskiem,
bez instalacji. Wymaga namespace sieci `unshare --net`; niedostępny namespace
lub adapter daje not-run z powodem. Wspólny budżet 0–300 s obejmuje adapter
i eksport; timeout kończy grupę procesów. Stryker czyta raport JSON,
mutmut używa `export-cicd-stats`; brak mutantów, skipped i niepełny wynik
nie dają punktów. `mutation_score` jest wyłącznie metryką; `score` pozostaje 0 bez trwałego kontraktu odbioru. To adapter opcjonalny; tej sesji nie towarzyszył prawdziwy run mutacji.

Istniejące `helix tools scan --help` opisuje wywołanie adapterów.
ScanCode działa na kopii, eksportuje wyłącznie lokalizacje i identyfikatory licencji,
bez zaliczania zgodności zależności. Zainstalowany licensee npm wymaga polityki
i drzewa zależności; kopia nie zawiera node_modules, dlatego zwraca not-run.
Manifesty i sygnały są przygotowaniem; brak wykonania SCA/DB offline pozostaje unknown.
