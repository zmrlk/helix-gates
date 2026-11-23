# Strukturalne detektory bezpieczeństwa

`helix review deep /code/app --out /audits/app-review` korzysta z zarządzanej
instalacji ast-grep 0.51.0 dla SEC-AUTH, SEC-IDOR, SEC-OTP, SEC-UPLOAD
i SEC-MASS. Plan ryzyka security deep używa tego samego silnika.
Instalacja pozostaje jawna: `helix tools install --yes --tool ast-grep`.
Przegląd nie pobiera pakietu ani nie uruchamia aplikacji.

Helix przekazuje odczytany snapshot do własnego katalogu tymczasowego,
z własnymi regułami, konfiguracją i HOME. Nie używa sgconfig, pluginów ani
node_modules celu. Weryfikuje receipt przypiętej instalacji, zakresy UTF-8,
tekst odpowiadający zakresom i zgodność plików odpowiedzi. Reguły są własne,
w `config/static-ast`; nie pochodzą z zewnętrznego rejestru reguł.

Granica funkcji pochodzi z drzewa składni. Kontrola innego rekordu, ignorowany
wynik bool, niewywołana funkcja i opcjonalna gałąź nie chronią operacji.
Kandydat `requireCan` dotyczy tego samego wiersza przed efektem lub ujawnieniem
odczytu. Jeden poziom helpera wymaga jednoznacznej lokalnej definicji albo
importu względnego lub `$lib`, zgodnego identyfikatora, odczytu wiersza i
oczekiwania na guard; sama globalnie unikalna nazwa nie wystarcza.

AUTH rozpoznaje również importowany helper, którego rzeczywiste ciało
odmawia dostępu bez użytkownika. Kandydat middleware wymaga eksportowanego
handle i rzeczywistego wywołania lokalnego delegata. Rzucony błąd i zwrócona
odpowiedź mają osobne kontrakty: samo `await` nie przekazuje odpowiedzi
401/403 do klienta. Literalne wykluczenia tras i granice aplikacji monorepo
pozostają zachowane; nieustalona gałąź ma applicability unknown oraz lukę.
Kontrola istnienia route.id zwracająca 404 nie jest listą chronionych tras.

Upload wiąże limit i odmowę typu z konkretnym plikiem lub jego buforem.
Odczyt właściwości, `&& false` i nieoczekiwana obietnica nie zaliczają odmowy.
Mass assignment rozpoznaje rzeczywiste wywołanie ze spreadem lub body,
z zachowaniem ponownego przypisania i przesłonięcia `createHash`.
OTP wymaga operacji na kodzie; nazwa ikony lub literał tekstowy nie wystarcza.

TS, JS i TSX mają własne reguły parsera. W Svelte obsługiwane są dosłowne
lokalne bloki script, z oddzielnymi zakresami module/instance i zachowaniem
oryginalnych linii. Markup pozostaje jawnie poza zakresem AST i zachowuje
fallback. Brak narzędzia, nieobsługiwana składnia, timeout i błędna odpowiedź
nie dają pustego udanego wyniku. Obowiązuje fallback leksykalny
z `evidence_kind=lexical_fallback`, pewnością possible i maksymalnie medium
dla tych pięciu rodzin. Inne detektory zachowują własny kontrakt.

Raport `static_engine` zawiera wersję i hash receipt, hash reguł oraz źródeł,
liczbę wywołań i bajtów, status każdego pliku i przyczyny luk. Prywatne fakty
AST zawierają tekst tylko na czas lokalnej analizy; nie są częścią raportu.
`local_candidates` wyjaśnia rozpoznane kontrole, które wyciszyły kandydatów
tych reguł. Nie stanowi dowodu bezpieczeństwa ani punktów jakości.

Parser udostępnia węzły ERROR, ale nie wszystkie brakujące węzły odzyskanej
składni. `PARSED` oznacza otrzymane lokalne fakty, przy osobnym
`parser_completeness=PARTIAL`; nie dowodzi poprawności całego programu.
Także bezpośredni guard pozostaje kandydatem. Status ochrony tras pozostaje
unknown do odrębnej weryfikacji, a wszystkie miejsca agregatu są zachowane.

Niskopoziomowe Python API `helix_static_security.analyze` zachowuje domyślny
tryb lexical dla zgodności istniejących odbiorców; `engine='auto'` włącza
zarządzany AST. Publiczny review deep i plan ryzyka wybierają auto. Testy
odtwarzają zapisane fakty własnych syntetycznych źródeł, więc nie wymagają
zainstalowanego programu ani sieci; rzeczywista kalibracja jest osobnym dowodem.
