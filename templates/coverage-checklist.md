# Lista pokrycia jakości: „o czym zapominamy”

Duża aplikacja B2B (panel klienta + panel admina, role, ERP, płatności, e-maile i XLSX) na komputer, tablet i telefon.
Źródło: rada modeli 24.10.2026 (Codex 65 pozycji, Gemini 57, Grok 77), scalone i odduplikowane przez Helixa.
Surowe odpowiedzi: `examples/coverage-council/`.

Kolumny: **Jak** = auto (skrypt/test) · model (ocena modelu) · ręcznie (człowiek, prawdziwe urządzenie, prawnik).
**Helix** = sygnał, który Helix sam sprawdza (`ux:*` z `helix ux`, `gate:*` z bramek). `-` = Helix tego nie sprawdza.
**Status** ustawia projekt w swojej kopii (`helix coverage --init`): `todo` · `partial` · `done` · `n/a`.
`helix coverage` łączy Status z tym, co faktycznie wyszło w ostatnim przebiegu, i pokazuje luki.

## UX i urządzenia

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| UX-01 | Macierz urządzeń | Telefony (mały, duży), składane (złożony/rozłożony, Duo), tablety, laptop, desktop, ultrawide, pion i poziom | auto | `ux:devices:phone`, `ux:devices:foldable`, `ux:devices:tablet`, `ux:devices:desktop` | todo |
| UX-02 | Poziomy scroll i obcięcia | Brak poziomego scrolla strony, nic nie jest ucięte ani nie nachodzi na siebie | auto | `ux:overflow`, `ux:clipped`, `ux:overlap` | todo |
| UX-03 | Cele dotyku | Przyciski i linki na dotyku min. 24px (WCAG 2.5.8), docelowo 44px; rękawiczki na magazynie | auto | `ux:tap-target` | todo |
| UX-04 | Elementy fixed/sticky | Banery cookie, nagłówki i paski nie zasłaniają treści ani pól formularza | auto | `ux:fixed-covers` | todo |
| UX-05 | Klawiatura ekranowa i safe area | Klawiatura iOS/Android, notch i paski przeglądarki nie zasłaniają aktywnego pola i przycisku „Zapisz” | ręcznie | - | todo |
| UX-06 | Zmiana postury składaka | Obrót i rozłożenie Folda w trakcie formularza nie gubi danych ani pozycji scrolla | ręcznie | - | todo |
| UX-07 | Dotyk bez hovera | Nic ważnego nie jest dostępne tylko po najechaniu myszą (tooltipy, menu) | model | `ux:judge` | todo |
| UX-08 | Scenariusze ról end-to-end | Najważniejsze zadania każdej roli (zamówienie, faktura, wydanie z magazynu) przechodzą na telefonie, tablecie i desktopie | auto | `ux:flows`, `ux:download` | todo |
| UX-09 | Symulacja persony | Model jako nowicjusz / księgowa / magazynier próbuje zrobić zadanie i zgłasza tarcia | model | `ux:explore` | todo |
| UX-10 | Ocena wizualna per urządzenie | Układ, spójność, czytelność i użyteczność oceniane przez model wizyjny | model | `ux:judge` | todo |
| UX-11 | Długie treści i duże ilości | Długie polskie nazwy firm, kwoty 1 234 567,89 zł, setki pozycji zamówienia, puste listy | auto | `ux:long-content`, `ux:api-empty` | todo |
| UX-12 | Stany błędów i puste | Błąd API, pusta lista i brak uprawnień pokazują zrozumiały komunikat, a nie pusty ekran | auto | `ux:api-error`, `ux:api-empty` | todo |
| UX-13 | Przerwania i odzyskiwanie | Odświeżenie, wstecz, wygaśnięcie sesji i przełączenie aplikacji nie gubią koszyka ani formularza | auto | - | todo |
| UX-14 | Autouzupełnianie i menedżery haseł | Pola mają `autocomplete`, NIP, kod pocztowy i telefon nie są psute przez autofill | ręcznie | - | todo |
| UX-15 | Skaner kodów (klawiatura HID) | Skaner na magazynie wpisuje kod i Enter w odpowiednie pole, bez gubienia znaków | ręcznie | - | todo |
| UX-16 | Współdzielony tablet | Szybkie przełączanie użytkownika, automatyczne wylogowanie, brak danych poprzedniej osoby | ręcznie | - | todo |
| UX-17 | Prawdziwe urządzenia | Krytyczne ścieżki na prawdziwym iPhonie (Safari) i Androidzie, nie tylko w emulacji | ręcznie | - | todo |

## Dostępność

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| A11Y-01 | Automatyczne WCAG 2.2 AA | axe-core: kontrast, etykiety, role, nazwy, landmarki | auto | `ux:a11y` | todo |
| A11Y-02 | Widoczny fokus i kolejność Tab | Fokus widoczny na każdym elemencie, sensowna kolejność, brak pułapek, fokus niezasłonięty | auto | `ux:kbd` | todo |
| A11Y-03 | Klikalne divy | Elementy z kursorem „rączki” dostępne z klawiatury | auto | `ux:kbd` | todo |
| A11Y-04 | Powiększenie 200% i reflow | Przy 200% i szerokości 320px nic nie wymaga poziomego scrolla | auto | `ux:zoom200` | todo |
| A11Y-05 | Duży tekst i odstępy | Tekst skaluje się z ustawieniem użytkownika, odstępy WCAG 1.4.12 nie ucinają treści | auto | `ux:large-text`, `ux:text-spacing` | todo |
| A11Y-06 | Ograniczenie ruchu | `prefers-reduced-motion` wyłącza animacje | auto | `ux:reduced-motion` | todo |
| A11Y-07 | Ciemny motyw i kontrast | `prefers-color-scheme: dark`, kontrast w obu motywach | auto | `ux:dark` | todo |
| A11Y-08 | Czytniki ekranu | VoiceOver i NVDA/TalkBack w krytycznych ścieżkach: tabele, błędy formularzy, komunikaty (aria-live) | ręcznie | - | todo |
| A11Y-09 | Modale i siatki danych | Fokus wraca po zamknięciu modala, siatki danych obsługiwane strzałkami | ręcznie | - | todo |
| A11Y-10 | Dokumenty i maile | PDF i e-maile mają strukturę, tekst alternatywny i czytelną kolejność | ręcznie | - | todo |

## Wydajność

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| PERF-01 | Core Web Vitals lokalnie | LCP, CLS, waga strony per urządzenie | auto | `ux:perf` | todo |
| PERF-02 | Wolne 3G i słaby CPU | Szkielet/loader w 3 s, akceptowalny czas ładowania | auto | `ux:slow3g` | todo |
| PERF-03 | Dane w skali produkcji | Wyszukiwanie, filtry, eksporty i dashboardy na realnej liczbie rekordów, bez zapytań N+1 | auto | - | todo |
| PERF-04 | INP na dużych siatkach | Responsywność przy setkach wierszy i edycji inline | auto | - | todo |
| PERF-05 | Długa sesja | Wielogodzinna praca (magazyn, admin) bez wycieków pamięci i spowolnień | auto | - | todo |
| PERF-06 | Pomiar u prawdziwych użytkowników | RUM per urządzenie i łącze, nie tylko lokalnie | auto | - | todo |

## Bezpieczeństwo

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| SEC-01 | IDOR i izolacja klientów | Zmiana ID w URL/API nie daje dostępu do cudzych zamówień, faktur, eksportów | auto | - | todo |
| SEC-02 | Mass assignment | Dodatkowe pola (rola, cena, rabat, status płatności) są ignorowane | auto | - | todo |
| SEC-03 | Wstrzyknięcia i XSS | SQL/XSS/CSRF/SSRF, także treści przychodzące z ERP i nazwy plików | auto | `gate:review` | todo |
| SEC-04 | Formuły w CSV/XLSX | Eksport neutralizuje `=`, `+`, `-`, `@` na początku komórki | auto | - | todo |
| SEC-05 | Uploady | Limit rozmiaru i pikseli, typ sprawdzany przed dekodowaniem, brak XXE i zip-slip | auto | - | todo |
| SEC-06 | Webhooki płatności | Podpis, znacznik czasu, powtórki, zgodność kwoty, waluty i zamówienia | auto | - | todo |
| SEC-07 | Cykl życia logowania | Reset hasła, enumeracja kont, rotacja sesji, MFA dla adminów, prefetch linków jednorazowych (Outlook Safe Links) | auto | - | todo |
| SEC-08 | Sekrety i zależności | Brak sekretów w repo, bundlach i source mapach, skan podatnych pakietów | auto | `gate:review` | todo |
| SEC-09 | Nagłówki i ekspozycja | CSP, HSTS, CORS, brak endpointów debug na produkcji | auto | - | todo |
| SEC-10 | Zewnętrzne żądania w testach | Testy UX nie wysyłają nic do produkcji ani zewnętrznych usług | auto | `ux:external-blocked` | todo |

## Prywatność i RODO

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| RODO-01 | Mapa danych osobowych | Gdzie trafiają dane: aplikacja, ERP, płatności, poczta, analityka, logi, backupy, modele AI | ręcznie | - | todo |
| RODO-02 | Usunięcie a retencja | Żądanie usunięcia anonimizuje kontakt, a faktury i płatności zostają przez okres wymagany prawem | ręcznie | - | todo |
| RODO-03 | Dane osobowe w narzędziach | Logi, trasy, zrzuty ekranu z testów i fixture'y agentów bez NIP, maili i adresów | auto | - | todo |
| RODO-04 | Dane testowe | Staging i środowiska agentów na danych zanonimizowanych, bez dostępu do produkcyjnego ERP i płatności | ręcznie | `gate:truth` | todo |
| RODO-05 | Polityka zgodna z rzeczywistością | Polityka prywatności, lista cookies i podprzetwarzających zgodne z tym, co działa | ręcznie | - | todo |

## Język i formaty (i18n/locale)

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| I18N-01 | Polskie znaki wszędzie | ą, ć, ę, ł, ń, ó, ś, ź, ż przez formularz, bazę, ERP, e-mail, XLSX, PDF i nazwy plików | auto | `ux:long-content` | todo |
| I18N-02 | Kwoty i liczby | Przecinek dziesiętny, spacja tysięcy, „zł”, parsowanie wpisanego „1 234,50” | auto | - | todo |
| I18N-03 | Daty i strefa | DD.MM.RRRR, Europe/Warsaw, zmiana czasu (DST), poniedziałek pierwszym dniem tygodnia | auto | - | todo |
| I18N-04 | Sortowanie i wyszukiwanie | Polska kolejność alfabetyczna, wyszukiwanie bez ogonków, NFC/NFD | auto | - | todo |
| I18N-05 | Liczba mnoga i kwota słownie | 1 zamówienie / 2 zamówienia / 5 zamówień, kwota słownie na fakturze | auto | - | todo |
| I18N-06 | Identyfikatory | NIP, REGON, kod pocztowy, NRB, EAN bez notacji naukowej i obcinania zer | auto | - | todo |
| I18N-07 | Kalendarz biznesowy | Święta, godziny odcięcia magazynu, terminy płatności | auto | - | todo |

## E-mail, XLSX i załączniki

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| MAIL-01 | Wygląd maili | Outlook desktop, Gmail, WP/Onet, telefon, ciemny motyw, zablokowane obrazki | model | - | todo |
| MAIL-02 | Dostarczalność | SPF, DKIM, DMARC, bounce, polskie znaki w nadawcy | auto | - | todo |
| MAIL-03 | Właściwy odbiorca | Ponowienie wysyłki nie wyśle załącznika klienta A do klienta B | auto | - | todo |
| XLSX-01 | Kontrakt arkusza | Kolumny, typy (NIP jako tekst, daty jako daty), kwoty, sumy zgodne ze źródłem; test „złotego pliku” | auto | `gate:behavior` | todo |
| XLSX-02 | Otwieranie w Excelu | Polski Excel i LibreOffice: kodowanie, formaty, zamrożony nagłówek | ręcznie | - | todo |
| XLSX-03 | Nazwa, typ, rozmiar | Nazwa z polskimi znakami (RFC 5987), poprawny MIME, limit rozmiaru załącznika | auto | `ux:download` | todo |

## Druk i PDF

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| PDF-01 | Wydruk A4 | Długie zamówienie: powtarzany nagłówek tabeli, niepodzielone wiersze, suma na ostatniej stronie | model | - | todo |
| PDF-02 | Fonty i kody | Osadzone polskie fonty, czytelne kody kreskowe/QR | ręcznie | - | todo |
| PDF-03 | Warianty dokumentu | Dokument klienta bez notatek wewnętrznych, lista kompletacyjna bez cen | auto | - | todo |

## SEO i strony publiczne

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| SEO-01 | Panel poza indeksem | Panel, konto, zamówienia i staging mają `noindex` i są za logowaniem | auto | - | todo |
| SEO-02 | Strony publiczne | Meta, canonical, sitemap, kody HTTP, karty udostępniania | auto | - | todo |

## Analityka

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| AN-01 | Zgoda a zdarzenia | Po odrzuceniu cookies nie idzie żadne zdarzenie analityczne ani nagrywanie sesji | auto | - | todo |
| AN-02 | Poprawność zdarzeń | Zdarzenia raz, z poprawną kwotą i walutą, bez tokenów i danych osobowych w URL | auto | - | todo |
| AN-03 | Ruch wewnętrzny | Wykluczony ruch pracowników, impersonacji i testów | ręcznie | - | todo |

## Monitoring błędów

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| ERR-01 | Błędy JS i żądań | Brak błędów w konsoli, nieobsłużonych wyjątków i nieudanych żądań na każdej stronie | auto | `ux:console`, `ux:requests` | todo |
| ERR-02 | Zbieranie błędów | Sentry/podobne: wersja wydania, czytelne stosy, ID korelacji, bez danych osobowych | auto | - | todo |
| ERR-03 | Błąd ładowania po wdrożeniu | ChunkLoadError po deployu: odświeżenie zamiast białego ekranu | auto | - | todo |
| ERR-04 | Ciche błędy w tle | Kolejka martwych wiadomości, alert na biznesowe odrzucenie mimo HTTP 200 | auto | - | todo |

## Backup i odtwarzanie

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| BAK-01 | Próba odtworzenia | Odtworzenie bazy, plików i konfiguracji w izolacji, zmierzone RPO i RTO | ręcznie | - | todo |
| BAK-02 | Uzgodnienie po odtworzeniu | Bez dublowania płatności, dokumentów ERP i maili | ręcznie | - | todo |

## Migracje i wycofanie

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| MIG-01 | Migracje w skali | Czas blokad, częściowy błąd i wznowienie na kopii wielkości produkcji | auto | - | todo |
| MIG-02 | Zgodność w obie strony | Stara aplikacja na nowym schemacie i odwrotnie (expand/contract), zadania w kolejce w starym formacie | auto | - | todo |
| MIG-03 | Rollback wydania | Przećwiczone wycofanie, feature flagi i kill switch dla ERP i maili | ręcznie | - | todo |

## Limity i nadużycia

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| RATE-01 | Limity wejściowe | Logowanie, wyszukiwanie, eksport, upload: limit per użytkownik i IP, czytelny komunikat | auto | - | todo |
| RATE-02 | Presja na integracje | Timeout i 429 z ERP/płatności: retry z jitterem, circuit breaker, polski komunikat o utrudnieniach | auto | - | todo |
| RATE-03 | Jeden harmonogram | Dwie instancje i zmiana czasu: eksporty i synchronizacje wykonują się raz | auto | - | todo |

## Przeglądarki

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| BR-01 | Silniki | Chromium, WebKit (Safari) i Firefox | auto | `ux:engine:chromium`, `ux:engine:webkit`, `ux:engine:firefox` | todo |
| BR-02 | Uzgodniona lista wersji | Najstarszy wspierany Chrome na magazynie, stary WebView Androida, Safari iOS (ITP, cookies) | ręcznie | - | todo |

## PWA i offline

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| OFF-01 | Komunikat offline | Utrata sieci daje zrozumiały komunikat, a nie stronę błędu przeglądarki | auto | `ux:offline`, `ux:flows:offline` | todo |
| OFF-02 | Cache service workera | Aktualizacja SW, wylogowanie i zmiana konta nie pokazują cudzych danych ani starych cen | auto | - | todo |
| OFF-03 | Wysyłka po powrocie sieci | Zamówienie w kolejce offline tworzy się dokładnie raz | auto | - | todo |

## Powiadomienia

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| NOT-01 | Cykl powiadomień | Właściwi odbiorcy, deduplikacja przy retry, preferencje, linki tylko dla uprawnionych | auto | - | todo |

## Prawo i zgodność

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| LEG-01 | Cookies i zgoda | Odrzucenie wyłącza niekonieczne cookies, wycofanie zgody działa | auto | - | todo |
| LEG-02 | Regulamin | Wersjonowana akceptacja regulaminu zapisana z użytkownikiem, czasem i wersją | auto | - | todo |
| LEG-03 | KSeF | Aktualny schemat FA, wysyłka, UPO, korekty, tryb awaryjny (potwierdzić z księgowością) | ręcznie | - | todo |
| LEG-04 | Zasady VAT | MPP, NRB, biała lista, blokada edycji wystawionych dokumentów | auto | - | todo |
| LEG-05 | NIP i dane kontrahenta | Suma kontrolna NIP, GUS/VIES | auto | - | todo |
| LEG-06 | Dostępność jako obowiązek | Czy projekt podlega European Accessibility Act / ustawie o dostępności (od 28.06.2025) | ręcznie | - | todo |

## Obserwowalność

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| OBS-01 | Śledzenie zamówienia | Jedno ID korelacji przez web, kolejkę, płatności, ERP i e-mail | auto | - | todo |
| OBS-02 | Monitoring procesów | Alerty na zawieszone zamówienia, opóźnienie synchronizacji ERP, kolejkę maili | auto | - | todo |
| OBS-03 | Testy syntetyczne po wdrożeniu | Logowanie i zamówienie per rola po każdym deployu | auto | `ux:flows` | todo |
| OBS-04 | Audyt zmian | Zmiany uprawnień, danych firmy i statusów zapisane w audycie | auto | - | todo |

## Integralność danych

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| DATA-01 | Kwoty i VAT | Grosze lub decimal, zaokrąglanie VAT per linia lub per dokument zgodnie z ERP | auto | `gate:behavior` | todo |
| DATA-02 | Dokładnie raz | Crash między płatnością a ERP/mailem, powtórka webhooka: jedna płatność, jeden dokument | auto | - | todo |
| DATA-03 | Dozwolone przejścia statusów | Maszyna stanów zamówienia, brak reaktywacji z pominięciem akceptacji | auto | `gate:behavior` | todo |
| DATA-04 | Historia handlowa | Stare zamówienia zachowują ceny, opisy i adresy po zmianach w katalogu | auto | - | todo |
| DATA-05 | Uzgodnienie dzienne | Sumy panelu, rozliczenia płatności i dokumenty ERP zgodne co do grosza | auto | - | todo |
| DATA-06 | Prawda o produkcji | Twierdzenia o działających systemach potwierdzone, a nie wzięte z nazw w kodzie | auto | `gate:truth` | todo |

## Role i uprawnienia

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| ROLE-01 | Pełna macierz ról | Jawne „wolno / nie wolno” dla każdej roli i akcji (admin, księgowość, magazyn, handlowiec, klient), w API i UI | auto | - | todo |
| ROLE-02 | Natychmiastowe odebranie | Zmiana roli lub blokada działa od następnego żądania, także w otwartej sesji | auto | - | todo |
| ROLE-03 | Rozdział obowiązków | Handlowiec nie zmieni sam ceny ani blokady kredytowej, impersonacja z powodem i audytem | ręcznie | - | todo |
| ROLE-04 | UX per rola | Flow i eksplorator uruchomione jako każda rola, nie tylko admin | auto | `ux:flows`, `ux:explore` | todo |

## Obciążenie i współbieżność

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| LOAD-01 | Szczyt | Koniec miesiąca: równoległe zamówienia, raporty i eksporty, opóźnienia i błędy w normie | auto | - | todo |
| LOAD-02 | Wyścigi | Ostatnia sztuka i ten sam koszyk z dwóch kart: jeden zwycięzca, bez ujemnego stanu | auto | - | todo |
| LOAD-03 | Edycja równoległa | Dwie osoby edytują to samo zamówienie: wykrycie konfliktu | auto | - | todo |

## Integracje (ERP, płatności)

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| INT-01 | Mapowanie | Jednostki, VAT, magazyny, ceny indywidualne, NIP z „PL” i spacjami nie tworzy duplikatu kontrahenta | auto | - | todo |
| INT-02 | Wiadomości trujące | Trwale odrzucone zamówienie trafia do kolejki z powodem, reszta idzie dalej | auto | - | todo |
| INT-03 | Wyścigi płatności | Zamknięta karta w 3DS, webhook przed powrotem przeglądarki: poprawne stany | auto | - | todo |
| INT-04 | Kodowanie znaków ERP | Polskie znaki przez stronę kodową ERP bez krzaczków | auto | - | todo |

## Kod pisany przez AI

| ID | Pozycja | Co sprawdzić | Jak | Helix | Status |
|---|---|---|---|---|---|
| AI-01 | Fałszywa pewność | Zamockowane granice integracji, rozjazd walidacji klient/serwer, brakujący audyt | model | `gate:review` | todo |
| AI-02 | Niezależna recenzja | Co najmniej dwóch recenzentów na różnych modelach | model | `gate:review` | todo |
