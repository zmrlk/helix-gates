## G0 Prawda i kontekst — g0: PASS

- [!] 1 Kontekst: Sklep demo (prod, hipotetycznie) (koszyk -> płatność): UNCONFIRMED by owner -> must be stated as unconfirmed in the report
- [x] 2 Twierdzenia: C1 VERIFIED: Suma koszyka uwzględnia ilość sztuk
- [!] 2 Twierdzenia: C2 ASSUMPTION (prod, not confirmed by owner): Produkcja (jeśli istnieje) liczy koszyk tym samym kodem co app/cart.js — niepotwierdzone
- [x] 2 Twierdzenia: C3 VERIFIED: Kwoty są formatowane tylko przez formatPLN
- [x] 3 Zachowanie: skipped (report only, no code change)
- [x] 4 Niezależna kontrola: codex/default: 1 false-claim and 0 break-risk findings, all resolved

Legenda: [x] ok, [!] ostrzeżenie (musi być w raporcie), [ ] blokuje.
Zasada: nazwa w kodzie nie jest dowodem tego, co działa na produkcji.
