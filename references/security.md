# Helix · Paczki security/perf/integrity i security deep

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

## Paczki dla agentów (faza 1)
`helix packs` sprawdza narzędzia; `helix security|perf|integrity scan` zbiera dowody.
`helix gate security|perf|integrity [cpN] --trusted-base` uruchamia ratchet:
0=PASS, 2=FAIL, 3=ERROR. Błędu narzędzia nie wolno uznać za PASS.
Security/integrity domyślnie blocking, perf advisory. Baseline wymaga uzasadnienia;
sekret dodatkowo `--accept-secret fingerprint=rotated|revoked|false-positive...`.
Nie zatwierdzaj samodzielnie zmian polityki, baseline ani waiverów właściciela.
`perf` nie buduje aplikacji bez `build_cmd`; SQL query counter jest w fazie 2.

## Security deep (faza 2)
`helix security deep [--scope src api] [--profile quick|standard] [--out DIR]`
opakowuje vendored Cloudflare security-audit-skill (MIT). Role dobierane są z rzeczywiście sprawdzonych modeli, jeśli właściciel ich nie ustawił.
Weryfikator należy do innej rodziny niż hunter; brak niezależnej rodziny daje LIMITED.
Jawnych ról ani modeli nie zmieniaj i nie zastępuj po cichu. Helix jest jedynym autorem wspólnych plików;
agenci dostają snapshot źródeł, nie wykonują kodu targetu ani poleceń/sieci,
nie czytają poświadczeń. Wyniki muszą być poza targetem; poprzednie przebiegi
wchodzą do kontekstu. Walidatory vendora sprawdzają coverage-ledger i findings;
jedna poprawka, potem partial/downgrade lub odrzucenie błędnego rekordu z notą.
Quick/scope oznacza partial coverage. Raporty oddzielają confirmed (VERIFIED),
needs_validation (ASSUMPTION) i rejected. `packs.security.deep_required: true`
dodaje do bramki potwierdzone high/critical z najnowszego przebiegu w zewnętrznym indeksie (także `--out`);
domyślnie false. Nie traktuj pustego raportu partial jako dowodu bezpieczeństwa.
