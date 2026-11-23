# Opcjonalne narzędzia OSS

`helix tools adapters` pokazuje rejestr, dostępność i odczytane wersje.
`helix tools scan shellcheck` uruchamia pojedynczy adapter na tymczasowej,
odfiltrowanej kopii repo; nie instaluje zależności. Limit domyślny: 60 s.
Surowe wyjście i fragmenty kodu nie trafiają do raportu.

Wykonanie: shellcheck, actionlint, typos, codespell, hadolint, bandit,
semgrep (lokalna reguła eval), gitleaks, zizmor, trufflehog (bez weryfikacji),
checkov (Terraform, bez pobierania), gosec (GOPROXY/GOSUMDB off), njsscan,
squawk, sqlfluff (Postgres/raw), stylelint (lokalny zestaw), jscpd i radon.
Pozostałe wpisy rejestru jawnie zwracają not-run z powodem, nie punkty.
Brak programu daje unavailable; brak plików profilu daje not-applicable.
Rejestr nie jest sandboxem systemowym; wynik skanera wymaga weryfikacji.
Runtime, DB i obrazy nie są uruchamiane przez ten adapter. Knip/jscpd/Squawk,
mutacje przyrostowe i Ponytail mają osobny [kontrakt advisory](advisory-tools.md);
mutacje wymagają jawnego zakresu i działającej izolacji sieci.

Wersje, ograniczenia i licencje: [TOOLS](rethink/TOOLS.md).
