# Helix · Ogólność i dowody po scaleniu; CI

Wydzielone z `SKILL.md` 2.11.2026 bez zmiany treści (rdzeń skilla musi mieścić się w 5 000 tokenach, które Claude Code zachowuje po kompaktowaniu). Czytaj z poziomu `SKILL.md`, sekcja „Czytaj, gdy”.

## Ogólność i dowody po scaleniu

Kontrakt projektu zapisuj w konfiguracji: `static_security`, `runtime.integrations.custom`,
`runtime.adapters.synthetic_rows`, `runtime.adapters.inbound_replay` oraz polityka tożsamości. Nie dodawaj reguł
zależnych od nazwy klienta, katalogu ani guarda. Semantykę guarda potwierdza ciało
funkcji lub sprawdzony jawny kontrakt. Rozpoznanie .NET nie uruchamia MSBuild i nie
potwierdza integracji NuGet. [Ogólność](../docs/generality.md).

Rejestr 50 dostawców runtime wybiera http-sink, record-replay, container lub disable.
Node fetch/http/https i Python requests mają transport przechwytu; Go/PHP/Ruby
mają rozpoznanie pakietów. Brak dostawcy, obrazu, SDK lub kontraktu pozostaje luką.
Nieznany HTTP zapisuje tylko kształt bez wartości i propozycję do akceptacji.
Zaślepione 2xx, gotowość procesu i lokalne przyjęcie nie zaliczają dostawcy ani trasy.
Czytaj `parts[].adapters`, `generic-*.json` oraz kontrole pdf-render, timezone-utc
i inbound-replay. Stary backup bez checksum nie zalicza restore.
[Adaptery](../docs/runtime-adapters.md).

Nowe bramki projektu mapuj przez `pro-evidence.json`. Niewykonany test lub CI
może zwiększyć wyłącznie preparation_score. Wykonanie wymaga SHA, hashów plików
oraz logu, a import nie uwierzytelnia hosta. Rezerwacje ID między worktree wymagają
wspólnego absolutnego `--registry`. AI i człowiek mają te same bramki modułów;
brak `ai-modules.json` to NOT_CONFIGURED. [Kontrakt](../docs/project-evidence.md).

Szybka kontrola to `python3 scripts/check_fast.py`; konfiguracja hooka pozostaje
jawną czynnością operatora z zachowaniem dotychczasowych hooków. Workflow CI
nie jest dowodem zielonego GitHub Actions. `model-call-<id>.json` pochodzi z próby
providera; JSON modelu nie potwierdza kosztu. Brak telemetryki to null, nie zero.
[CI i zużycie](../docs/ci.md).
