# Zatwierdzone piny pakietów

Instalator czyta wyłącznie piny z tego katalogu. Brak pliku dla danej
platformy/ABI daje `APPROVED_PIN_MISSING`, bez rozwiązywania zależności
w rejestrze. Starsze receipts bez `repository-pins-v1` są nieważne.

Układ: `<darwin|linux>-<arm64|x86_64>/<tool>.json` dla npm i podkatalog
`cp312` (odpowiednio inne obsługiwane ABI) dla wheels. Każde koło, także
przechodnie, ma nazwę, wersję, nazwę pliku i SHA-256. Dla npm obok deskryptora
leży `<tool>.package-lock.json`, związany SHA-256; każdy tarball ma SRI.
ast-grep wymaga dodatkowo `native.path` oraz `native.sha256`.

`scripts/collect_tool_pins.py --out /external/new-candidates --npm --ci`
zbiera kandydatów na aktualnej platformie i Pythonie, bez instalacji
pakietów i bez lifecycle scripts. `--ci` wymaga CPython 3.12. Wykonaj
oddzielnie na obsługiwanych OS/architekturach/ABI. Pliki i pobrane bajty
pozostają poza repo do przeglądu. Pobranie i obliczenie skrótu nie jest
zatwierdzeniem dostawcy ani audytem zależności. Do repo trafiają dopiero
przejrzane JSON/locki; katalog `downloads` nigdy tu nie trafia.

CI wymaga `cp312/ci.requirements.lock` dla architektury runnera. Brak locka
zatrzymuje job przed pipem. Nie ma zastępczej instalacji bez hashy.

Zatwierdzony zestaw: Darwin arm64, npm oraz wheels/CI dla CPython 3.12
(26.10.2026, recenzja Claude przekazana i zatwierdzona przez właściciela).
SHA-256 natywnego ast-grep porównano również z osobno pobranym oficjalnym
`app-aarch64-apple-darwin.zip` wydania 0.51.0:
`6e4e64393e1cbc67b68f56606982c2834e9ffe771cf10d4811de0f4d15ee3a6d`.
Linux x86_64/arm64, Darwin x86_64 i inne ABI są obecnie nieobsługiwane:
brak pinu daje odmowę, także w CI. Macierz CI nadal pokazuje Ubuntu jako
wymagane, lecz zablokowane pokrycie; ten job nie przejdzie bez zatwierdzonego locka.
Pobranie zatwierdzonych plików nie jest dowodem instalacji/smoke ani wykonania CI.
