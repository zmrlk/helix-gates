# Syntetyczne fakty AST

32 własne przypadki Helixa, bez kodu projektu A. `recorded-cases.json` zachowuje źródło i znormalizowane fakty z rzeczywistego ast-grep 0.51.0. Manifest wiąże cały plik, każdy rekord ma własny hash i SHA-256 źródła.

Testy odtwarzają wyłącznie reguły lokalne z tych faktów. Nie uruchamiają ast-grep, modeli, kodu fixture ani sieci i nie wymagają narzędzia na komputerze. Dowód parsowania jest historyczny; pełna poprawność przepływu i brak brakujących węzłów nie są deklarowane.

Oczekiwania znajdują się w test_security_ast_rules.py i nie są kopiowane z poprzednich wyników analizatora. Nazwa upload-safe pochodzi z pierwszej próby: brak await przy sniffImage ma nadal dawać hipotezę SEC-UPLOAD; osobny upload-awaited sprawdza rozpoznaną kontrolę lokalną.
