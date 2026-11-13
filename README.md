# LANL auth scenario injector

Skrypt `main.py` domiesza do zbioru LANL sztuczny, oznaczony scenariusz
incydentu. Dane wejściowe i wyjściowe mogą być zwykłym tekstem albo plikiem
`.bz2`; pliku nie trzeba wcześniej rozpakowywać.

## Scenariusz

Dokładnie pierwsza połowa **oryginalnych rekordów** jest kopiowana bez zmian.
W drugiej połowie skrypt wykorzystuje wyłącznie istniejące identyfikatory i
dodaje trzy fazy:

1. `account_takeover` — aktywne konto o normalnym profilu 2–8 komputerów w
   jednej sekundzie loguje się do kilkudziesięciu wcześniej nieużywanych hostów,
2. `lateral_movement` — to samo konto rozszerza fan-out nawet do 120 rzadkich
   komputerów,
3. `privilege_escalation` — konto dociera do centralnych hostów, a kolejne konta
   pojawiają się na tym samym hoście pośrednim i powtarzają fan-out,
4. `automated_spread` — jedno z wtórnie przejętych kont wykonuje co 5 minut
   równoczesne logowania do 18 komputerów w trzygodzinnym oknie. Takie okno
   powtarza się co 24 godziny aż do końca zbioru.

Domyślnie pierwsze trzy fazy zajmują 6 godzin. Pierwsze okno automatycznego
ruchu zaczyna się po nich, trwa 3 godziny, po czym wraca codziennie do końca
danych. Dokładne interwały i identyczne timestampy w serii są zamierzone:
okresowość ma być czytelnym sygnałem dla analizującej grupy.

Nie są to prawdziwe informacje o roli hostów ani o uprawnieniach (zbiór zawiera
tylko trzy pola). To kontrolowane anomalie w grafie uwierzytelnień, dobrane tak,
żeby scenariusz był łatwy do wykrycia na zajęciach.

## Uruchomienie

Umieść pobrany plik w katalogu `data`. Jeżeli jest tam tylko jeden plik
`.bz2`, `.txt` albo `.csv`, wystarczy:

```powershell
.\.venv\Scripts\python.exe .\main.py
```

Skrypt automatycznie utworzy na przykład
`output\lanl-auth-dataset-1-modified.bz2` oraz pliki kontrolne w tym samym
katalogu.

Jeżeli w `data` znajduje się kilka zbiorów, wskaż nazwę wejścia. Opcjonalnie
możesz też podać nazwę wyjścia:

```powershell
.\.venv\Scripts\python.exe .\main.py `
  lanl-auth-dataset-1.bz2 `
  auth-for-other-team.bz2
```

Nazwy względne wejścia są szukane w `data`, a nazwy względne wyników trafiają
do `output`. Nadal można podać ścieżkę bezwzględną.

Skrypt wykonuje dwa pełne przebiegi po wejściu. Przy pliku 2.3 GB należy
zapewnić miejsce na nowy plik `.bz2` i liczyć się z długim czasem dekompresji
oraz ponownej kompresji.

Powstaną trzy pliki:

- `output\lanl-auth-dataset-1-modified.bz2` — dane do przekazania drugiej grupie,
- `*.ground_truth.csv` — lista wyłącznie dodanych zdarzeń wraz z fazą i opisem,
- `*.metadata.json` — wybrane konto, host pośredni, cele i parametry przebiegu.

Plików `ground_truth` i `metadata` nie należy przekazywać analizującej grupie.
Skrypt nie nadpisuje istniejących plików.

Przydatne opcje:

```text
--intensity 1..5       rozmiar fan-out (domyślnie 2)
--duration SECONDS     czas przejęcia/ruchu bocznego/eskalacji (domyślnie 6 godzin)
--automation-duration SECONDS
                       czas jednego dziennego okna (domyślnie 3 godziny)
--automation-interval SECONDS
                       odstęp między seriami (domyślnie 5 minut)
--automation-period SECONDS
                       odstęp między oknami (domyślnie 24 godziny)
--automation-hosts N   liczba hostów w jednej serii (domyślnie 18)
--seed N               deterministyczny wybór/kolejność (domyślnie 20261113)
--compresslevel 1..9   poziom kompresji bzip2
--progress-every N     częstotliwość komunikatów postępu; 0 je wyłącza
```

Do szybkiego testu warto najpierw użyć niewielkiego wycinka rozpakowanych danych
i wyjścia `.txt`; pełny plik uruchomić dopiero po obejrzeniu plików kontrolnych.

## Analiza z perspektywy drugiej grupy

Skrypt `analyze_logs.py` analizuje wyłącznie zmodyfikowany log i nie korzysta z
pliku ground truth ani metadanych generatora. Jeżeli w `output` znajduje się
jeden plik ze słowem `modified` w nazwie, wystarczy:

```powershell
.\.venv\Scripts\python.exe .\analyze_logs.py
```

Powstanie `output\analysis-report.html`. Raport zawiera dokładne timestampy
kandydatów początku incydentu, wykres wolumenu,
godzinowego fan-out, równoczesnych serii, ranking anomalii, analizę okresowości
i graf podejrzanych relacji użytkownik–komputer.

Przy wielu plikach wejście i nazwę raportu można wskazać jawnie:

```powershell
.\.venv\Scripts\python.exe .\analyze_logs.py `
  lanl-auth-dataset-1-modified.bz2 `
  monthly-analysis.html
```

Analiza pełnego skompresowanego zbioru także jest strumieniowa, ale wymaga
pełnej dekompresji i odczytania wszystkich rekordów. Istniejący raport można
zastąpić opcją `--force`.

Wygląd raportu można obejrzeć bez danych wejściowych:

```powershell
.\.venv\Scripts\python.exe .\analyze_logs.py --demo --force
```
