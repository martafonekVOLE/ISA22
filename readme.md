# NetFlow v5 exporter

## Úvod
V rámci projektu do předmětu Síťové aplikace a správa sítí byl vytvořen NetFlow exportér. Tato aplikace umožnuje
zpracovávat zachycená data ve formátu pcap. Po zpracování záznamů dojde k exportu analyzovaných dat na kolektor
ve formátu NetFlow packetu. Výstupním formátem je tedy NetFlow záznam ve verzi 51 (dále jen flow ). Takto
formátovaný záznam je odeslán na kolektor. Program podporuje zpracování protokolů TCP, UDP a ICMP. Aplikace byla
vyvíjena v jazyce C++ a je určena pro Unixové operační systémy.

## Překlad
Po stažení zdrojových souborů je aplikaci potřeba přeložit. K tomu je možné využít přiložený soubor makefile, nebo
překladač G++ s příkazem:
g++ main.cpp -o flow -lpcap

## Obecná syntaxe spouštění:
./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m
<count>]

-f <file> - volitelný parametr, který očekává jméno pcap souboru. Není-li uveden, program načítá ze standart-
ního vstupu STDIN.

-c <netflow_collector>:<port> - volitelný parametr, očekává hostovské jméno/ip adresu místa, na které má
odesílat výsledné NetFlow záznamy. Volitelně lze doplnit i port. Jako výchozí hodnoty uvažuje 127.0.0.1:2055.

-a <active_timer> - volitelný parametr značící maximální dobu sdružování packetů do jedné flow. Příjmá
hodnoty v sekundách. Výchozí hodnota je 60. Po vypršení se hodnoty odesílají na kolektor.

-i <inactive_timer> - volitelný parametr značící maximální dobu čekání na následující packet v dané flow.
Příjmá hodnoty v sekundách. Výchozí hodnota je 10. Po vypršení se hodnoty odesílají na kolektor.

-m <count> - volitelný parametr označující velikost flow cache, tedy maximální počet záznamů udržitelný v jeden
moment v paměti. Při dosažení maximální velikosti dojde k odeslání nejstaršího záznamu. Výchozí hodnota je
1024.

V případě nevyplnění některého z parametrů uvažuje aplikace výchozí hodnotu.

## Manuál
man -l flow.1 zobrazí manuálovou stránku příkazu

## Dokumentace
Pro konkrétní popis čtěte prosím dokumentaci manual.pdf
