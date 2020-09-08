Popis programu ipk-sniffer:

Sniffer je aplikácia, ktorá zachytáva a filtruje pakety na zadanom sieťovom rozhraní. Aplikácia umožňuje užívateľovi zobraziť aktívne sieťové rozhrania a následne sledovať TCP alebo UDP pakety na vybranom rozhraní, prípadne aj na vybranom porte daného rozhrania. Výstup snifferu obsahuje čas prijatia paketu, IP adresu/príslušné doménové meno a port zdroja paketu, IP adresu/príslušné doménové meno a port cieľa paketu. Nasleduje obsah hlavičiek a obsah dát paketu v hexadecimálnej forme a v ASCII forme kde sú netlačiteľné znaky nahradené bodkou. Taktiež je možné vypísať si obsah DNS cache programu.

Rozšírenia:
Program v základnom nastavení neprekladá IP adresy na doménové mená. Na spustenie resolvingu je potrebný spínač -r(vytvára si vlastnú DNS cache a nevytvára cyklenie paketov). Spínač -d spustí zobrazovanie danej cache.

Príklady spustenia: 

•	$ ./ipk-sniffer -i enp0s3 -p 80 -t -n 5
•	$ ./ipk-sniffer -i enp0s3 -u
•	$ ./ipk-sniffer
•	$ ./ipk-sniffer -n
•	$ ./ipk-sniffer -p 443 -t -u
•	$ ./ipk-sniffer -i enp0s3
•	$ ./ipk-sniffer -i enp0s3 -n 5 -r -d


Zoznam odovzdaných súborov:
1. ipk-sniffer.c
2. Makefile
3. manual.pdf
4. README.txt
