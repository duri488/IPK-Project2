all: ipk-sniffer.c 
	gcc -g -Wall -o ipk-sniffer ipk-sniffer.c -lpcap
clean: 
	$(RM) ipk-sniffer
