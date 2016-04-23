# The makefile for MP1.

INCLUDES = -I/usr/include/mysql/
LIBS = -L/usr/include/mysql/ -L/usr/lib64/mysql -lmysqlclient -lpthread -lz -lm -lssl -lcrypto -ldl -lpcap

rollcall: rollcall.o
	gcc -Wall -g rollcall.o -o rollcall $(LIBS)

rollcall.o: rollcall.c rollcall.h
	gcc -Wall -g -c $(INCLUDES) rollcall.c

sniff2: sniff2.c
	gcc -Wall -g sniff2.c -o sniff2

macsiff: macsniff.c
	gcc -Wall -g sniff2.c -o sniff2

run:
	sudo ./rollcall -d wlp0s20u2

clean :
	rm -f *.o rollcall sniff2 macsniff core 

