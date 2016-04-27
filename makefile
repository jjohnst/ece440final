#Builds rollcall and submit executables
CC=gcc -Wall
#correct includes can be found using mysql_config --cflags
INCLUDES = -I/usr/local/mysql/include -fno-omit-frame-pointer -arch x86_64
#correct mysql libs can be found by using mysql_config --libs
LIBS = -L/usr/local/mysql/lib -lmysqlclient -lpthread -lz -lm -lssl -lcrypto -ldl -lpcap
BINS = rollcall submit core

all: rollcall  submit

rollcall.o: rollcall.c rollcall.h
	$(CC) -c $(INCLUDES) rollcall.c

rollcall: rollcall.o
	$(CC) -o rollcall rollcall.o $(LIBS)

submit.o: submit.c rollcall.h
	$(CC) -c $(INCLUDES) submit.c

submit: submit.o
	$(CC) -o submit submit.o $(LIBS)

clean:
	rm $(BINS) *.o 

run:
	sudo ./rollcall -d en0
