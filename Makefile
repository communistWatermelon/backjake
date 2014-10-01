
# Makefile for pscan

CC=gcc -Wall 
CLIB=-lpthread -lpcap

pscan: pscan.o dgram.o utils.o pktcap.o
	$(CC) -g -o pscan pscan.o dgram.o utils.o pktcap.o $(CLIB)

clean:
	rm -f *.o core.* pscan

pscan.o:
	$(CC) -c pscan.c 
dgram.o: 
	$(CC) -c dgram.c
utils.o: 
	$(CC) -c utils.c
pktcap.o:
	$(CC) -c pktcap.c
