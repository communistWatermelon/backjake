
# Makefile for pscan

CC=gcc -Wall 
CLIB=-lpthread -lpcap

back: backjake.o recvFunctions.o spyFunctions.o utils.o sendFunctions.o
	$(CC) -g -o back backjake.o recvFunctions.o spyFunctions.o utils.o sendFunctions.o $(CLIB)

clean:
	rm -f *.o core.* back

backjake.o:
	$(CC) -c backjake.c 
recvFunctions.o: 
	$(CC) -c recvFunctions.c
spyFunctions.o:
	$(CC) -c spyFunctions.c
sendFunctions.c:
	$(CC) -c sendFunctions.c
utils.o:
	$(CC) -c utils.c