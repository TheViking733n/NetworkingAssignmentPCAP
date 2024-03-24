CC = gcc
CFLAGS = -Wall
CLIBS = -lpcap

q1: q1.cpp
	$(CC) $(CFLAGS) -o q1 q1.cpp $(CLIBS)

clean:
	rm -f q1

