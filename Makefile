CC = gcc
CFLAGS = -Wall
CLIBS = -lpcap

q1.out: q1.cpp
	$(CC) $(CFLAGS) -o q1.out q1.cpp $(CLIBS)

q2.out: q2.cpp
	$(CC) $(CFLAGS) -o q2.out q2.cpp $(CLIBS)

q1: q1.out
	sudo ./q1.out

q2: q2.out
	sudo ./q2.out


.PHONY: clean

clean:
	rm -f q1.out
