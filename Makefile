.PHONY: all clean

all: superstrip

superstrip:
	gcc -o superstrip superstrip.c -I /usr/include/skalibs/ -l skarnet -L /usr/lib64/skalibs

clean:
	rm superstrip
