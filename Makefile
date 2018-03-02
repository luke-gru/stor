CC=gcc
CFLAGS=-I./include -std=c99 -Wall -Werror -g
ODIR=build

.PHONY: stor
stor: build
	$(CC) $(CFLAGS) main.c strdup.c vec.c -o $(ODIR)/stor

build:
	mkdir $(ODIR)

.PHONY: clean
clean:
	rm -f $(ODIR)/*
