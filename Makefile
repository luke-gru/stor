CC=gcc
CFLAGS=-I./include -std=c99 -Wall -Werror -g
ODIR=build

.PHONY: stor
stor: build
	$(CC) $(CFLAGS) main.c db.c kstrdup.c vec.c -o $(ODIR)/stor

.PHONY: test
test: build
	$(CC) $(CFLAGS) test.c db.c kstrdup.c vec.c -o $(ODIR)/test

build:
	mkdir $(ODIR)

.PHONY: clean
clean:
	rm -f $(ODIR)/*
