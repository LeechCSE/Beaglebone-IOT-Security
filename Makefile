CC = gcc
CFLAGS = -Wall -Wextra -g -lmraa -lm

default: build

build:
	$(CC) $(CFLAGS) -o tcp tcp.c
	$(CC) $(CFLAGS) -lssl -lcrypto -o tls tls.c

clean:
	@rm -f iot_security.tar.gz tcp tls *.log

dist: build
	@tar -czf iot_security.tar.gz tcp.c tls.c README.md Makefile
