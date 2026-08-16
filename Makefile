CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -Wpedantic -O2 -g
CPPFLAGS += -Iinclude -Isrc

.PHONY: all test clean autobahn

all: libwsio.a test_wsio echo_server

libwsio.a: src/wsio.o src/wsio_utf8.o
	$(AR) rcs $@ $^

src/wsio.o: src/wsio.c include/wsio.h src/wsio_utf8.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

src/wsio_utf8.o: src/wsio_utf8.c src/wsio_utf8.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

test_wsio: tests/test_wsio.c libwsio.a
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_wsio.c -L. -lwsio -o $@

echo_server: examples/echo_server.c libwsio.a
	$(CC) $(CPPFLAGS) $(CFLAGS) examples/echo_server.c -L. -lwsio -o $@

test: test_wsio
	./test_wsio

clean:
	rm -f src/*.o libwsio.a test_wsio echo_server
	rm -rf build autobahn/reports

autobahn: echo_server
	./scripts/run-autobahn.sh
