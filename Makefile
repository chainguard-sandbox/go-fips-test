# SPDX-FileCopyrightText: 2026 Chainguard, Inc
#
# SPDX-License-Identifier: Apache-2.0

CFLAGS  ?= -Wall -Wextra -O3 -flto -ffunction-sections -fdata-sections -g0
LDFLAGS ?= -flto -Wl,--gc-sections -Wl,-s

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin

all: go-fips-test

go-fips-test: main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

install: go-fips-test
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 go-fips-test $(DESTDIR)$(BINDIR)/go-fips-test

annotate:
	reuse annotate --copyright "Chainguard, Inc" --license Apache-2.0 --recursive .

clean:
	rm -f go-fips-test

.PHONY: all install clean
