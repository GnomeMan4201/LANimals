PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

INSTALL_BIN := $(notdir $(wildcard bin/lanimals*))

all:
	@echo "Available targets: install, uninstall, package"

install:
	mkdir -p $(BINDIR)
	for bin in $(INSTALL_BIN); do \
		ln -sfn "$(CURDIR)/bin/$$bin" "$(BINDIR)/$$bin"; \
	done

uninstall:
	for bin in $(INSTALL_BIN); do \
		rm -f $(BINDIR)/$$bin; \
	done
