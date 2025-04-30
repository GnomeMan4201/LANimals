PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

INSTALL_BIN = lanimals lanimals_sysinfo lanimals_recon lanimals_alert lanimals_traffic lanimals_netmap lanimals_fortress

all:
	@echo "Available targets: install, uninstall, package"

install:
	mkdir -p $(BINDIR)
	for bin in $(INSTALL_BIN); do \
		install -m 0755 bin/$$bin $(BINDIR)/$$bin; \
	done

uninstall:
	for bin in $(INSTALL_BIN); do \
		rm -f $(BINDIR)/$$bin; \
	done

