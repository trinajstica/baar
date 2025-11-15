CC = gcc
# Suppress deprecated-declarations warnings (GTK4 still exposes some deprecated helpers)
CFLAGS = -O2 -Wall $(PKG_CFLAGS) -Wno-deprecated-declarations
LDFLAGS = -lz -pthread $(PKG_LIBS) -lcrypto
PREFIX ?= /usr
DESTDIR ?=

# use pkg-config for gtk4, json-glib, and libarchive
PKG_CFLAGS := $(shell pkg-config --cflags gtk4 json-glib-1.0 libarchive 2>/dev/null)
PKG_LIBS := $(shell pkg-config --libs gtk4 json-glib-1.0 libarchive 2>/dev/null)

# Conversion helpers removed; no detection performed

SRC = $(wildcard src/*.c)
OBJ = $(SRC:.c=.o)

# build only the CLI binary: baar
BIN = baar

all: $(BIN)

# CLI: build from src/baar.c and src/la_bridge.c
baar: src/baar.o src/la_bridge.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# generic compilation rule for C sources
src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<


clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean install uninstall

install:
	strip --strip-unneeded baar || true
	upx -9 baar || true
	install -Dm755 baar $(DESTDIR)$(PREFIX)/bin/baar
	install -Dm644 baar.desktop $(DESTDIR)$(PREFIX)/share/applications/baar.desktop
	install -Dm644 baar.png $(DESTDIR)$(PREFIX)/share/pixmaps/baar.png
	install -Dm644 baar.xml $(DESTDIR)$(PREFIX)/share/mime/packages/baar.xml
	install -Dm644 baar.png $(DESTDIR)$(PREFIX)/share/icons/hicolor/48x48/mimetypes/application-x-baar.png
	update-mime-database $(DESTDIR)$(PREFIX)/share/mime || true
	gtk-update-icon-cache $(DESTDIR)$(PREFIX)/share/icons/hicolor || true

UNINSTALL_FILES = \
	$(DESTDIR)$(PREFIX)/bin/baar \
	$(DESTDIR)$(PREFIX)/share/applications/baar.desktop \
	$(DESTDIR)$(PREFIX)/share/pixmaps/baar.png \
	$(DESTDIR)$(PREFIX)/share/mime/packages/baar.xml \
	$(DESTDIR)$(PREFIX)/share/icons/hicolor/48x48/mimetypes/application-x-baar.png

uninstall:
	@echo "Odstranjevanje BAAR namestitve..."
	@for f in $(UNINSTALL_FILES); do \
		if [ -f $$f ]; then rm -f $$f && echo "removed $$f"; fi; \
	done
	@echo "Osvežujem MIME in ikonske predpomnilnike..."
	-update-mime-database $(DESTDIR)$(PREFIX)/share/mime || true
	-gtk-update-icon-cache $(DESTDIR)$(PREFIX)/share/icons/hicolor || true
