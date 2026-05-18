PREFIX  ?= /usr/local
LIBDIR   = $(PREFIX)/lib
SO_NAME  = tls12_cap.so
SO_PATH  = $(LIBDIR)/$(SO_NAME)

CC       = gcc
CFLAGS   = -shared -fPIC -O2 -D_GNU_SOURCE -Wall -Wextra
LDFLAGS  = -ldl -lssl
MAPFLAG  = -Wl,--version-script=src/tls12_cap.map

.PHONY: all install uninstall clean

all: $(SO_NAME)

$(SO_NAME): src/tls12_cap.c src/tls12_cap.map
	$(CC) $(CFLAGS) -o $@ src/tls12_cap.c $(LDFLAGS) $(MAPFLAG)

install: $(SO_NAME)
	install -Dm 755 $(SO_NAME) $(SO_PATH)

uninstall:
	rm -f $(SO_PATH)

clean:
	rm -f $(SO_NAME)
