# Installation directories.
PREFIX ?= /usr
SBINDIR ?= $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man
ETCDIR ?= /etc

CFLAGS ?= -Werror -Wall -W
override CFLAGS += -D_FILE_OFFSET_BITS=64
override LDLIBS += -lselinux

all: sebox

sebox: sebox.o

install: all
	[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	-mkdir -p $(DESTDIR)$(SBINDIR)
	install -m 755 sebox $(DESTDIR)$(SBINDIR)
	install -m 644 sebox.8 $(DESTDIR)$(MANDIR)/man8
	-mkdir -p $(DESTDIR)$(ETCDIR)

clean:
	rm -f sebox *.o

indent:
	../../scripts/Lindent $(wildcard *.[ch])

relabel:
