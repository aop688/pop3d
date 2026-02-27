# Makefile for pop3d - Production POP3 server with PAM/shadow authentication

PROG		= pop3d
MAN		= pop3d.8
CC		= cc
CFLAGS		= -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes
CFLAGS		+= -Wmissing-declarations -Wshadow -Wpointer-arith
CFLAGS		+= -Wcast-qual -Wsign-compare -O2
CFLAGS		+= -D_GNU_SOURCE -D_DEFAULT_SOURCE
LDFLAGS		= -lssl -lcrypto -lcrypt

# Check for PAM availability
PAM_CHECK := $(shell pkg-config --exists pam 2>/dev/null && echo yes || echo no)
ifeq ($(PAM_CHECK),yes)
  CFLAGS += $(shell pkg-config --cflags pam)
  LDFLAGS += $(shell pkg-config --libs pam) -lpam_misc
  AUTH_MODE = PAM
else
  # Check for PAM header directly
  PAM_HEADER := $(shell echo '#include <security/pam_appl.h>' | $(CC) -E - >/dev/null 2>&1 && echo yes || echo no)
  ifeq ($(PAM_HEADER),yes)
    LDFLAGS += -lpam -lpam_misc
    AUTH_MODE = PAM
  else
    AUTH_MODE = SHADOW
  endif
endif

PREFIX		= /usr/local
BINDIR		= $(PREFIX)/sbin
MANDIR		= $(PREFIX)/share/man/man8
SYSCONFDIR	= /etc
PAMDIR		= $(SYSCONFDIR)/pam.d

SRCS		= pop3d.c

.PHONY: all clean install uninstall test cert check

all: check $(PROG)

check:
	@echo "Building with $(AUTH_MODE) authentication support"

$(PROG): $(SRCS)
	$(CC) $(CFLAGS) -o $(PROG) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(PROG) *.o core

install: $(PROG)
	@echo "Installing pop3d..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(PROG) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 $(MAN) $(DESTDIR)$(MANDIR)/ 2>/dev/null || true
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -m 644 pop3d.conf $(DESTDIR)$(SYSCONFDIR)/pop3d.conf
ifeq ($(AUTH_MODE),PAM)
	install -d $(DESTDIR)$(PAMDIR)
	install -m 644 pop3d.pam $(DESTDIR)$(PAMDIR)/pop3d
endif
	@echo "Installing systemd service..."
	install -d $(DESTDIR)$(SYSCONFDIR)/systemd/system
	install -m 644 pop3d.service $(DESTDIR)$(SYSCONFDIR)/systemd/system/
	@echo "Creating mail directory..."
	install -d -m 755 $(DESTDIR)/var/mail
	@echo ""
	@echo "Installation complete!"
ifeq ($(AUTH_MODE),PAM)
	@echo "Using PAM authentication."
else
	@echo "Using shadow password authentication (PAM headers not found)."
	@echo "To use PAM, install libpam0g-dev (Debian/Ubuntu) or pam-devel (RHEL)."
endif
	@echo ""
	@echo "Next steps:"
	@echo "  1. Generate SSL certificate: sudo $(DESTDIR)$(BINDIR)/$(PROG) -g"
	@echo "  2. Edit config: sudo editor $(DESTDIR)$(SYSCONFDIR)/pop3d.conf"
	@echo "  3. Start service: sudo systemctl enable --now pop3d"
	@echo "  4. Check status: sudo systemctl status pop3d"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(PROG)
	rm -f $(DESTDIR)$(MANDIR)/$(MAN)
	rm -f $(DESTDIR)$(SYSCONFDIR)/pop3d.conf
	rm -f $(DESTDIR)$(PAMDIR)/pop3d
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/pop3d.service

cert: $(PROG)
	./$(PROG) -g

test: $(PROG)
	@echo "Testing POP3 server:"
	@echo "  Configuration: $(SYSCONFDIR)/pop3d.conf"
ifeq ($(AUTH_MODE),PAM)
	@echo "  PAM config: $(PAMDIR)/pop3d"
endif
	@echo ""
	@echo "To test:"
	@echo "  1. Start server: sudo ./$(PROG) -d"
	@echo "  2. Connect: openssl s_client -connect localhost:995 -quiet"
	@echo "  3. Or with STARTTLS: openssl s_client -connect localhost:110 -starttls pop3 -quiet"
	@echo ""
	@echo "Then type:"
	@echo "  USER your_username"
	@echo "  PASS your_password"
	@echo "  STAT"
	@echo "  LIST"
	@echo "  QUIT"
