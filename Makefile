# Makefile for pop3d and smtpd - Production mail servers with shared library

POP3D_PROG	= pop3d
SMTPD_PROG	= smtpd
POP3D_MAN	= pop3d.8
SMTPD_MAN	= smtpd.8

CC		= cc
CFLAGS		= -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes
CFLAGS		+= -Wmissing-declarations -Wshadow -Wpointer-arith
CFLAGS		+= -Wcast-qual -Wsign-compare -O2
CFLAGS		+= -D_GNU_SOURCE -D_DEFAULT_SOURCE
LDFLAGS		= -lssl -lcrypto

# crypt library needed on Linux but included in libc on macOS
ifeq ($(shell uname -s),Linux)
  LDFLAGS += -lcrypt
endif

# Auto-detect macOS Homebrew OpenSSL paths
ifeq ($(shell uname -s),Darwin)
  ifeq ($(shell test -d /opt/homebrew/opt/openssl && echo yes || echo no),yes)
    CFLAGS += -I/opt/homebrew/opt/openssl/include
    LDFLAGS += -L/opt/homebrew/opt/openssl/lib
  else ifeq ($(shell test -d /usr/local/opt/openssl && echo yes || echo no),yes)
    CFLAGS += -I/usr/local/opt/openssl/include
    LDFLAGS += -L/usr/local/opt/openssl/lib
  endif
endif

# Check for PAM availability using pkg-config
PAM_CHECK := $(shell pkg-config --exists pam 2>/dev/null && echo yes || echo no)
ifeq ($(PAM_CHECK),yes)
  CFLAGS += $(shell pkg-config --cflags pam 2>/dev/null)
  LDFLAGS += $(shell pkg-config --libs pam 2>/dev/null) -lpam_misc
  AUTH_MODE = PAM
else
  # Fallback: check for PAM header file directly
  PAM_HEADER_EXISTS := $(shell test -f /usr/include/security/pam_appl.h && echo yes || echo no)
  ifeq ($(PAM_HEADER_EXISTS),yes)
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

COMMON_SRCS	= mail_common.c
COMMON_OBJS	= mail_common.o
POP3D_SRCS	= pop3d.c
SMTPD_SRCS	= smtpd.c

.PHONY: all clean install uninstall test cert check

all: check $(POP3D_PROG) $(SMTPD_PROG)

check:
	@echo "Building with $(AUTH_MODE) authentication support"

$(COMMON_OBJS): $(COMMON_SRCS) mail_common.h
	$(CC) $(CFLAGS) -c -o $@ $(COMMON_SRCS)

$(POP3D_PROG): $(POP3D_SRCS) $(COMMON_OBJS) mail_common.h
	$(CC) $(CFLAGS) -o $(POP3D_PROG) $(POP3D_SRCS) $(COMMON_OBJS) $(LDFLAGS)

$(SMTPD_PROG): $(SMTPD_SRCS) $(COMMON_OBJS) mail_common.h
	$(CC) $(CFLAGS) -o $(SMTPD_PROG) $(SMTPD_SRCS) $(COMMON_OBJS) $(LDFLAGS)

clean:
	rm -f $(POP3D_PROG) $(SMTPD_PROG) $(COMMON_OBJS) *.o core

install: all
	@echo "Installing pop3d..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(POP3D_PROG) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 $(POP3D_MAN) $(DESTDIR)$(MANDIR)/ 2>/dev/null || true
	install -d $(DESTDIR)$(SYSCONFDIR)
	install -m 644 maild.conf $(DESTDIR)$(SYSCONFDIR)/maild.conf
ifeq ($(AUTH_MODE),PAM)
	install -d $(DESTDIR)$(PAMDIR)
	install -m 644 maild.pam $(DESTDIR)$(PAMDIR)/pop3d
	install -m 644 maild.pam $(DESTDIR)$(PAMDIR)/smtpd
endif
	@echo "Installing pop3d systemd service..."
	install -d $(DESTDIR)$(SYSCONFDIR)/systemd/system
	install -m 644 pop3d.service $(DESTDIR)$(SYSCONFDIR)/systemd/system/
	@echo "Installing smtpd..."
	install -m 755 $(SMTPD_PROG) $(DESTDIR)$(BINDIR)/
	install -m 644 $(SMTPD_MAN) $(DESTDIR)$(MANDIR)/ 2>/dev/null || true
	@echo "Installing smtpd systemd service..."
	install -m 644 smtpd.service $(DESTDIR)$(SYSCONFDIR)/systemd/system/
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
	@echo "  1. Generate SSL certificates:"
	@echo "     sudo $(DESTDIR)$(BINDIR)/$(POP3D_PROG) -g"
	@echo "     sudo $(DESTDIR)$(BINDIR)/$(SMTPD_PROG) -g"
	@echo "  2. Edit config:"
	@echo "     sudo editor $(DESTDIR)$(SYSCONFDIR)/maild.conf"
	@echo "  3. Start services:"
	@echo "     sudo systemctl enable --now pop3d"
	@echo "     sudo systemctl enable --now smtpd"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(POP3D_PROG)
	rm -f $(DESTDIR)$(BINDIR)/$(SMTPD_PROG)
	rm -f $(DESTDIR)$(MANDIR)/$(POP3D_MAN)
	rm -f $(DESTDIR)$(MANDIR)/$(SMTPD_MAN)
	rm -f $(DESTDIR)$(SYSCONFDIR)/maild.conf
	rm -f $(DESTDIR)$(PAMDIR)/pop3d
	rm -f $(DESTDIR)$(PAMDIR)/smtpd
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/pop3d.service
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/smtpd.service

cert: $(POP3D_PROG) $(SMTPD_PROG)
	./$(POP3D_PROG) -g
	./$(SMTPD_PROG) -g

test: all
	@echo "Testing POP3 and SMTP servers:"
	@echo "  Configuration: $(SYSCONFDIR)/maild.conf"
	@echo ""
ifeq ($(AUTH_MODE),PAM)
	@echo "  PAM config: $(PAMDIR)/pop3d"
	@echo "  PAM config: $(PAMDIR)/smtpd"
endif
	@echo ""
	@echo "To test POP3:"
	@echo "  1. Start server: sudo ./$(POP3D_PROG) -d"
	@echo "  2. Connect: openssl s_client -connect localhost:995 -quiet"
	@echo "  3. Commands: USER, PASS, STAT, LIST, RETR, QUIT"
	@echo ""
	@echo "To test SMTP:"
	@echo "  1. Start server: sudo ./$(SMTPD_PROG) -d"
	@echo "  2. Connect: openssl s_client -connect localhost:465 -quiet"
	@echo "  3. Commands: EHLO, AUTH LOGIN, MAIL FROM, RCPT TO, DATA, QUIT"
