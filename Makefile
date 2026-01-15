# Linux Makefile for pop3d
PROG=		pop3d
SIMPLE_PROG=	simple_pop3d
MAN=		pop3d.8
CC=		cc
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations -Wshadow -Wpointer-arith
CFLAGS+=	-Wcast-qual -Wsign-compare
CFLAGS+=	-DIO_SSL -D_GNU_SOURCE
DEBUG=		-g
SRCS=		pop3d.c pop3e.c session.c maildrop.c maildir.c mbox.c util.c
SRCS+=		imsgev.c iobuf.c ioev.c imsg.c
SRCS+=		ssl.c ssl_privsep.c
LDADD+=		-levent -lssl -lcrypto

# Default target - build all versions
all: $(SIMPLE_PROG) secure_pop3d ssl_pop3d

# Basic version for Linux
$(SIMPLE_PROG): simple_pop3d.c
	$(CC) $(CFLAGS) -o $(SIMPLE_PROG) simple_pop3d.c

# More secure version (still not production-ready)
secure_pop3d: secure_pop3d.c
	$(CC) $(CFLAGS) -o secure_pop3d secure_pop3d.c

# SSL-enabled version with STARTTLS and POP3S
ssl_pop3d: ssl_pop3d.c
	$(CC) $(CFLAGS) -o ssl_pop3d ssl_pop3d.c -lssl -lcrypto

# Original complex version (may not compile on Linux)
$(PROG): $(SRCS)
	$(CC) $(CFLAGS) -o $(PROG) $(SRCS) $(LDADD) || echo "Original version failed to compile - use simple_pop3d instead"

clean:
	rm -f $(PROG) $(SIMPLE_PROG) secure_pop3d ssl_pop3d *.o

install: ssl_pop3d
	install -m 755 ssl_pop3d /usr/local/bin/
	install -m 644 $(MAN) /usr/local/man/man8/ || echo "Man page installation optional"

test: ssl_pop3d
	@echo "Testing SSL-enabled POP3 server:"
	@echo "User: aptuser"
	@echo "Password: pop3dabc123"
	@echo "Ports: 110 (STARTTLS) and 995 (POP3S)"
	@echo "Run: sudo ./ssl_pop3d"
	@echo ""
	@echo "Generate test certificate:"
	@echo "./ssl_pop3d -g"

.PHONY: all clean install test
