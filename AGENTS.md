# MailD Project - Agent Documentation

This document provides essential information for AI coding agents working on the MailD project.

## Project Overview

MailD is a production-ready mail server suite for Linux consisting of two daemons:
- **pop3d**: POP3 server for mail retrieval (RFC 1939 compliant)
- **smtpd**: SMTP server for mail submission and delivery

Both servers share a common library and support:
- PAM or shadow password authentication
- SSL/TLS encryption (OpenSSL)
- Maildir format storage
- IPv4/IPv6 dual-stack
- Systemd integration

## Technology Stack

- **Language**: C (GNU99 standard)
- **Build System**: GNU Make
- **SSL/TLS**: OpenSSL (1.0+ and 3.0+)
- **Authentication**: PAM (preferred) or shadow passwords (fallback)
- **Logging**: syslog
- **Platform**: Linux (Debian/Ubuntu, RHEL/CentOS, Arch)

## File Structure

```
maild/
├── pop3d.c           # POP3 server implementation (~988 lines)
├── smtpd.c           # SMTP server implementation (~1166 lines)
├── mail_common.c     # Shared library (~725 lines)
├── mail_common.h     # Common header with structs and prototypes
├── Makefile          # Build configuration
├── README.md         # User documentation
├── AGENTS.md         # This file
│
├── pop3d.conf        # POP3 configuration template
├── smtpd.conf        # SMTP configuration template
├── maild.conf        # Unified configuration (installed to /etc/)
│
├── pop3d.pam         # PAM config template for POP3
├── smtpd.pam         # PAM config template for SMTP
├── maild.pam         # Unified PAM config
│
├── pop3d.service     # Systemd service for POP3
├── smtpd.service     # Systemd service for SMTP
│
├── pop3d.8           # Man page for pop3d
├── smtpd.8           # Man page for smtpd
│
├── test_pop3d.sh     # Comprehensive test suite
└── certs/            # Certificate directory (runtime)
```

## Build System

### Build Commands

```bash
# Build both daemons
make

# Build with verbose output
make check all

# Clean build artifacts
make clean

# Clean build artifacts
make clean

# Install (requires root)
sudo make install

# Uninstall
sudo make uninstall
```

### Build Configuration

The Makefile auto-detects:
- **PAM support**: Uses pkg-config to detect libpam, falls back to shadow passwords
- **OpenSSL location**: Auto-detects Homebrew paths on macOS
- **Platform**: Adds `-lcrypt` on Linux

Compiler flags:
```makefile
CFLAGS = -Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes
       -Wmissing-declarations -Wshadow -Wpointer-arith
       -Wcast-qual -Wsign-compare -O2
       -D_GNU_SOURCE -D_DEFAULT_SOURCE
```

## Code Organization

### Common Library (mail_common.c/h)

Shared structures and functions used by both daemons:

**Key Structures:**
- `ClientBase`: Base client structure (socket, SSL, auth state, IP)
- `GlobalConfig`: Unified configuration for both protocols
- `ServerContext`: Server state (SSL context, running flag, service name)

**Key Functions:**
- `authenticate_user()`: PAM or shadow auth
- `init_ssl()`, `cleanup_ssl()`: SSL context management
- `send_response()`, `receive_line()`: Network I/O with SSL support
- `validate_input()`: Input sanitization
- `parse_config()`: Configuration file parsing
- `create_server_socket()`: IPv4/IPv6 socket creation

### POP3 Server (pop3d.c)

**Client Structure:** `Pop3Client` extends `ClientBase`
- Maildir path and message array
- Login attempt counter

**Commands Implemented:**
- `USER/PASS`: Authentication
- `STAT`: Message count and size
- `LIST`: Message listing
- `RETR`: Retrieve message
- `DELE`: Mark for deletion
- `RSET`: Reset deletion marks
- `UIDL`: Unique message IDs
- `TOP`: Headers + partial body
- `NOOP`, `QUIT`, `CAPA`

**Ports:**
- 110: Plaintext POP3 (optional STARTTLS)
- 995: POP3S (SSL/TLS)

### SMTP Server (smtpd.c)

**Client Structure:** `SmtpClient` extends `ClientBase`
- SMTP state machine
- Envelope information (MAIL FROM, RCPT TO)
- Message spool file descriptor

**Commands Implemented:**
- `EHLO/HELO`: Greeting
- `MAIL FROM`: Sender specification
- `RCPT TO`: Recipient specification
- `DATA`: Message content
- `AUTH PLAIN/LOGIN`: Authentication
- `STARTTLS`: TLS upgrade
- `RSET`, `NOOP`, `QUIT`, `HELP`

**Ports:**
- 25: SMTP (requires STARTTLS for auth)
- 587: Submission (STARTTLS)
- 465: SMTPS (implicit TLS)

## Configuration System

### Configuration File Format

Key-value format with `#` comments:
```ini
# Network settings
port = 110
ssl_port = 995
ipv6_enabled = 1

# Security
allow_plaintext = 0
max_connections = 50

# Paths
cert_file = /etc/ssl/certs/maild.crt
key_file = /etc/ssl/private/maild.key
maildir_base = /var/mail

# Timeouts (seconds)
timeout_login = 60
timeout_command = 300
```

### Configuration Loading Order

1. Hardcoded defaults in `g_config` (mail_common.c)
2. `/etc/maild.conf` (or `-c` specified file)
3. Protocol-specific settings override common settings

## Testing

### Test Suite: test_pop3d.sh

Comprehensive bash-based test suite with categories:

1. **Connection & Protocol** (8 tests): Greeting, CAPA, NOOP, command validation
2. **Authentication** (10 tests): USER/PASS flow, auth failures
3. **Transaction State** (6+ tests): STAT, LIST, RETR, DELE, RSET
4. **Maildir Operations**: Message delivery, deletion persistence
5. **Security**: Long lines, invalid commands, timeout handling

### Running Tests

```bash
# Run test suite
./test_pop3d.sh

# Requires root for full auth testing
sudo ./test_pop3d.sh
```

### Manual Testing

```bash
# Test POP3S
openssl s_client -connect localhost:995 -quiet

# Test SMTP
openssl s_client -connect localhost:465 -quiet

# Test PAM auth directly
sudo pamtester pop3d username authenticate
```

## Security Considerations

### Authentication
- Primary: PAM (supports LDAP, Kerberos, 2FA via PAM modules)
- Fallback: Shadow passwords with timing-attack resistant crypt()
- Max 3 login attempts per connection (POP3)

### Encryption
- TLS 1.2+ required (SSLv2/3 and TLSv1/1.1 disabled)
- Self-signed cert generation: `pop3d -g` or `smtpd -g`
- Production: Use Let's Encrypt or proper CA certificates

### Input Validation
- `validate_input()`: Rejects non-printable characters
- Line length limits (MAX_LINE_LENGTH = 1024)
- Email address parsing with bounds checking

### Privilege Separation
- Runs as unprivileged user after binding ports
- Systemd hardening: `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`

### Security Logging
```c
log_security("Auth failed", client_ip, username);
log_security("Login limit exceeded", client_ip, NULL);
log_security("Connection limit reached", client_ip, NULL);
log_security("SSL handshake failed", client_ip, NULL);
```

## Code Style Guidelines

### Naming Conventions
- Functions: `snake_case` (e.g., `handle_command`, `load_maildir`)
- Structs: `PascalCase` (e.g., `Pop3Client`, `GlobalConfig`)
- Constants: `UPPER_CASE` with underscores
- Globals: `g_` prefix (e.g., `g_config`, `g_ctx`)

### Error Handling
- Check all system calls for errors
- Use `log_error()` for operational errors
- Use `syslog(LOG_ERR, ...)` directly for critical failures
- Always cleanup resources on error paths

### Memory Management
- Use `calloc()` for zero-initialization
- Free resources in reverse allocation order
- Check for NULL before dereferencing

### String Handling
- Always use `strncpy()` with sizeof-1 and null-terminate
- Use `snprintf()` for formatted output
- Validate string lengths before operations

Example:
```c
strncpy(dest, src, sizeof(dest) - 1);
dest[sizeof(dest) - 1] = '\0';
```

## Protocol Implementation Details

### POP3 State Machine
```
AUTH -> (USER+PASS) -> TRANSACTION -> (QUIT) -> UPDATE
```

### SMTP State Machine
```
CONNECTED -> EHLO/HELO -> MAIL -> RCPT -> DATA -> (QUIT)
```

### Maildir Format
- `new/`: Incoming messages
- `cur/`: Messages being accessed
- `tmp/`: Temporary files during delivery

Message filenames: `<timestamp>.<pid>.<host>`

## Common Tasks

### Adding a New Configuration Option

1. Add field to `GlobalConfig` struct in `mail_common.h`
2. Set default in `g_config` initialization in `mail_common.c`
3. Add parsing case in `parse_config()` function
4. Update `maild.conf` template with documentation

### Adding a New POP3 Command

1. Add handler function in `pop3d.c`:
   ```c
   static void handle_newcmd(Pop3Client *client, const char *arg)
   ```
2. Add command case in `process_command()` switch statement
3. Add to CAPA list if applicable
4. Add test case in `test_pop3d.sh`

### Adding a New SMTP Command

1. Add handler function in `smtpd.c`
2. Add command case in `process_command()`
3. Update EHLO response if extension
4. Update state machine if needed

## Debugging

### Debug Mode
Run in foreground with debug output:
```bash
sudo ./pop3d -d
sudo ./smtpd -d
```

### Syslog Output
```bash
# systemd journal
sudo journalctl -u pop3d -f
sudo journalctl -u smtpd -f

# syslog
sudo tail -f /var/log/mail.log
```

### Common Issues

**SSL handshake failures:**
- Check certificate permissions (readable by service user)
- Verify certificate with: `openssl x509 -in cert.crt -text -noout`

**Authentication failures:**
- Test PAM: `pamtester pop3d username authenticate`
- Check /etc/pam.d/pop3d configuration
- Verify user exists: `id username`

**Permission denied on maildir:**
```bash
chown -R username:mail /var/mail/username
chmod 700 /var/mail/username
```

## License

ISC License - See source file headers for full text.
