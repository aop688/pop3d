# POP3D - Production POP3 Server for OpenSMTPD

## Project Overview

This is a production-ready POP3 server for Linux, designed for personal/small-scale mail servers using OpenSMTPD. It features PAM authentication, SSL/TLS encryption, and maildir storage support.

## Project Structure

```
.
├── pop3d.c              # Main server source code
├── pop3d.conf           # Configuration file
├── pop3d.pam            # PAM authentication configuration
├── pop3d.service        # systemd service file
├── pop3d.8              # Man page
├── Makefile             # Build system
├── README.md            # User documentation
└── certs/               # SSL certificates (generated at runtime)
    ├── server.crt
    └── server.key
```

## Building

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install build-essential libssl-dev libpam0g-dev

# CentOS/RHEL/Rocky Linux
sudo yum install gcc openssl-devel pam-devel

# Arch Linux
sudo pacman -S base-devel openssl pam
```

### Compilation

```bash
make
sudo make install
```

## Configuration

### Basic Configuration (/etc/pop3d.conf)

```ini
port = 110
ssl_port = 995
allow_plaintext = 0
max_connections = 50

cert_file = /etc/ssl/certs/pop3d.crt
key_file = /etc/ssl/private/pop3d.key
maildir_base = /var/mail
```

### SSL Certificate Generation

```bash
sudo pop3d -g
```

## Authentication Methods

The server automatically detects and uses available authentication:

1. **PAM** (preferred): Uses system PAM configuration via `/etc/pam.d/pop3d`
2. **Shadow passwords** (fallback): Direct /etc/shadow access if PAM headers unavailable

## Integration with OpenSMTPD

### OpenSMTPD Configuration

Add to `/etc/smtpd.conf`:

```
# Deliver to user's maildir
deliver to maildir "~/Maildir"

# Or system-wide maildir
deliver to maildir "/var/mail/%{rcpt.user}"
```

### User Maildir Setup

```bash
# Create maildir structure
mkdir -p ~/Maildir/{cur,new,tmp}
chmod 700 ~/Maildir
```

## Testing

### Quick Test

```bash
# Start in foreground
sudo ./pop3d -d

# Connect via SSL
openssl s_client -connect localhost:995 -quiet

# POP3 commands
USER username
PASS password
STAT
LIST
QUIT
```

## Code Style

- Indentation: 4 spaces
- Braces: K&R style (opening brace on same line)
- Line length: 80 characters recommended
- Comments: C-style /* */ for multi-line, // acceptable for single line

## Security Considerations

1. Always use SSL/TLS in production (`allow_plaintext = 0`)
2. Use strong certificates (Let's Encrypt recommended)
3. Monitor logs for brute force attempts
4. Enable fail2ban for additional protection
5. Run as non-root user (handled by systemd)

## Troubleshooting

- Check syslog/journald for errors
- Verify PAM configuration with `pamtester`
- Ensure proper maildir permissions (700)
- Test SSL with `openssl s_client`

## License

ISC License
