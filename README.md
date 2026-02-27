# POP3D - Production POP3 Server

A production-ready POP3 server for Linux with PAM authentication, SSL/TLS support, and maildir storage. Designed for personal/small-scale mail servers using OpenSMTPD.

## Features

- **PAM Authentication**: Uses system authentication (Unix passwords, LDAP, etc.)
- **SSL/TLS Support**: POP3S (port 995) and STARTTLS (port 110)
- **Maildir Support**: Full maildir implementation with new/cur/tmp folders
- **IPv6 Support**: Dual-stack IPv4/IPv6 support
- **Standards Compliant**: RFC 1939 (POP3) compliant
- **Security**: No hardcoded credentials, privilege separation, input validation
- **Logging**: Comprehensive syslog logging

## Requirements

- Linux with PAM support
- OpenSSL development libraries
- PAM development libraries

### Debian/Ubuntu
```bash
sudo apt-get install build-essential libssl-dev libpam0g-dev
```

### CentOS/RHEL/Rocky Linux
```bash
sudo yum install gcc openssl-devel pam-devel
# or
sudo dnf install gcc openssl-devel pam-devel
```

### Arch Linux
```bash
sudo pacman -S base-devel openssl pam
```

## Building

```bash
make
sudo make install
```

This installs:
- Binary: `/usr/local/sbin/pop3d`
- Config: `/etc/pop3d.conf`
- PAM config: `/etc/pam.d/pop3d`
- Systemd service: `/etc/systemd/system/pop3d.service`

## Configuration

### 1. Generate SSL Certificate

```bash
sudo /usr/local/sbin/pop3d -g
```

Or use Let's Encrypt:
```bash
# If you have certbot certificates
sudo ln -s /etc/letsencrypt/live/mail.example.com/fullchain.pem /etc/ssl/certs/pop3d.crt
sudo ln -s /etc/letsencrypt/live/mail.example.com/privkey.pem /etc/ssl/private/pop3d.key
```

### 2. Edit Configuration

Edit `/etc/pop3d.conf`:

```ini
# Force SSL only (recommended for production)
allow_plaintext = 0

# Certificate paths
cert_file = /etc/ssl/certs/pop3d.crt
key_file = /etc/ssl/private/pop3d.key

# Mail storage location
maildir_base = /var/mail
```

### 3. Configure PAM (Optional)

The default PAM configuration uses system passwords. Edit `/etc/pam.d/pop3d` to customize:

```
# Use LDAP (requires libpam-ldap)
auth    required    pam_ldap.so
account required    pam_ldap.so

# Or use system auth (default)
auth    required    pam_unix.so nullok
account required    pam_unix.so
```

### 4. Start the Service

```bash
sudo systemctl enable --now pop3d
sudo systemctl status pop3d
```

## Integration with OpenSMTPD

### 1. OpenSMTPD Configuration

Add to `/etc/smtpd.conf`:

```
# Deliver to maildir
deliver to maildir "~/Maildir"

# Or for virtual users
deliver to maildir "/var/mail/%{rcpt.user}"
```

### 2. User Maildir Setup

Each user needs a maildir:

```bash
# Create maildir for user
sudo mkdir -p /var/mail/username/{cur,new,tmp}
sudo chown -R username:mail /var/mail/username
sudo chmod 700 /var/mail/username

# Or in user's home
sudo -u username mkdir -p ~/Maildir/{cur,new,tmp}
```

### 3. Procmail/Dovecot Alternative

If using procmail or other LDA:

```bash
# In .procmailrc
DEFAULT=$HOME/Maildir/
```

## Testing

### Test with OpenSSL

```bash
# Test POP3S (SSL)
openssl s_client -connect localhost:995 -quiet

# Test STARTTLS
openssl s_client -connect localhost:110 -starttls pop3 -quiet
```

Then type POP3 commands:
```
USER your_username
PASS your_password
STAT
LIST
RETR 1
QUIT
```

### Test with Telnet (plaintext only if enabled)

```bash
telnet localhost 110
```

### Test Authentication

```bash
# Test PAM directly
sudo pamtester pop3d your_username authenticate
```

## Command Line Options

```
Usage: pop3d [options]
  -c <file>    Configuration file (default: /etc/pop3d.conf)
  -d           Run in foreground (debug mode)
  -g           Generate self-signed certificate
  -h           Show help
```

## Logging

View logs:
```bash
# systemd journal
sudo journalctl -u pop3d -f

# or syslog
sudo tail -f /var/log/mail.log
```

## Security Recommendations

1. **Disable plaintext**: Set `allow_plaintext = 0` in `/etc/pop3d.conf`

2. **Firewall**: Allow only necessary ports
   ```bash
   sudo ufw allow 995/tcp   # POP3S
   sudo ufw deny 110/tcp    # Block plaintext
   ```

3. **Use strong SSL**: Consider using Let's Encrypt certificates

4. **Monitor logs**: Watch for brute force attempts
   ```bash
   sudo grep "SECURITY" /var/log/mail.log
   ```

5. **Fail2ban**: Add filter for pop3d
   ```ini
   # /etc/fail2ban/jail.local
   [pop3d]
   enabled = true
   port = 995
   filter = pop3d
   logpath = /var/log/mail.log
   maxretry = 5
   ```

## Troubleshooting

### Cannot authenticate
```bash
# Check PAM configuration
sudo pamtester pop3d username authenticate

# Check syslog for errors
sudo journalctl -u pop3d -n 50
```

### Permission denied on maildir
```bash
# Fix permissions
sudo chown -R username:mail /var/mail/username
sudo chmod 700 /var/mail/username
```

### SSL handshake failed
```bash
# Check certificate
openssl x509 -in /etc/ssl/certs/pop3d.crt -text -noout
openssl rsa -in /etc/ssl/private/pop3d.key -check

# Generate new certificate
sudo pop3d -g
```

### Port already in use
```bash
# Find process using port 995
sudo lsof -i :995
sudo ss -tlnp | grep 995
```

## Uninstall

```bash
sudo make uninstall
sudo systemctl daemon-reload
```

## License

ISC License - See source code header

## See Also

- RFC 1939 - Post Office Protocol - Version 3
- OpenSMTPD documentation: https://man.openbsd.org/smtpd.conf
- PAM configuration: `man pam.conf`
