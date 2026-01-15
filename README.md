I am no longer using this code, archived.

pop3d
=====

POP3 Daemon with POP3S, STARTTLS extensions. Supports maildir, mbox formats.
Presently builds and runs only on OpenBSD.

POP3D(8)
POP3D(8)
NAME
pop3d — Post Office Protocol (POP3) daemon.
SYNOPSIS
pop3d [−c certfile] [−d] [−k keyfile] [−p path] [−t type]
DESCRIPTION
The pop3d daemon implements Post Office Protocol (Version 3) as specified in RFC 1939 as well as POP3S and STARTTLS extensions.
pop3d binds to 110 (POP3), 995 (POP3S) ports and operates on local mailboxes on behalf of its remote users.
The options are as follows:

−c certfile
Specify the certificate file. Defaults to /etc/ssl/server.crt.
−d
Do not daemonize. If this option is specified, pop3d will run in foreground and log to stderr.
−k keyfile
Specify the key file. Defaults to /etc/ssl/private/server.key.
−p path
Path to the maildrop. Defaults to /var/mail/%u in case of mbox and ~/Maildir in case of maildir. pop3d expands '~' to user's home dir and '%u' to user's name if specified in the path.
−t type
Specify maildrop type. Options are mbox and maildir. Defaults to mbox.

FILES
~/Maildir
/var/mail/%u
User maildrops.
SEE ALSO
smtpd(8), ssl(8)
STANDARDS
J. Myers, M. Rose. Post Office Protocol — Version 3. RFC 1939, May 1996.
C. Newman. Using TLS with IMAP, POP3 and ACAP. RFC 2595, June 1999.
A. Melnikov, C. Newman, M. Yevstifeyev. draft-melnikov-pop3-over-tls-02. August 2011.
CAVEATS
POP3 authenticates using cleartext passwords on 110 (POP3) port.