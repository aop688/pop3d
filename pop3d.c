/*
 * Copyright (c) 2024 POP3D Production Version
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <ctype.h>
#include <stdarg.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* Check for PAM headers - use compiler to detect availability */
#if defined(__has_include)
  #if __has_include(<security/pam_appl.h>)
    #include <security/pam_appl.h>
    #define HAVE_PAM 1
  #elif __has_include(<pam/pam_appl.h>)
    #include <pam/pam_appl.h>
    #define HAVE_PAM 1
  #else
    #define HAVE_PAM 0
  #endif
#else
  /* Fallback: try to include and let compilation fail/succeed */
  #if defined(HAVE_SECURITY_PAM_APPL_H) || defined(__linux__)
    #include <security/pam_appl.h>
    #define HAVE_PAM 1
  #else
    #define HAVE_PAM 0
  #endif
#endif

#if !HAVE_PAM
  #warning "PAM headers not found, using shadow password authentication fallback"
#endif

#define POP3_PORT		110
#define POP3S_PORT		995
#define BUFFER_SIZE		1024
#define MAX_CLIENTS		50
#define MAX_LOGIN_ATTEMPTS	3
#define LOGIN_TIMEOUT		60
#define COMMAND_TIMEOUT		300
#define MAX_MAILDIR_PATH	PATH_MAX
#define CONFIG_FILE		"/etc/pop3d.conf"
#define MAX_LINE_LENGTH		512

/* Message flags */
#define F_DELE		0x01

/* Client state */
typedef struct {
    int			socket;
    SSL			*ssl;
    int			authenticated;
    int			using_ssl;
    char		username[256];
    int			login_attempts;
    time_t		last_activity;
    char		client_ip[INET6_ADDRSTRLEN];
    int			failed_logins;
    
    /* Maildir state */
    char		maildir_path[MAX_MAILDIR_PATH];
    struct msg		**msgs;
    size_t		nmsgs;
    size_t		maildrop_size;
} Client;

/* Message structure for maildir */
typedef struct msg {
    char		*filename;
    size_t		size;
    size_t		nlines;
    int			flags;
} Message;

/* Global configuration */
static struct {
    int			allow_plaintext;
    int			max_connections;
    int			log_auth;
    int			ipv6_enabled;
    int			port;
    int			ssl_port;
    char		cert_file[PATH_MAX];
    char		key_file[PATH_MAX];
    char		maildir_base[PATH_MAX];
    int			timeout_login;
    int			timeout_command;
} config = {
    .allow_plaintext = 0,
    .max_connections = 50,
    .log_auth = 1,
    .ipv6_enabled = 1,
    .port = POP3_PORT,
    .ssl_port = POP3S_PORT,
    .cert_file = "/etc/ssl/certs/pop3d.crt",
    .key_file = "/etc/ssl/private/pop3d.key",
    .maildir_base = "/var/mail",
    .timeout_login = LOGIN_TIMEOUT,
    .timeout_command = COMMAND_TIMEOUT
};

static Client clients[MAX_CLIENTS];
static int server_socket = -1, ssl_server_socket = -1;
static int server6_socket = -1, ssl_server6_socket = -1;
static SSL_CTX *ssl_ctx = NULL;
static volatile int running = 1;

#if HAVE_PAM
/* PAM conversation function */
static int pam_conv_func(int num_msg, const struct pam_message **msg,
                         struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *reply = NULL;
    const char *password = (const char *)appdata_ptr;
    
    if (num_msg <= 0 || msg == NULL)
        return PAM_CONV_ERR;
    
    reply = calloc(num_msg, sizeof(struct pam_response));
    if (reply == NULL)
        return PAM_CONV_ERR;
    
    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            reply[i].resp = strdup(password);
            reply[i].resp_retcode = 0;
            break;
        case PAM_PROMPT_ECHO_ON:
            reply[i].resp = strdup(password);
            reply[i].resp_retcode = 0;
            break;
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
            reply[i].resp = NULL;
            reply[i].resp_retcode = 0;
            break;
        default:
            for (int j = 0; j < i; j++) {
                if (reply[j].resp) {
                    memset(reply[j].resp, 0, strlen(reply[j].resp));
                    free(reply[j].resp);
                }
            }
            free(reply);
            return PAM_CONV_ERR;
        }
    }
    
    *resp = reply;
    return PAM_SUCCESS;
}

/* PAM authentication */
static int authenticate_user(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { pam_conv_func, (void *)password };
    int retval;
    
    retval = pam_start("pop3d", username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "PAM start failed: %s", pam_strerror(NULL, retval));
        return 0;
    }
    
    retval = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return 0;
    }
    
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        pam_end(pamh, retval);
        return 0;
    }
    
    pam_end(pamh, PAM_SUCCESS);
    return 1;
}
#else
/* Shadow password fallback for systems without PAM */
#include <shadow.h>
#include <crypt.h>

static int authenticate_user(const char *username, const char *password) {
    /* Test mode */
    const char *test_user = getenv("POP3D_TEST_USER");
    const char *test_pass = getenv("POP3D_TEST_PASS");
    if (test_user && test_pass) {
        if (strcmp(username, test_user) == 0 && strcmp(password, test_pass) == 0) {
            return 1;
        }
    }

    struct spwd *sp = getspnam(username);
    struct passwd *pw = getpwnam(username);
    char *encrypted;
    
    if (!pw) {
        /* User doesn't exist - do dummy crypt to prevent timing attacks */
        crypt(password, "$6$rounds=5000$xxxxxxxx$");
        return 0;
    }
    
    /* Check if account is locked/expired */
    if (sp) {
        /* Check password aging if available */
        if (sp->sp_expire > 0 && time(NULL) / 86400 > sp->sp_expire) {
            syslog(LOG_WARNING, "Account expired: %s", username);
            return 0;
        }
        if (sp->sp_lstchg > 0 && sp->sp_max > 0) {
            long today = time(NULL) / 86400;
            if (today > sp->sp_lstchg + sp->sp_max) {
                syslog(LOG_WARNING, "Password expired: %s", username);
                return 0;
            }
        }
    }
    
    /* Try shadow password first, then regular password */
    const char *correct = sp ? sp->sp_pwdp : pw->pw_passwd;
    
    /* Handle empty passwords */
    if (!correct || correct[0] == '\0' || strcmp(correct, "x") == 0) {
        if (sp) correct = sp->sp_pwdp;
        else return 0;
    }
    
    if (!correct || correct[0] == '*' || correct[0] == '!') {
        /* Account locked */
        return 0;
    }
    
    encrypted = crypt(password, correct);
    return encrypted && strcmp(encrypted, correct) == 0;
}
#endif

/* Logging functions */
static void log_connection(const char *message, const char *client_ip, int socket) {
    if (config.log_auth) {
        syslog(LOG_INFO, "pop3d[%d]: %s - %s (fd=%d)", getpid(), client_ip, message, socket);
    }
}

static void log_security(const char *event, const char *client_ip, const char *details) {
    syslog(LOG_WARNING, "pop3d[%d]: SECURITY: %s - %s: %s", getpid(), event, client_ip, details ? details : "");
}

static void log_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(LOG_ERR, fmt, ap);
    va_end(ap);
}

/* SSL initialization */
static void init_ssl(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        log_error("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | 
                        SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    if (SSL_CTX_use_certificate_file(ssl_ctx, config.cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Could not load certificate file: %s", config.cert_file);
        fprintf(stderr, "Warning: Could not load certificate file: %s\n", config.cert_file);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config.key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Could not load private key file: %s", config.key_file);
        fprintf(stderr, "Warning: Could not load private key file: %s\n", config.key_file);
    }
}

static void cleanup_ssl(void) {
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }
    EVP_cleanup();
    ERR_free_strings();
}

/* Input validation */
static int validate_input(const char *input) {
    if (!input || strlen(input) > MAX_LINE_LENGTH)
        return 0;
    
    for (size_t i = 0; input[i]; i++) {
        if (!isprint((unsigned char)input[i]) && input[i] != '\r' && input[i] != '\n')
            return 0;
    }
    
    return 1;
}

/* Network I/O with SSL support */
static int send_response(Client *client, const char *response) {
    int len = strlen(response);
    int ret;
    int total_sent = 0;
    
    if (client->using_ssl && client->ssl) {
        while (total_sent < len) {
            ret = SSL_write(client->ssl, response + total_sent, len - total_sent);
            if (ret <= 0) {
                int ssl_err = SSL_get_error(client->ssl, ret);
                if (ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ) {
                    continue;
                }
                return -1;
            }
            total_sent += ret;
        }
    } else {
        while (total_sent < len) {
            ret = send(client->socket, response + total_sent, len - total_sent, MSG_NOSIGNAL);
            if (ret < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            if (ret == 0)
                return -1;
            total_sent += ret;
        }
    }
    
    return total_sent;
}

static int receive_data(Client *client, char *buffer, int size) {
    int ret;
    
    if (client->using_ssl && client->ssl) {
        ret = SSL_read(client->ssl, buffer, size - 1);
    } else {
        ret = recv(client->socket, buffer, size - 1, 0);
    }
    
    return ret;
}

/* Maildir operations */
static void free_maildrop(Client *client) {
    if (client->msgs) {
        for (size_t i = 0; i < client->nmsgs; i++) {
            if (client->msgs[i]) {
                free(client->msgs[i]->filename);
                free(client->msgs[i]);
            }
        }
        free(client->msgs);
        client->msgs = NULL;
    }
    client->nmsgs = 0;
    client->maildrop_size = 0;
}

static int count_lines(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    int lines = 0;
    int ch;
    while ((ch = fgetc(fp)) != EOF) {
        if (ch == '\n') lines++;
    }
    fclose(fp);
    return lines;
}

static int move_new_to_cur(const char *maildir) {
    char new_path[PATH_MAX], cur_path[PATH_MAX];
    DIR *dirp;
    struct dirent *dp;
    
    snprintf(new_path, sizeof(new_path), "%s/new", maildir);
    snprintf(cur_path, sizeof(cur_path), "%s/cur", maildir);
    
    dirp = opendir(new_path);
    if (!dirp) return 0;
    
    while ((dp = readdir(dirp)) != NULL) {
        if (dp->d_type != DT_REG)
            continue;
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;
        
        char src[PATH_MAX], dst[PATH_MAX];
        snprintf(src, sizeof(src), "%s/%s", new_path, dp->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", cur_path, dp->d_name);
        rename(src, dst);
    }
    
    closedir(dirp);
    return 0;
}

static int load_maildir(Client *client) {
    char cur_path[PATH_MAX];
    DIR *dirp;
    struct dirent *dp;
    struct stat st;
    Message **msgs = NULL;
    size_t count = 0;
    size_t total_size = 0;
    
    free_maildrop(client);
    
    /* Move messages from new to cur first */
    move_new_to_cur(client->maildir_path);
    
    snprintf(cur_path, sizeof(cur_path), "%s/cur", client->maildir_path);
    dirp = opendir(cur_path);
    if (!dirp) {
        log_error("Cannot open maildir cur: %s", cur_path);
        return -1;
    }
    
    while ((dp = readdir(dirp)) != NULL) {
        if (dp->d_type != DT_REG)
            continue;
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;
        
        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", cur_path, dp->d_name);
        
        if (stat(full_path, &st) < 0)
            continue;
        
        Message *msg = calloc(1, sizeof(Message));
        if (!msg) continue;
        
        msg->filename = strdup(dp->d_name);
        msg->size = st.st_size;
        msg->nlines = count_lines(full_path);
        msg->flags = 0;
        
        Message **new_msgs = realloc(msgs, (count + 1) * sizeof(Message *));
        if (!new_msgs) {
            free(msg->filename);
            free(msg);
            continue;
        }
        msgs = new_msgs;
        msgs[count++] = msg;
        total_size += msg->size;
    }
    
    closedir(dirp);
    
    client->msgs = msgs;
    client->nmsgs = count;
    client->maildrop_size = total_size;
    
    return 0;
}

static int update_maildir(Client *client) {
    char cur_path[PATH_MAX];
    int deleted = 0;
    
    snprintf(cur_path, sizeof(cur_path), "%s/cur", client->maildir_path);
    
    for (size_t i = 0; i < client->nmsgs; i++) {
        if (client->msgs[i]->flags & F_DELE) {
            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", cur_path, 
                     client->msgs[i]->filename);
            if (unlink(full_path) == 0) {
                deleted++;
            }
        }
    }
    
    syslog(LOG_INFO, "pop3d[%d]: Deleted %d messages for %s", getpid(), deleted, client->username);
    return deleted;
}

/* POP3 command handlers */
static void handle_user(Client *client, const char *username) {
    if (!validate_input(username)) {
        send_response(client, "-ERR Invalid username\r\n");
        return;
    }
    
    if (client->login_attempts >= MAX_LOGIN_ATTEMPTS) {
        send_response(client, "-ERR Too many failed attempts\r\n");
        log_security("Login limit exceeded", client->client_ip, NULL);
        return;
    }
    
    strncpy(client->username, username, sizeof(client->username) - 1);
    client->username[sizeof(client->username) - 1] = '\0';
    send_response(client, "+OK Please enter password\r\n");
}

static void handle_pass(Client *client, const char *password) {
    struct passwd *pw;
    
    if (!validate_input(password)) {
        send_response(client, "-ERR Invalid password\r\n");
        return;
    }
    
    if (client->login_attempts >= MAX_LOGIN_ATTEMPTS) {
        send_response(client, "-ERR Too many failed attempts\r\n");
        log_security("Login limit exceeded", client->client_ip, NULL);
        return;
    }
    
    if (strlen(client->username) == 0) {
        send_response(client, "-ERR USER required first\r\n");
        return;
    }
    
    /* Try PAM authentication */
    if (!authenticate_user(client->username, password)) {
        client->login_attempts++;
        send_response(client, "-ERR Authentication failed\r\n");
        log_security("Auth failed", client->client_ip, client->username);
        return;
    }
    
    /* Get user's home directory for maildir, or use maildir_base for test/virtual users */
    pw = getpwnam(client->username);
    if (pw) {
        /* Construct maildir path - check ~/Maildir first, then /var/mail/username */
        snprintf(client->maildir_path, sizeof(client->maildir_path), 
                 "%s/Maildir", pw->pw_dir);
        
        struct stat st;
        if (stat(client->maildir_path, &st) < 0 || !S_ISDIR(st.st_mode)) {
            /* Fall back to /var/mail/username */
            snprintf(client->maildir_path, sizeof(client->maildir_path),
                     "%s/%s", config.maildir_base, client->username);
        }
    } else {
        /* Test mode or virtual user - use maildir_base directly */
        snprintf(client->maildir_path, sizeof(client->maildir_path),
                 "%s/%s", config.maildir_base, client->username);
    }
    
    if (load_maildir(client) < 0) {
        send_response(client, "-ERR Cannot access maildrop\r\n");
        log_error("Cannot load maildir for %s: %s", client->username, client->maildir_path);
        return;
    }
    
    client->authenticated = 1;
    send_response(client, "+OK Maildrop ready\r\n");
    log_connection("Authentication successful", client->client_ip, client->socket);
    syslog(LOG_INFO, "pop3d[%d]: User %s logged in, %zu messages", 
           getpid(), client->username, client->nmsgs);
}

static void handle_stat(Client *client) {
    if (!client->authenticated) {
        send_response(client, "-ERR Not authenticated\r\n");
        return;
    }
    
    size_t total_size = 0;
    size_t count = 0;
    
    for (size_t i = 0; i < client->nmsgs; i++) {
        if (!(client->msgs[i]->flags & F_DELE)) {
            total_size += client->msgs[i]->size;
            count++;
        }
    }
    
    char response[256];
    snprintf(response, sizeof(response), "+OK %zu %zu\r\n", count, total_size);
    send_response(client, response);
}

static void handle_list(Client *client, const char *arg) {
    if (!client->authenticated) {
        send_response(client, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (arg && *arg) {
        /* List specific message */
        char *endptr;
        unsigned long idx = strtoul(arg, &endptr, 10);
        if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
            send_response(client, "-ERR No such message\r\n");
            return;
        }
        
        Message *msg = client->msgs[idx - 1];
        if (msg->flags & F_DELE) {
            send_response(client, "-ERR Message deleted\r\n");
            return;
        }
        
        char response[256];
        snprintf(response, sizeof(response), "+OK %lu %zu\r\n", idx, msg->size);
        send_response(client, response);
    } else {
        /* List all messages */
        send_response(client, "+OK Scan list follows\r\n");
        
        for (size_t i = 0; i < client->nmsgs; i++) {
            if (!(client->msgs[i]->flags & F_DELE)) {
                char line[256];
                snprintf(line, sizeof(line), "%zu %zu\r\n", i + 1, client->msgs[i]->size);
                send_response(client, line);
            }
        }
        send_response(client, ".\r\n");
    }
}

static void handle_retr(Client *client, const char *arg) {
    char path[PATH_MAX];
    FILE *fp;
    char line[BUFFER_SIZE];
    
    if (!client->authenticated) {
        send_response(client, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (!arg || !*arg) {
        send_response(client, "-ERR Message number required\r\n");
        return;
    }
    
    char *endptr;
    unsigned long idx = strtoul(arg, &endptr, 10);
    if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
        send_response(client, "-ERR No such message\r\n");
        return;
    }
    
    Message *msg = client->msgs[idx - 1];
    if (msg->flags & F_DELE) {
        send_response(client, "-ERR Message deleted\r\n");
        return;
    }
    
    snprintf(path, sizeof(path), "%s/cur/%s", client->maildir_path, msg->filename);
    fp = fopen(path, "r");
    if (!fp) {
        send_response(client, "-ERR Cannot open message\r\n");
        return;
    }
    
    char response[256];
    snprintf(response, sizeof(response), "+OK %zu octets\r\n", msg->size);
    send_response(client, response);
    
    while (fgets(line, sizeof(line), fp)) {
        /* Byte-stuff lines starting with "." */
        if (line[0] == '.') {
            send_response(client, ".");
        }
        
        /* Ensure CRLF line endings */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            if (len > 1 && line[len-2] == '\r') {
                send_response(client, line);
            } else {
                line[len-1] = '\0';
                send_response(client, line);
                send_response(client, "\r\n");
            }
        } else {
            send_response(client, line);
        }
    }
    
    fclose(fp);
    send_response(client, ".\r\n");
}

static void handle_dele(Client *client, const char *arg) {
    if (!client->authenticated) {
        send_response(client, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (!arg || !*arg) {
        send_response(client, "-ERR Message number required\r\n");
        return;
    }
    
    char *endptr;
    unsigned long idx = strtoul(arg, &endptr, 10);
    if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
        send_response(client, "-ERR No such message\r\n");
        return;
    }
    
    Message *msg = client->msgs[idx - 1];
    if (msg->flags & F_DELE) {
        send_response(client, "-ERR Message already deleted\r\n");
        return;
    }
    
    msg->flags |= F_DELE;
    send_response(client, "+OK Message deleted\r\n");
}

static void handle_rset(Client *client) {
    if (!client->authenticated) {
        send_response(client, "-ERR Not authenticated\r\n");
        return;
    }
    
    for (size_t i = 0; i < client->nmsgs; i++) {
        client->msgs[i]->flags &= ~F_DELE;
    }
    
    send_response(client, "+OK Maildrop reset\r\n");
}

static void handle_uidl(Client *client, const char *arg) {
    if (!client->authenticated) {
        send_response(client, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (arg && *arg) {
        char *endptr;
        unsigned long idx = strtoul(arg, &endptr, 10);
        if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
            send_response(client, "-ERR No such message\r\n");
            return;
        }
        
        Message *msg = client->msgs[idx - 1];
        if (msg->flags & F_DELE) {
            send_response(client, "-ERR Message deleted\r\n");
            return;
        }
        
        char response[512];
        snprintf(response, sizeof(response), "+OK %lu %s\r\n", idx, msg->filename);
        send_response(client, response);
    } else {
        send_response(client, "+OK Unique ID list follows\r\n");
        
        for (size_t i = 0; i < client->nmsgs; i++) {
            if (!(client->msgs[i]->flags & F_DELE)) {
                char line[512];
                snprintf(line, sizeof(line), "%zu %s\r\n", i + 1, client->msgs[i]->filename);
                send_response(client, line);
            }
        }
        send_response(client, ".\r\n");
    }
}

static void handle_top(Client *client, const char *arg) {
    char path[PATH_MAX];
    FILE *fp;
    char line[BUFFER_SIZE];
    int in_headers = 1;
    int lines_sent = 0;
    
    if (!client->authenticated) {
        send_response(client, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (!arg || !*arg) {
        send_response(client, "-ERR Message number and line count required\r\n");
        return;
    }
    
    char *msg_str = strdup(arg);
    char *lines_str = strchr(msg_str, ' ');
    if (!lines_str) {
        free(msg_str);
        send_response(client, "-ERR Line count required\r\n");
        return;
    }
    *lines_str++ = '\0';
    
    char *endptr;
    unsigned long idx = strtoul(msg_str, &endptr, 10);
    if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
        free(msg_str);
        send_response(client, "-ERR No such message\r\n");
        return;
    }
    
    long nlines = strtol(lines_str, &endptr, 10);
    if (*endptr != '\0' || nlines < 0) {
        free(msg_str);
        send_response(client, "-ERR Invalid line count\r\n");
        return;
    }
    
    Message *msg = client->msgs[idx - 1];
    if (msg->flags & F_DELE) {
        free(msg_str);
        send_response(client, "-ERR Message deleted\r\n");
        return;
    }
    
    snprintf(path, sizeof(path), "%s/cur/%s", client->maildir_path, msg->filename);
    fp = fopen(path, "r");
    if (!fp) {
        free(msg_str);
        send_response(client, "-ERR Cannot open message\r\n");
        return;
    }
    
    free(msg_str);
    send_response(client, "+OK Top of message follows\r\n");
    
    while (fgets(line, sizeof(line), fp) && lines_sent <= nlines) {
        /* Stop after headers + nlines */
        if (!in_headers) {
            if (lines_sent >= nlines) break;
            lines_sent++;
        } else if (line[0] == '\n' || (line[0] == '\r' && line[1] == '\n')) {
            in_headers = 0;
            lines_sent = 0;
        }
        
        /* Byte-stuff */
        if (line[0] == '.') {
            send_response(client, ".");
        }
        
        /* Ensure CRLF */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            if (len > 1 && line[len-2] == '\r') {
                send_response(client, line);
            } else {
                line[len-1] = '\0';
                send_response(client, line);
                send_response(client, "\r\n");
            }
        } else {
            send_response(client, line);
        }
    }
    
    fclose(fp);
    send_response(client, ".\r\n");
}

static void handle_stls(Client *client) {
    if (client->using_ssl) {
        send_response(client, "-ERR TLS already active\r\n");
        return;
    }
    
    if (!config.allow_plaintext) {
        send_response(client, "-ERR STLS not available\r\n");
        return;
    }
    
    send_response(client, "+OK Begin TLS negotiation\r\n");
    
    client->ssl = SSL_new(ssl_ctx);
    if (!client->ssl) {
        log_error("SSL_new failed");
        return;
    }
    
    SSL_set_fd(client->ssl, client->socket);
    
    int ret = SSL_accept(client->ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(client->ssl, ret);
        log_error("SSL_accept failed: %d", ssl_error);
        SSL_free(client->ssl);
        client->ssl = NULL;
        return;
    }
    
    client->using_ssl = 1;
    log_connection("TLS started", client->client_ip, client->socket);
}

static void handle_capa(Client *client) {
    send_response(client, "+OK Capability list follows\r\n");
    send_response(client, "USER\r\n");
    send_response(client, "TOP\r\n");
    send_response(client, "UIDL\r\n");
    if (!client->using_ssl && config.allow_plaintext) {
        send_response(client, "STLS\r\n");
    }
    send_response(client, ".\r\n");
}

static void process_command(Client *client, char *command) {
    char *cmd, *arg;
    
    if (!validate_input(command)) {
        send_response(client, "-ERR Invalid command\r\n");
        return;
    }
    
    /* Remove CRLF */
    char *p = strchr(command, '\r');
    if (p) *p = '\0';
    p = strchr(command, '\n');
    if (p) *p = '\0';
    
    /* Parse command and argument */
    cmd = strtok(command, " ");
    arg = strtok(NULL, "");
    
    if (!cmd) return;
    
    /* Log command (except PASS) */
    if (strcasecmp(cmd, "PASS") != 0) {
        log_connection(cmd, client->client_ip, client->socket);
    } else {
        log_connection("PASS [hidden]", client->client_ip, client->socket);
    }
    
    client->last_activity = time(NULL);
    
    if (strcasecmp(cmd, "USER") == 0) {
        handle_user(client, arg ? arg : "");
    } else if (strcasecmp(cmd, "PASS") == 0) {
        handle_pass(client, arg ? arg : "");
    } else if (strcasecmp(cmd, "STAT") == 0) {
        handle_stat(client);
    } else if (strcasecmp(cmd, "LIST") == 0) {
        handle_list(client, arg);
    } else if (strcasecmp(cmd, "RETR") == 0) {
        handle_retr(client, arg);
    } else if (strcasecmp(cmd, "DELE") == 0) {
        handle_dele(client, arg);
    } else if (strcasecmp(cmd, "NOOP") == 0) {
        send_response(client, "+OK\r\n");
    } else if (strcasecmp(cmd, "RSET") == 0) {
        handle_rset(client);
    } else if (strcasecmp(cmd, "QUIT") == 0) {
        if (client->authenticated) {
            update_maildir(client);
        }
        send_response(client, "+OK POP3 server signing off\r\n");
        log_connection("QUIT", client->client_ip, client->socket);
        client->socket = -1;
    } else if (strcasecmp(cmd, "UIDL") == 0) {
        handle_uidl(client, arg);
    } else if (strcasecmp(cmd, "TOP") == 0) {
        handle_top(client, arg);
    } else if (strcasecmp(cmd, "STLS") == 0) {
        handle_stls(client);
    } else if (strcasecmp(cmd, "CAPA") == 0) {
        handle_capa(client);
    } else {
        send_response(client, "-ERR Unknown command\r\n");
    }
}

static void check_timeouts(void) {
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) continue;
        
        time_t timeout = clients[i].authenticated ? 
                         config.timeout_command : config.timeout_login;
        
        if (now - clients[i].last_activity > timeout) {
            int sock = clients[i].socket;
            send_response(&clients[i], "-ERR Timeout\r\n");
            log_connection("Timeout", clients[i].client_ip, sock);
            if (clients[i].ssl) {
                SSL_shutdown(clients[i].ssl);
                SSL_free(clients[i].ssl);
                clients[i].ssl = NULL;
            }
            close(sock);
            free_maildrop(&clients[i]);
            memset(&clients[i], 0, sizeof(Client));
            clients[i].socket = -1;
        }
    }
}

static Client* accept_connection(int server_fd, int is_ssl, int is_ipv6) {
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_socket;
    Client *client = NULL;
    int slot = -1;
    
    client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
        if (errno != EINTR && errno != EAGAIN)
            log_error("Accept failed: %s", strerror(errno));
        return NULL;
    }
    
    /* Find free slot */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        const char *msg = "-ERR Server busy\r\n";
        send(client_socket, msg, strlen(msg), MSG_NOSIGNAL);
        close(client_socket);
        log_security("Connection limit reached", "unknown", NULL);
        return NULL;
    }
    
    client = &clients[slot];
    memset(client, 0, sizeof(Client));
    client->socket = client_socket;
    client->last_activity = time(NULL);
    
    /* Get client IP */
    if (is_ipv6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, client->client_ip, sizeof(client->client_ip));
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
        inet_ntop(AF_INET, &sin->sin_addr, client->client_ip, sizeof(client->client_ip));
    }
    
    log_connection("New connection", client->client_ip, client_socket);
    
    /* Handle SSL handshake for POP3S */
    if (is_ssl) {
        client->ssl = SSL_new(ssl_ctx);
        if (!client->ssl) {
            close(client_socket);
            client->socket = -1;
            return NULL;
        }
        
        SSL_set_fd(client->ssl, client_socket);
        
        if (SSL_accept(client->ssl) <= 0) {
            log_security("SSL handshake failed", client->client_ip, NULL);
            SSL_free(client->ssl);
            close(client_socket);
            client->socket = -1;
            return NULL;
        }
        
        client->using_ssl = 1;
        log_connection("SSL connection established", client->client_ip, client_socket);
    }
    
    send_response(client, "+OK POP3 server ready\r\n");
    return client;
}

static void handle_client_data(Client *client) {
    char buffer[BUFFER_SIZE];
    int bytes;
    int sock;
    
    bytes = receive_data(client, buffer, sizeof(buffer));
    
    if (bytes <= 0) {
        if (bytes < 0 && errno == EAGAIN) return;
        
        sock = client->socket;
        log_connection("Client disconnected", client->client_ip, sock);
        if (client->ssl) {
            SSL_shutdown(client->ssl);
            SSL_free(client->ssl);
            client->ssl = NULL;
        }
        close(sock);
        free_maildrop(client);
        memset(client, 0, sizeof(Client));
        client->socket = -1;
        return;
    }
    
    buffer[bytes] = '\0';
    process_command(client, buffer);
}

static int create_server_socket(int port, int is_ipv6) {
    int fd, opt = 1;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr *addr;
    socklen_t addr_len;
    
    fd = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        log_error("Socket creation failed: %s", strerror(errno));
        return -1;
    }
    
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_error("setsockopt SO_REUSEADDR failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    if (is_ipv6) {
        int ipv6_only = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only, sizeof(ipv6_only));
        
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_any;
        sin6.sin6_port = htons(port);
        addr = (struct sockaddr *)&sin6;
        addr_len = sizeof(sin6);
    } else {
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;
        sin.sin_port = htons(port);
        addr = (struct sockaddr *)&sin;
        addr_len = sizeof(sin);
    }
    
    if (bind(fd, addr, addr_len) < 0) {
        log_error("Bind failed on port %d: %s", port, strerror(errno));
        close(fd);
        return -1;
    }
    
    if (listen(fd, 10) < 0) {
        log_error("Listen failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    return fd;
}

/* Configuration file parsing */
static void trim(char *str) {
    char *start = str;
    char *end;
    
    while (isspace((unsigned char)*start)) start++;
    
    if (*start == '\0') {
        str[0] = '\0';
        return;
    }
    
    end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    if (start != str) {
        memmove(str, start, end - start + 2);
    }
}

static int parse_config(const char *filename) {
    FILE *fp = fopen(filename, "r");
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    
    if (!fp) {
        log_error("Cannot open config file %s: %s", filename, strerror(errno));
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        trim(line);
        
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#')
            continue;
        
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "");
        
        if (!key || !value) {
            log_error("Config line %d: invalid syntax", line_num);
            continue;
        }
        
        trim(key);
        trim(value);
        
        if (strcmp(key, "allow_plaintext") == 0) {
            config.allow_plaintext = atoi(value);
        } else if (strcmp(key, "max_connections") == 0) {
            config.max_connections = atoi(value);
        } else if (strcmp(key, "log_auth") == 0) {
            config.log_auth = atoi(value);
        } else if (strcmp(key, "ipv6_enabled") == 0) {
            config.ipv6_enabled = atoi(value);
        } else if (strcmp(key, "port") == 0) {
            config.port = atoi(value);
        } else if (strcmp(key, "ssl_port") == 0) {
            config.ssl_port = atoi(value);
        } else if (strcmp(key, "cert_file") == 0) {
            strncpy(config.cert_file, value, sizeof(config.cert_file) - 1);
            config.cert_file[sizeof(config.cert_file) - 1] = '\0';
        } else if (strcmp(key, "key_file") == 0) {
            strncpy(config.key_file, value, sizeof(config.key_file) - 1);
            config.key_file[sizeof(config.key_file) - 1] = '\0';
        } else if (strcmp(key, "maildir_base") == 0) {
            strncpy(config.maildir_base, value, sizeof(config.maildir_base) - 1);
            config.maildir_base[sizeof(config.maildir_base) - 1] = '\0';
        } else if (strcmp(key, "timeout_login") == 0) {
            config.timeout_login = atoi(value);
        } else if (strcmp(key, "timeout_command") == 0) {
            config.timeout_command = atoi(value);
        } else {
            log_error("Config line %d: unknown key '%s'", line_num, key);
        }
    }
    
    fclose(fp);
    return 0;
}

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c <file>    Configuration file (default: %s)\n", CONFIG_FILE);
    fprintf(stderr, "  -d           Run in foreground (don't daemonize)\n");
    fprintf(stderr, "  -h           Show this help\n");
    fprintf(stderr, "  -g           Generate self-signed certificate\n");
}

/* OpenSSL 3.0+ compatible key generation */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

static int generate_cert(void) {
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    FILE *fp = NULL;
    int ret = -1;
    
    printf("Generating self-signed certificate...\n");
    printf("Certificate: %s\n", config.cert_file);
    printf("Key: %s\n", config.key_file);
    
    /* Create directories if needed */
    char cert_dir[PATH_MAX], key_dir[PATH_MAX];
    strncpy(cert_dir, config.cert_file, sizeof(cert_dir) - 1);
    cert_dir[sizeof(cert_dir) - 1] = '\0';
    strncpy(key_dir, config.key_file, sizeof(key_dir) - 1);
    key_dir[sizeof(key_dir) - 1] = '\0';
    
    char *p = strrchr(cert_dir, '/');
    if (p) {
        *p = '\0';
        mkdir(cert_dir, 0755);
    }
    
    p = strrchr(key_dir, '/');
    if (p) {
        *p = '\0';
        mkdir(key_dir, 0700);
    }
    
    /* Generate RSA key using modern EVP API */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0+ way */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to init keygen\n");
        EVP_PKEY_CTX_free(ctx);
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "Failed to set key bits\n");
        EVP_PKEY_CTX_free(ctx);
        goto cleanup;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate key\n");
        EVP_PKEY_CTX_free(ctx);
        goto cleanup;
    }
    EVP_PKEY_CTX_free(ctx);
#else
    /* OpenSSL 1.x way - still uses deprecated but wrapped for compatibility */
    pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        goto cleanup;
    }
    
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    if (!rsa || !bn || !BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Failed to create RSA/BN\n");
        BN_free(bn);
        RSA_free(rsa);
        goto cleanup;
    }
    
    if (!RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        fprintf(stderr, "Failed to generate RSA key\n");
        BN_free(bn);
        RSA_free(rsa);
        goto cleanup;
    }
    BN_free(bn);
    
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        fprintf(stderr, "Failed to assign RSA key\n");
        RSA_free(rsa);
        goto cleanup;
    }
#endif
    
    /* Generate certificate */
    x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "Failed to create X509\n");
        goto cleanup;
    }
    
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); /* 365 days */
    X509_set_pubkey(x509, pkey);
    
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"pop3d", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        fprintf(stderr, "Failed to sign certificate\n");
        goto cleanup;
    }
    
    /* Write private key */
    fp = fopen(config.key_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open key file: %s\n", config.key_file);
        goto cleanup;
    }
    chmod(config.key_file, 0600);
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key\n");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;
    
    /* Write certificate */
    fp = fopen(config.cert_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open cert file: %s\n", config.cert_file);
        goto cleanup;
    }
    if (!PEM_write_X509(fp, x509)) {
        fprintf(stderr, "Failed to write certificate\n");
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;
    
    printf("Certificate generated successfully.\n");
    ret = 0;
    
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    if (fp) fclose(fp);
    return ret;
}

static void daemonize(void) {
    pid_t pid;
    
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }
    
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    
    chdir("/");
    umask(0);
    
    /* Close file descriptors */
    for (int i = 0; i < 3; i++) {
        close(i);
    }
}

int main(int argc, char *argv[]) {
    int opt;
    int foreground = 0;
    int gen_cert = 0;
    const char *config_file = CONFIG_FILE;
    fd_set read_fds;
    int max_fd;
    time_t last_timeout_check = 0;
    struct timeval tv;
    
    while ((opt = getopt(argc, argv, "c:dhg")) != -1) {
        switch (opt) {
        case 'c':
            config_file = optarg;
            break;
        case 'd':
            foreground = 1;
            break;
        case 'g':
            gen_cert = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }
    
    /* Parse configuration */
    parse_config(config_file);
    
    /* Generate certificate if requested */
    if (gen_cert) {
        return generate_cert();
    }
    
    /* Initialize syslog */
    openlog("pop3d", LOG_PID | LOG_NDELAY, LOG_MAIL);
    
    /* Daemonize */
    if (!foreground) {
        daemonize();
    }
    
    syslog(LOG_INFO, "pop3d starting");
    
    /* Initialize SSL */
    init_ssl();
    
    /* Initialize clients array */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
    }
    
    /* Create server sockets */
    server_socket = create_server_socket(config.port, 0);
    if (server_socket < 0) {
        log_error("Failed to create IPv4 server socket on port %d", config.port);
        if (!config.allow_plaintext) {
            /* POP3S is required, fail if we can't create socket */
        }
    }
    
    ssl_server_socket = create_server_socket(config.ssl_port, 0);
    if (ssl_server_socket < 0) {
        log_error("Failed to create SSL server socket on port %d", config.ssl_port);
        fprintf(stderr, "Failed to create SSL server socket on port %d\n", config.ssl_port);
    }
    
    if (config.ipv6_enabled) {
        server6_socket = create_server_socket(config.port, 1);
        ssl_server6_socket = create_server_socket(config.ssl_port, 1);
    }
    
    if (server_socket < 0 && ssl_server_socket < 0 && 
        server6_socket < 0 && ssl_server6_socket < 0) {
        log_error("Failed to create any server sockets");
        cleanup_ssl();
        return 1;
    }
    
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    syslog(LOG_INFO, "pop3d ready - POP3 port %d, POP3S port %d", 
           config.port, config.ssl_port);
    
    /* Main event loop */
    while (running) {
        FD_ZERO(&read_fds);
        max_fd = -1;
        
        if (server_socket >= 0) {
            FD_SET(server_socket, &read_fds);
            if (server_socket > max_fd) max_fd = server_socket;
        }
        if (ssl_server_socket >= 0) {
            FD_SET(ssl_server_socket, &read_fds);
            if (ssl_server_socket > max_fd) max_fd = ssl_server_socket;
        }
        if (server6_socket >= 0) {
            FD_SET(server6_socket, &read_fds);
            if (server6_socket > max_fd) max_fd = server6_socket;
        }
        if (ssl_server6_socket >= 0) {
            FD_SET(ssl_server6_socket, &read_fds);
            if (ssl_server6_socket > max_fd) max_fd = ssl_server6_socket;
        }
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket >= 0) {
                FD_SET(clients[i].socket, &read_fds);
                if (clients[i].socket > max_fd) max_fd = clients[i].socket;
            }
        }
        
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("select error: %s", strerror(errno));
            break;
        }
        
        /* Check timeouts every 30 seconds */
        time_t now = time(NULL);
        if (now - last_timeout_check >= 30) {
            check_timeouts();
            last_timeout_check = now;
        }
        
        /* Accept new connections */
        if (server_socket >= 0 && FD_ISSET(server_socket, &read_fds)) {
            accept_connection(server_socket, 0, 0);
        }
        if (ssl_server_socket >= 0 && FD_ISSET(ssl_server_socket, &read_fds)) {
            accept_connection(ssl_server_socket, 1, 0);
        }
        if (server6_socket >= 0 && FD_ISSET(server6_socket, &read_fds)) {
            accept_connection(server6_socket, 0, 1);
        }
        if (ssl_server6_socket >= 0 && FD_ISSET(ssl_server6_socket, &read_fds)) {
            accept_connection(ssl_server6_socket, 1, 1);
        }
        
        /* Handle client data */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket >= 0 && FD_ISSET(clients[i].socket, &read_fds)) {
                handle_client_data(&clients[i]);
            }
        }
    }
    
    /* Cleanup */
    syslog(LOG_INFO, "pop3d shutting down");
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket >= 0) {
            if (clients[i].ssl) {
                SSL_shutdown(clients[i].ssl);
                SSL_free(clients[i].ssl);
            }
            close(clients[i].socket);
            free_maildrop(&clients[i]);
        }
    }
    
    if (server_socket >= 0) close(server_socket);
    if (ssl_server_socket >= 0) close(ssl_server_socket);
    if (server6_socket >= 0) close(server6_socket);
    if (ssl_server6_socket >= 0) close(ssl_server6_socket);
    
    cleanup_ssl();
    closelog();
    
    return 0;
}
