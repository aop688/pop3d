/*
 * Copyright (c) 2024 SMTPD - SMTP Server (Refactored with mail_common)
 */

#include "mail_common.h"
#include <dirent.h>
#include <grp.h>
#include <sys/wait.h>

/* ============================================================================
 * SMTP specific constants
 * ============================================================================ */
#define SMTP_MAX_RCPT		100
#define SMTP_MAX_FAILED_RCPTS	5

/* ============================================================================
 * SMTP states
 * ============================================================================ */
typedef enum {
    STATE_CONNECTED,
    STATE_HELO,
    STATE_MAIL,
    STATE_RCPT,
    STATE_DATA,
    STATE_QUIT
} SmtpState;

/* ============================================================================
 * Recipient structure
 * ============================================================================ */
typedef struct Recipient {
    char address[256];
    char user[128];
    char domain[128];
    int is_local;
} Recipient;

/* ============================================================================
 * SMTP Client structure - extends ClientBase
 * ============================================================================ */
typedef struct SmtpClient {
    ClientBase		base;
    SmtpState		state;
    char		helo[256];
    char		mail_from[256];
    Recipient		recipients[SMTP_MAX_RCPT];
    int			nrcpt;
    int			failed_commands;
    int			data_fd;
    char		data_path[PATH_MAX];
    size_t		msg_size;
    int			auth_login_state;
} SmtpClient;

/* ============================================================================
 * Forward declarations
 * ============================================================================ */
static void smtp_client_init(void *client);
static int smtp_is_slot_free(void *client);
static void smtp_send_greeting(ClientBase *client);
static int smtp_process_data(void *client);
static int smtp_get_timeout(void *client);
static void smtp_handle_timeout(void *client);
static void smtp_cleanup(void *client);

static void reset_client(SmtpClient *client);
static int deliver_to_maildir(const char *user, int fd, const char *data_path);
static int get_maildir_path(const char *user, char *path, size_t path_size);
static int create_maildir(const char *path);
static int is_local_domain(const char *domain);

static void handle_ehlo(SmtpClient *client, const char *arg);
static void handle_helo(SmtpClient *client, const char *arg);
static void handle_mail(SmtpClient *client, const char *arg);
static void handle_rcpt(SmtpClient *client, const char *arg);
static void handle_data(SmtpClient *client);
static void handle_data_content(SmtpClient *client, const char *line);
static void handle_rset(SmtpClient *client);
static void handle_auth(SmtpClient *client, const char *arg);
static void handle_auth_plain(SmtpClient *client, const char *params);
static void handle_auth_login_user(SmtpClient *client, const char *line);
static void handle_auth_login_pass(SmtpClient *client, const char *line);
static void handle_starttls(SmtpClient *client);
static void handle_noop(SmtpClient *client);
static void handle_vrfy(SmtpClient *client, const char *arg);
static void handle_help(SmtpClient *client);
static void handle_quit(SmtpClient *client);
static void process_command(SmtpClient *client, char *line);

/* ============================================================================
 * Protocol handler
 * ============================================================================ */
static ProtocolHandler smtp_handler = {
    .send_greeting = smtp_send_greeting,
    .process_data = smtp_process_data,
    .get_timeout = smtp_get_timeout,
    .handle_timeout = smtp_handle_timeout,
    .cleanup_client = smtp_cleanup
};

/* ============================================================================
 * Client management callbacks
 * ============================================================================ */
static void smtp_client_init(void *client)
{
    SmtpClient *smtp = (SmtpClient *)client;
    memset(smtp, 0, sizeof(SmtpClient));
    smtp->base.socket = -1;
    smtp->data_fd = -1;
    smtp->state = STATE_CONNECTED;
}

static int smtp_is_slot_free(void *client)
{
    SmtpClient *smtp = (SmtpClient *)client;
    return smtp->base.socket == -1;
}

static void smtp_cleanup(void *client)
{
    SmtpClient *smtp = (SmtpClient *)client;
    reset_client(smtp);
}

static void smtp_send_greeting(ClientBase *client)
{
    char greeting[256];
    snprintf(greeting, sizeof(greeting), "220 %s ESMTP\r\n", g_config.hostname);
    send_response(client, greeting);
}

static int smtp_get_timeout(void *client)
{
    SmtpClient *smtp = (SmtpClient *)client;
    if (smtp->state == STATE_DATA) {
        return g_config.timeout_data;
    }
    return smtp->base.authenticated ? 
           g_config.timeout_command : g_config.timeout_login;
}

static void smtp_handle_timeout(void *client)
{
    SmtpClient *smtp = (SmtpClient *)client;
    send_response(&smtp->base, "421 4.4.2 Timeout\r\n");
}

/* ============================================================================
 * Data processing
 * ============================================================================ */
static int smtp_process_data(void *client)
{
    SmtpClient *smtp = (SmtpClient *)client;
    char buffer[BUFFER_SIZE];
    int bytes;
    
    bytes = receive_line(&smtp->base, buffer, sizeof(buffer));
    
    if (bytes <= 0) {
        return -1; /* Connection closed or error */
    }
    
    process_command(smtp, buffer);
    return (smtp->state == STATE_QUIT || smtp->base.socket == -1) ? -1 : 0;
}

/* ============================================================================
 * Utility functions
 * ============================================================================ */
static int is_local_domain(const char *domain)
{
    return strcmp(domain, g_config.hostname) == 0;
}

static int create_maildir(const char *path)
{
    char subdir[PATH_MAX];
    struct stat st;
    
    if (stat(path, &st) < 0) {
        if (mkdir(path, 0700) < 0)
            return -1;
    }
    
    snprintf(subdir, sizeof(subdir), "%s/cur", path);
    if (stat(subdir, &st) < 0) {
        if (mkdir(subdir, 0700) < 0)
            return -1;
    }
    
    snprintf(subdir, sizeof(subdir), "%s/new", path);
    if (stat(subdir, &st) < 0) {
        if (mkdir(subdir, 0700) < 0)
            return -1;
    }
    
    snprintf(subdir, sizeof(subdir), "%s/tmp", path);
    if (stat(subdir, &st) < 0) {
        if (mkdir(subdir, 0700) < 0)
            return -1;
    }
    
    return 0;
}

static int get_maildir_path(const char *user, char *path, size_t path_size)
{
    struct passwd *pw = getpwnam(user);
    struct stat st;
    
    if (pw) {
        snprintf(path, path_size, "%s/Maildir", pw->pw_dir);
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            return create_maildir(path);
        }
        
        snprintf(path, path_size, "%s/%s", g_config.maildir_base, user);
        return create_maildir(path);
    }
    
    snprintf(path, path_size, "%s/%s", g_config.maildir_base, user);
    return create_maildir(path);
}

static int deliver_to_maildir(const char *user, int fd, const char *data_path)
{
    char maildir[PATH_MAX];
    char new_path[PATH_MAX];
    char tmp_path[PATH_MAX];
    char dest_path[PATH_MAX];
    struct timeval tv;
    struct stat st;
    int src_fd, dst_fd;
    char buffer[BUFFER_SIZE];
    ssize_t n;
    
    (void)data_path;
    
    if (get_maildir_path(user, maildir, sizeof(maildir)) < 0) {
        log_error("Cannot create maildir for %s", user);
        return -1;
    }
    
    gettimeofday(&tv, NULL);
    pid_t pid = getpid();
    
    snprintf(new_path, sizeof(new_path), "%lu.%lu.%d.%s",
             (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec,
             (int)pid, g_config.hostname);
    
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp/%s", maildir, new_path);
    snprintf(dest_path, sizeof(dest_path), "%s/new/%s", maildir, new_path);
    
    src_fd = fd;
    if (lseek(src_fd, 0, SEEK_SET) < 0) {
        log_error("Cannot seek temp file: %s", strerror(errno));
        return -1;
    }
    
    dst_fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (dst_fd < 0) {
        log_error("Cannot create temp file %s: %s", tmp_path, strerror(errno));
        return -1;
    }
    
    while ((n = read(src_fd, buffer, sizeof(buffer))) > 0) {
        if (write(dst_fd, buffer, n) != n) {
            log_error("Write error to %s: %s", tmp_path, strerror(errno));
            close(dst_fd);
            unlink(tmp_path);
            return -1;
        }
    }
    
    if (fsync(dst_fd) < 0) {
        log_error("fsync error on %s: %s", tmp_path, strerror(errno));
        close(dst_fd);
        unlink(tmp_path);
        return -1;
    }
    
    close(dst_fd);
    
    if (rename(tmp_path, dest_path) < 0) {
        log_error("Cannot rename %s to %s: %s", tmp_path, dest_path, strerror(errno));
        unlink(tmp_path);
        return -1;
    }
    
    log_connection("Delivered message", user, 0);
    return 0;
}

/* ============================================================================
 * Client management
 * ============================================================================ */
static void reset_client(SmtpClient *client)
{
    client->state = STATE_HELO;
    client->helo[0] = '\0';
    client->mail_from[0] = '\0';
    client->nrcpt = 0;
    memset(client->recipients, 0, sizeof(client->recipients));
    client->auth_login_state = 0;
    
    if (client->data_fd >= 0) {
        close(client->data_fd);
        client->data_fd = -1;
    }
    
    if (client->data_path[0] && strlen(client->data_path) > 0) {
        unlink(client->data_path);
        client->data_path[0] = '\0';
    }
    
    client->msg_size = 0;
}

/* ============================================================================
 * SMTP command handlers
 * ============================================================================ */
static void handle_ehlo(SmtpClient *client, const char *arg)
{
    if (!validate_input(arg, MAX_LINE_LENGTH)) {
        send_response(&client->base, "501 Syntax error in parameters\r\n");
        return;
    }
    
    reset_client(client);
    strncpy(client->helo, arg, sizeof(client->helo) - 1);
    client->helo[sizeof(client->helo) - 1] = '\0';
    client->state = STATE_HELO;
    
    char response[512];
    snprintf(response, sizeof(response), "250-%s\r\n", g_config.hostname);
    send_response(&client->base, response);
    
    send_response(&client->base, "250-PIPELINING\r\n");
    send_response(&client->base, "250-SIZE ");
    char size_str[32];
    snprintf(size_str, sizeof(size_str), "%zu\r\n", g_config.max_msg_size);
    send_response(&client->base, size_str);
    
    if (!client->base.using_ssl && g_config.allow_plaintext) {
        send_response(&client->base, "250-STARTTLS\r\n");
    }
    
    if (!client->base.authenticated) {
        send_response(&client->base, "250-AUTH PLAIN LOGIN\r\n");
    }
    
    send_response(&client->base, "250-ENHANCEDSTATUSCODES\r\n");
    send_response(&client->base, "250 8BITMIME\r\n");
}

static void handle_helo(SmtpClient *client, const char *arg)
{
    if (!validate_input(arg, MAX_LINE_LENGTH)) {
        send_response(&client->base, "501 Syntax error in parameters\r\n");
        return;
    }
    
    reset_client(client);
    strncpy(client->helo, arg, sizeof(client->helo) - 1);
    client->helo[sizeof(client->helo) - 1] = '\0';
    client->state = STATE_HELO;
    
    char response[512];
    snprintf(response, sizeof(response), "250 %s\r\n", g_config.hostname);
    send_response(&client->base, response);
}

static void handle_mail(SmtpClient *client, const char *arg)
{
    if (client->state < STATE_HELO) {
        send_response(&client->base, "503 5.5.1 Send HELO/EHLO first\r\n");
        return;
    }
    
    if (!arg || strncasecmp(arg, "FROM:", 5) != 0) {
        send_response(&client->base, "501 5.5.4 Syntax error in parameters\r\n");
        return;
    }
    
    const char *from = arg + 5;
    while (*from && isspace((unsigned char)*from)) from++;
    
    if (!validate_input(from, MAX_LINE_LENGTH)) {
        send_response(&client->base, "501 5.1.7 Bad sender address syntax\r\n");
        return;
    }
    
    if (g_config.require_auth && !client->base.authenticated) {
        char user[128], domain[128];
        const char *addr = from;
        if (*addr == '<') addr++;
        
        char addr_copy[256];
        strncpy(addr_copy, addr, sizeof(addr_copy) - 1);
        addr_copy[sizeof(addr_copy) - 1] = '\0';
        
        char *gt = strchr(addr_copy, '>');
        if (gt) *gt = '\0';
        
        if (parse_email_address(addr_copy, user, sizeof(user),
                                domain, sizeof(domain)) == 0) {
            if (!is_local_domain(domain)) {
                send_response(&client->base,
                              "530 5.7.0 Authentication required\r\n");
                return;
            }
        } else {
            send_response(&client->base, "530 5.7.0 Authentication required\r\n");
            return;
        }
    }
    
    const char *size_param = strcasestr(arg, "SIZE=");
    if (size_param) {
        size_t size = strtoul(size_param + 5, NULL, 10);
        if (size > g_config.max_msg_size) {
            char response[256];
            snprintf(response, sizeof(response),
                     "552 5.3.4 Message size exceeds fixed limit of %zu\r\n",
                     g_config.max_msg_size);
            send_response(&client->base, response);
            return;
        }
    }
    
    strncpy(client->mail_from, from, sizeof(client->mail_from) - 1);
    client->mail_from[sizeof(client->mail_from) - 1] = '\0';
    client->state = STATE_MAIL;
    
    send_response(&client->base, "250 2.1.0 Ok\r\n");
}

static void handle_rcpt(SmtpClient *client, const char *arg)
{
    if (client->state < STATE_MAIL) {
        send_response(&client->base, "503 5.5.1 Need MAIL FROM first\r\n");
        return;
    }
    
    if (!arg || strncasecmp(arg, "TO:", 3) != 0) {
        send_response(&client->base, "501 5.5.4 Syntax error in parameters\r\n");
        return;
    }
    
    const char *to = arg + 3;
    while (*to && isspace((unsigned char)*to)) to++;
    
    if (!validate_input(to, MAX_LINE_LENGTH)) {
        send_response(&client->base, "501 5.1.3 Bad recipient address syntax\r\n");
        return;
    }
    
    if (client->nrcpt >= SMTP_MAX_RCPT) {
        send_response(&client->base, "452 4.5.3 Too many recipients\r\n");
        return;
    }
    
    char addr_copy[256];
    strncpy(addr_copy, to, sizeof(addr_copy) - 1);
    addr_copy[sizeof(addr_copy) - 1] = '\0';
    
    char *gt = strchr(addr_copy, '>');
    if (gt) *gt = '\0';
    
    const char *addr = addr_copy;
    if (*addr == '<') addr++;
    
    char user[128], domain[128];
    if (parse_email_address(addr, user, sizeof(user), domain, sizeof(domain)) < 0) {
        send_response(&client->base, "501 5.1.3 Bad recipient address syntax\r\n");
        return;
    }
    
    int is_local = is_local_domain(domain);
    
    if (!is_local && g_config.require_auth && !client->base.authenticated) {
        send_response(&client->base, "530 5.7.0 Authentication required\r\n");
        client->failed_commands++;
        return;
    }
    
    if (is_local && !is_local_user(user)) {
        send_response(&client->base, "550 5.1.1 User unknown\r\n");
        client->failed_commands++;
        return;
    }
    
    Recipient *rcpt = &client->recipients[client->nrcpt++];
    strncpy(rcpt->address, addr, sizeof(rcpt->address) - 1);
    strncpy(rcpt->user, user, sizeof(rcpt->user) - 1);
    strncpy(rcpt->domain, domain, sizeof(rcpt->domain) - 1);
    rcpt->is_local = is_local;
    
    client->state = STATE_RCPT;
    
    send_response(&client->base, "250 2.1.5 Ok\r\n");
}

static void handle_data(SmtpClient *client)
{
    if (client->state < STATE_RCPT) {
        send_response(&client->base, "503 5.5.1 Need RCPT TO first\r\n");
        return;
    }
    
    snprintf(client->data_path, sizeof(client->data_path),
             "/tmp/smtpd.XXXXXX");
    
    client->data_fd = mkstemp(client->data_path);
    if (client->data_fd < 0) {
        log_error("Cannot create temp file: %s", strerror(errno));
        send_response(&client->base,
                      "452 4.3.0 Insufficient system storage\r\n");
        return;
    }
    
    unlink(client->data_path);
    
    client->state = STATE_DATA;
    client->msg_size = 0;
    
    send_response(&client->base,
                  "354 Start mail input; end with <CRLF>.<CRLF>\r\n");
}

static void handle_data_content(SmtpClient *client, const char *line)
{
    if (strcmp(line, ".") == 0) {
        int delivered = 0;
        int failed = 0;
        
        if (lseek(client->data_fd, 0, SEEK_SET) < 0) {
            log_error("Cannot seek temp file: %s", strerror(errno));
            send_response(&client->base,
                          "451 4.3.0 Local error in processing\r\n");
            reset_client(client);
            return;
        }
        
        char final_path[PATH_MAX];
        snprintf(final_path, sizeof(final_path), "/tmp/smtpd.final.XXXXXX");
        int final_fd = mkstemp(final_path);
        if (final_fd < 0) {
            send_response(&client->base,
                          "451 4.3.0 Local error in processing\r\n");
            reset_client(client);
            return;
        }
        
        char received[1024];
        time_t now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%a, %d %b %Y %H:%M:%S %z",
                 tm_info);
        
        snprintf(received, sizeof(received),
                 "Received: from %s (%s)\r\n\tby %s with SMTP; %s\r\n",
                 client->helo, client->base.client_ip,
                 g_config.hostname, time_str);
        write(final_fd, received, strlen(received));
        
        char buffer[BUFFER_SIZE];
        ssize_t n;
        lseek(client->data_fd, 0, SEEK_SET);
        while ((n = read(client->data_fd, buffer, sizeof(buffer))) > 0) {
            write(final_fd, buffer, n);
        }
        
        close(client->data_fd);
        client->data_fd = -1;
        
        for (int i = 0; i < client->nrcpt; i++) {
            Recipient *rcpt = &client->recipients[i];
            
            if (rcpt->is_local) {
                if (deliver_to_maildir(rcpt->user, final_fd, final_path) == 0) {
                    delivered++;
                } else {
                    failed++;
                }
            } else {
                log_connection("Would relay to remote", rcpt->address,
                               client->base.socket);
                delivered++;
            }
        }
        
        close(final_fd);
        unlink(final_path);
        
        if (failed > 0 && delivered == 0) {
            send_response(&client->base,
                          "451 4.3.0 Unable to process message\r\n");
        } else {
            send_response(&client->base, "250 2.0.0 Ok: queued\r\n");
        }
        
        reset_client(client);
        return;
    }
    
    const char *data = line;
    if (strncmp(line, "..", 2) == 0) {
        data = line + 1;
    }
    
    size_t len = strlen(data);
    if (write(client->data_fd, data, len) != (ssize_t)len ||
        write(client->data_fd, "\r\n", 2) != 2) {
        log_error("Write error: %s", strerror(errno));
        send_response(&client->base,
                      "451 4.3.0 Error writing message\r\n");
        reset_client(client);
        return;
    }
    
    client->msg_size += len + 2;
    
    if (client->msg_size > g_config.max_msg_size) {
        send_response(&client->base,
                      "552 5.3.4 Message size exceeds fixed limit\r\n");
        reset_client(client);
        return;
    }
}

static void handle_rset(SmtpClient *client)
{
    reset_client(client);
    client->state = STATE_HELO;
    send_response(&client->base, "250 2.0.0 Ok\r\n");
}

static void handle_auth_plain(SmtpClient *client, const char *params)
{
    char decoded[256];
    char *username = NULL;
    char *password = NULL;
    
    if (params) {
        int len = EVP_DecodeBlock((unsigned char *)decoded,
                                  (unsigned char *)params, strlen(params));
        if (len > 0) {
            decoded[len] = '\0';
            char *p = decoded;
            while (*p) p++;
            p++;
            username = p;
            while (*p) p++;
            p++;
            password = p;
        }
    }
    
    if (username && password) {
        if (authenticate_user(username, password, g_ctx.service_name)) {
            client->base.authenticated = 1;
            strncpy(client->base.username, username,
                    sizeof(client->base.username) - 1);
            send_response(&client->base,
                          "235 2.7.0 Authentication successful\r\n");
            log_connection("AUTH PLAIN success",
                           client->base.client_ip, client->base.socket);
        } else {
            send_response(&client->base,
                          "535 5.7.8 Authentication credentials invalid\r\n");
            log_security("AUTH PLAIN failed",
                         client->base.client_ip, username);
        }
    } else {
        send_response(&client->base,
                      "501 5.5.4 Syntax error in parameters\r\n");
    }
}

static void handle_auth(SmtpClient *client, const char *arg)
{
    if (client->base.using_ssl == 0 && g_config.allow_plaintext == 0) {
        send_response(&client->base, "538 5.7.11 Encryption required for "
                      "requested authentication mechanism\r\n");
        return;
    }
    
    if (!arg) {
        send_response(&client->base, "501 5.5.4 Syntax error in parameters\r\n");
        return;
    }
    
    char *mech = strdup(arg);
    char *params = strchr(mech, ' ');
    if (params) {
        *params = '\0';
        params++;
    }
    
    if (strcasecmp(mech, "PLAIN") == 0) {
        handle_auth_plain(client, params);
    } else if (strcasecmp(mech, "LOGIN") == 0) {
        send_response(&client->base, "334 VXNlcm5hbWU6\r\n");
        free(mech);
        return;
    } else {
        send_response(&client->base,
                      "504 5.5.4 Unrecognized authentication type\r\n");
    }
    
    free(mech);
}

static void handle_auth_login_user(SmtpClient *client, const char *line)
{
    char decoded[256];
    int len = EVP_DecodeBlock((unsigned char *)decoded,
                              (unsigned char *)line, strlen(line));
    if (len > 0) {
        decoded[len] = '\0';
        strncpy(client->base.username, decoded,
                sizeof(client->base.username) - 1);
        client->base.username[sizeof(client->base.username) - 1] = '\0';
        send_response(&client->base, "334 UGFzc3dvcmQ6\r\n");
    } else {
        send_response(&client->base,
                      "501 5.5.4 Syntax error in parameters\r\n");
    }
}

static void handle_auth_login_pass(SmtpClient *client, const char *line)
{
    char decoded[256];
    int len = EVP_DecodeBlock((unsigned char *)decoded,
                              (unsigned char *)line, strlen(line));
    if (len > 0) {
        decoded[len] = '\0';
        if (authenticate_user(client->base.username, decoded,
                              g_ctx.service_name)) {
            client->base.authenticated = 1;
            send_response(&client->base,
                          "235 2.7.0 Authentication successful\r\n");
            log_connection("AUTH LOGIN success",
                           client->base.client_ip, client->base.socket);
        } else {
            send_response(&client->base,
                          "535 5.7.8 Authentication credentials invalid\r\n");
            log_security("AUTH LOGIN failed",
                         client->base.client_ip, client->base.username);
        }
    } else {
        send_response(&client->base,
                      "501 5.5.4 Syntax error in parameters\r\n");
    }
}

static void handle_starttls(SmtpClient *client)
{
    if (client->base.using_ssl) {
        send_response(&client->base, "454 4.7.0 TLS already active\r\n");
        return;
    }
    
    if (!g_config.allow_plaintext) {
        send_response(&client->base,
                      "454 4.7.0 STARTTLS not available\r\n");
        return;
    }
    
    send_response(&client->base, "220 2.0.0 Ready to start TLS\r\n");
    
    client->base.ssl = SSL_new(g_ctx.ssl_ctx);
    if (!client->base.ssl) {
        log_error("SSL_new failed");
        return;
    }
    
    SSL_set_fd(client->base.ssl, client->base.socket);
    
    int ret = SSL_accept(client->base.ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(client->base.ssl, ret);
        log_error("SSL_accept failed: %d", ssl_error);
        SSL_free(client->base.ssl);
        client->base.ssl = NULL;
        return;
    }
    
    client->base.using_ssl = 1;
    client->base.authenticated = 0;
    client->state = STATE_CONNECTED;
    
    log_connection("TLS started", client->base.client_ip, client->base.socket);
}

static void handle_noop(SmtpClient *client)
{
    send_response(&client->base, "250 2.0.0 Ok\r\n");
}

static void handle_vrfy(SmtpClient *client, const char *arg)
{
    (void)arg;
    send_response(&client->base, "252 2.5.2 Cannot VRFY user, but will "
                  "accept message and attempt delivery\r\n");
}

static void handle_help(SmtpClient *client)
{
    send_response(&client->base,
                  "214-This server supports the following commands:\r\n");
    send_response(&client->base, "214 HELO EHLO MAIL RCPT DATA RSET VRFY "
                  "HELP QUIT AUTH STARTTLS\r\n");
}

static void handle_quit(SmtpClient *client)
{
    send_response(&client->base, "221 2.0.0 Bye\r\n");
    client->state = STATE_QUIT;
}

static void process_command(SmtpClient *client, char *line)
{
    char *cmd;
    char *arg;
    
    if (!validate_input(line, MAX_LINE_LENGTH)) {
        send_response(&client->base,
                      "500 5.5.2 Syntax error, command unrecognized\r\n");
        return;
    }
    
    str_trim(line);
    
    if (strlen(line) == 0) {
        if (client->state == STATE_DATA) {
            handle_data_content(client, "");
        }
        return;
    }
    
    if (client->auth_login_state == 1) {
        client->auth_login_state = 2;
        handle_auth_login_user(client, line);
        return;
    } else if (client->auth_login_state == 2) {
        client->auth_login_state = 0;
        handle_auth_login_pass(client, line);
        return;
    }
    
    if (client->state == STATE_DATA) {
        handle_data_content(client, line);
        return;
    }
    
    cmd = strtok(line, " ");
    arg = strtok(NULL, "");
    
    if (!cmd) {
        send_response(&client->base, "500 5.5.2 Syntax error\r\n");
        return;
    }
    
    client->base.last_activity = time(NULL);
    
    if (strncasecmp(cmd, "AUTH", 4) == 0) {
        log_connection("AUTH", client->base.client_ip, client->base.socket);
    } else if (strncasecmp(cmd, "PASS", 4) == 0) {
        log_connection("PASS [hidden]",
                       client->base.client_ip, client->base.socket);
    } else {
        log_connection(cmd, client->base.client_ip, client->base.socket);
    }
    
    if (strncasecmp(cmd, "AUTH", 4) == 0 && arg &&
        strncasecmp(arg, "LOGIN", 5) == 0) {
        client->auth_login_state = 1;
    }
    
    if (strcasecmp(cmd, "EHLO") == 0) {
        client->auth_login_state = 0;
        handle_ehlo(client, arg ? arg : "");
    } else if (strcasecmp(cmd, "HELO") == 0) {
        client->auth_login_state = 0;
        handle_helo(client, arg ? arg : "");
    } else if (strcasecmp(cmd, "MAIL") == 0) {
        client->auth_login_state = 0;
        handle_mail(client, arg);
    } else if (strcasecmp(cmd, "RCPT") == 0) {
        client->auth_login_state = 0;
        handle_rcpt(client, arg);
    } else if (strcasecmp(cmd, "DATA") == 0) {
        client->auth_login_state = 0;
        handle_data(client);
    } else if (strcasecmp(cmd, "RSET") == 0) {
        client->auth_login_state = 0;
        handle_rset(client);
    } else if (strcasecmp(cmd, "AUTH") == 0) {
        handle_auth(client, arg);
    } else if (strcasecmp(cmd, "STARTTLS") == 0) {
        client->auth_login_state = 0;
        handle_starttls(client);
    } else if (strcasecmp(cmd, "NOOP") == 0) {
        client->auth_login_state = 0;
        handle_noop(client);
    } else if (strcasecmp(cmd, "VRFY") == 0) {
        client->auth_login_state = 0;
        handle_vrfy(client, arg);
    } else if (strcasecmp(cmd, "HELP") == 0) {
        client->auth_login_state = 0;
        handle_help(client);
    } else if (strcasecmp(cmd, "QUIT") == 0) {
        client->auth_login_state = 0;
        handle_quit(client);
    } else {
        client->auth_login_state = 0;
        send_response(&client->base,
                      "500 5.5.2 Syntax error, command unrecognized\r\n");
        client->failed_commands++;
    }
}

/* ============================================================================
 * Main entry point
 * ============================================================================ */
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c <file>    Configuration file (default: %s)\n",
            CONFIG_FILE);
    fprintf(stderr, "  -d           Run in foreground (don't daemonize)\n");
    fprintf(stderr, "  -h           Show this help\n");
    fprintf(stderr, "  -g           Generate self-signed certificate\n");
}

int main(int argc, char *argv[])
{
    int opt;
    int foreground = 0;
    int gen_cert = 0;
    const char *config_file = CONFIG_FILE;
    MailServer server;
    ClientPool *pool;
    
    /* Set service-specific context */
    g_ctx.service_name = "smtpd";
    g_ctx.protocol_name = "SMTP";
    
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
    
    parse_config(config_file);
    
    if (gen_cert) {
        return generate_self_signed_cert(g_config.cert_file,
                                          g_config.key_file, "smtpd");
    }
    
    if (!g_config.smtp_enabled) {
        fprintf(stderr, "SMTP is disabled in configuration\n");
        return 0;
    }
    
    openlog("smtpd", LOG_PID | LOG_NDELAY, LOG_MAIL);
    
    if (!foreground) {
        daemonize();
    }
    
    syslog(LOG_INFO, "smtpd starting");
    
    if (init_ssl(g_config.cert_file, g_config.key_file) < 0) {
        log_error("SSL initialization failed");
        return 1;
    }
    
    /* Create client pool */
    pool = pool_create(sizeof(SmtpClient), MAX_CLIENTS,
                       smtp_is_slot_free, smtp_client_init);
    if (!pool) {
        log_error("Failed to create client pool");
        cleanup_ssl();
        return 1;
    }
    
    /* Initialize server */
    server_init(&server, pool, &smtp_handler);
    
    /* Add server sockets */
    ss_add_socket(&server.ss_set, g_config.smtp_port, 0, 0, "SMTP");
    ss_add_socket(&server.ss_set, g_config.smtps_port, 0, 1, "SMTPS");
    ss_add_socket(&server.ss_set, g_config.submission_port, 0, 0, "Submission");
    if (g_config.ipv6_enabled) {
        ss_add_socket(&server.ss_set, g_config.smtp_port, 1, 0, "SMTP-IPv6");
        ss_add_socket(&server.ss_set, g_config.smtps_port, 1, 1, "SMTPS-IPv6");
        ss_add_socket(&server.ss_set, g_config.submission_port, 1, 0, "Submission-IPv6");
    }
    
    if (server.ss_set.count == 0) {
        log_error("Failed to create any server sockets");
        pool_destroy(pool);
        cleanup_ssl();
        return 1;
    }
    
    setup_signal_handlers();
    
    syslog(LOG_INFO, "smtpd ready - SMTP port %d, Submission port %d, "
           "SMTPS port %d",
           g_config.smtp_port, g_config.submission_port, g_config.smtps_port);
    
    /* Run server */
    server_run(&server);
    
    syslog(LOG_INFO, "smtpd shutting down");
    
    server_shutdown(&server);
    pool_destroy(pool);
    cleanup_ssl();
    closelog();
    
    return 0;
}
