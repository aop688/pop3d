/*
 * Copyright (c) 2024 POP3D - POP3 Server (Refactored with mail_common)
 */

#include "mail_common.h"
#include <dirent.h>
#include <grp.h>

/* ============================================================================
 * POP3 specific constants
 * ============================================================================ */
#define POP3_MAX_LOGIN_ATTEMPTS	3
#define POP3_MAX_MAILDIR_PATH	PATH_MAX

/* Message flags */
#define F_DELE			0x01

/* ============================================================================
 * Message structure for maildir
 * ============================================================================ */
typedef struct Message {
    char		*filename;
    size_t		size;
    size_t		nlines;
    int			flags;
} Message;

/* ============================================================================
 * POP3 Client structure - extends ClientBase
 * ============================================================================ */
typedef struct Pop3Client {
    ClientBase		base;
    int			login_attempts;
    char		maildir_path[POP3_MAX_MAILDIR_PATH];
    Message		**msgs;
    size_t		nmsgs;
    size_t		maildrop_size;
} Pop3Client;

/* ============================================================================
 * Forward declarations
 * ============================================================================ */
static void pop3_client_init(void *client);
static int pop3_is_slot_free(void *client);
static void pop3_send_greeting(ClientBase *client);
static int pop3_process_data(void *client);
static int pop3_get_timeout(void *client);
static void pop3_handle_timeout(void *client);
static void pop3_cleanup(void *client);

static void free_maildrop(Pop3Client *client);
static int load_maildir(Pop3Client *client);
static int update_maildir(Pop3Client *client);

static void handle_user(Pop3Client *client, const char *username);
static void handle_pass(Pop3Client *client, const char *password);
static void handle_stat(Pop3Client *client);
static void handle_list(Pop3Client *client, const char *arg);
static void handle_retr(Pop3Client *client, const char *arg);
static void handle_dele(Pop3Client *client, const char *arg);
static void handle_rset(Pop3Client *client);
static void handle_uidl(Pop3Client *client, const char *arg);
static void handle_top(Pop3Client *client, const char *arg);
static void handle_stls(Pop3Client *client);
static void handle_capa(Pop3Client *client);
static void process_command(Pop3Client *client, char *command);

/* ============================================================================
 * Protocol handler
 * ============================================================================ */
static ProtocolHandler pop3_handler = {
    .send_greeting = pop3_send_greeting,
    .process_data = pop3_process_data,
    .get_timeout = pop3_get_timeout,
    .handle_timeout = pop3_handle_timeout,
    .cleanup_client = pop3_cleanup
};

/* ============================================================================
 * Client management callbacks
 * ============================================================================ */
static void pop3_client_init(void *client)
{
    Pop3Client *pop3 = (Pop3Client *)client;
    memset(pop3, 0, sizeof(Pop3Client));
    pop3->base.socket = -1;
}

static int pop3_is_slot_free(void *client)
{
    Pop3Client *pop3 = (Pop3Client *)client;
    return pop3->base.socket == -1;
}

static void pop3_cleanup(void *client)
{
    Pop3Client *pop3 = (Pop3Client *)client;
    free_maildrop(pop3);
}

static void pop3_send_greeting(ClientBase *client)
{
    send_response(client, "+OK POP3 server ready\r\n");
}

static int pop3_get_timeout(void *client)
{
    Pop3Client *pop3 = (Pop3Client *)client;
    return pop3->base.authenticated ? 
           g_config.timeout_command : g_config.timeout_login;
}

static void pop3_handle_timeout(void *client)
{
    Pop3Client *pop3 = (Pop3Client *)client;
    send_response(&pop3->base, "-ERR Timeout\r\n");
}

/* ============================================================================
 * Data processing
 * ============================================================================ */
static int pop3_process_data(void *client)
{
    Pop3Client *pop3 = (Pop3Client *)client;
    char buffer[BUFFER_SIZE];
    int bytes;
    
    /* POP3 is a line-based protocol, must use receive_line */
    bytes = receive_line(&pop3->base, buffer, sizeof(buffer));
    
    if (bytes <= 0) {
        return -1; /* Connection closed or error */
    }
    
    process_command(pop3, buffer);
    /* QUIT command sets socket to -1 to signal disconnection */
    return (pop3->base.socket == -1) ? -1 : 0;
}

/* ============================================================================
 * Maildir operations
 * ============================================================================ */
static int count_lines(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    int lines = 0;
    char buffer[4096];
    size_t n;
    
    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        for (size_t i = 0; i < n; i++) {
            if (buffer[i] == '\n') lines++;
        }
    }
    
    fclose(fp);
    return lines;
}

/* Safe string copy helper */
static void safe_strcpy(char *dest, size_t dest_size, const char *src)
{
    if (dest_size == 0) return;
    if (src) {
        size_t len = strlen(src);
        if (len >= dest_size) len = dest_size - 1;
        memcpy(dest, src, len);
        dest[len] = '\0';
    } else {
        dest[0] = '\0';
    }
}

static int move_new_to_cur(const char *maildir)
{
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

static void free_maildrop(Pop3Client *client)
{
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

static int load_maildir(Pop3Client *client)
{
    char cur_path[PATH_MAX];
    DIR *dirp;
    struct dirent *dp;
    struct stat st;
    Message **msgs = NULL;
    Message **new_msgs = NULL;
    size_t count = 0;
    size_t total_size = 0;
    size_t capacity = 0;
    
    free_maildrop(client);
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
        
        /* Grow array if needed */
        if (count >= capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 16;
            new_msgs = realloc(msgs, new_capacity * sizeof(Message *));
            if (!new_msgs) {
                log_error("Failed to allocate memory for message list");
                continue;
            }
            msgs = new_msgs;
            capacity = new_capacity;
        }
        
        Message *msg = calloc(1, sizeof(Message));
        if (!msg) continue;
        
        msg->filename = strdup(dp->d_name);
        if (!msg->filename) {
            free(msg);
            continue;
        }
        msg->size = st.st_size;
        msg->nlines = count_lines(full_path);
        msg->flags = 0;
        
        msgs[count++] = msg;
        total_size += msg->size;
    }
    
    closedir(dirp);
    
    client->msgs = msgs;
    client->nmsgs = count;
    client->maildrop_size = total_size;
    
    return 0;
}

static int update_maildir(Pop3Client *client)
{
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
    
    syslog(LOG_INFO, "pop3d[%d]: Deleted %d messages for %s",
           getpid(), deleted, client->base.username);
    return deleted;
}

/* ============================================================================
 * POP3 command handlers
 * ============================================================================ */
static void handle_user(Pop3Client *client, const char *username)
{
    if (!validate_input(username, MAX_LINE_LENGTH)) {
        send_response(&client->base, "-ERR Invalid username\r\n");
        return;
    }
    
    if (client->login_attempts >= POP3_MAX_LOGIN_ATTEMPTS) {
        send_response(&client->base, "-ERR Too many failed attempts\r\n");
        log_security("Login limit exceeded", client->base.client_ip, NULL);
        return;
    }
    
    safe_strcpy(client->base.username, sizeof(client->base.username), username);
    send_response(&client->base, "+OK Please enter password\r\n");
}

static void handle_pass(Pop3Client *client, const char *password)
{
    struct passwd *pw;
    
    if (!validate_input(password, MAX_LINE_LENGTH)) {
        send_response(&client->base, "-ERR Invalid password\r\n");
        return;
    }
    
    if (client->login_attempts >= POP3_MAX_LOGIN_ATTEMPTS) {
        send_response(&client->base, "-ERR Too many failed attempts\r\n");
        log_security("Login limit exceeded", client->base.client_ip, NULL);
        return;
    }
    
    if (strlen(client->base.username) == 0) {
        send_response(&client->base, "-ERR USER required first\r\n");
        return;
    }
    
    if (!authenticate_user(client->base.username, password, g_ctx.service_name)) {
        client->login_attempts++;
        send_response(&client->base, "-ERR Authentication failed\r\n");
        log_security("Auth failed", client->base.client_ip, client->base.username);
        return;
    }
    
    /* Get user's maildir path */
    pw = getpwnam(client->base.username);
    if (pw) {
        snprintf(client->maildir_path, sizeof(client->maildir_path),
                 "%s/Maildir", pw->pw_dir);
        
        struct stat st;
        if (stat(client->maildir_path, &st) < 0 || !S_ISDIR(st.st_mode)) {
            int n = snprintf(client->maildir_path, sizeof(client->maildir_path),
                     "%s/%s", g_config.maildir_base, client->base.username);
            if (n < 0 || (size_t)n >= sizeof(client->maildir_path)) {
                send_response(&client->base, "-ERR Maildir path too long\r\n");
                return;
            }
        }
    } else {
        int n = snprintf(client->maildir_path, sizeof(client->maildir_path),
                 "%s/%s", g_config.maildir_base, client->base.username);
        if (n < 0 || (size_t)n >= sizeof(client->maildir_path)) {
            send_response(&client->base, "-ERR Maildir path too long\r\n");
            return;
        }
    }
    
    if (load_maildir(client) < 0) {
        send_response(&client->base, "-ERR Cannot access maildrop\r\n");
        log_error("Cannot load maildir for %s: %s",
                  client->base.username, client->maildir_path);
        return;
    }
    
    client->base.authenticated = 1;
    send_response(&client->base, "+OK Maildrop ready\r\n");
    log_connection("Authentication successful", client->base.client_ip, client->base.socket);
    syslog(LOG_INFO, "pop3d[%d]: User %s logged in, %zu messages",
           getpid(), client->base.username, client->nmsgs);
}

static void handle_stat(Pop3Client *client)
{
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
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
    send_response(&client->base, response);
}

static void handle_list(Pop3Client *client, const char *arg)
{
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (arg && *arg) {
        char *endptr;
        unsigned long idx = strtoul(arg, &endptr, 10);
        if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
            send_response(&client->base, "-ERR No such message\r\n");
            return;
        }
        
        Message *msg = client->msgs[idx - 1];
        if (msg->flags & F_DELE) {
            send_response(&client->base, "-ERR Message deleted\r\n");
            return;
        }
        
        char response[256];
        snprintf(response, sizeof(response), "+OK %lu %zu\r\n", idx, msg->size);
        send_response(&client->base, response);
    } else {
        send_response(&client->base, "+OK Scan list follows\r\n");
        
        for (size_t i = 0; i < client->nmsgs; i++) {
            if (!(client->msgs[i]->flags & F_DELE)) {
                char line[256];
                snprintf(line, sizeof(line), "%zu %zu\r\n",
                         i + 1, client->msgs[i]->size);
                send_response(&client->base, line);
            }
        }
        send_response(&client->base, ".\r\n");
    }
}

static void handle_retr(Pop3Client *client, const char *arg)
{
    char path[PATH_MAX];
    FILE *fp;
    char line[BUFFER_SIZE];
    
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (!arg || !*arg) {
        send_response(&client->base, "-ERR Message number required\r\n");
        return;
    }
    
    char *endptr;
    unsigned long idx = strtoul(arg, &endptr, 10);
    if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
        send_response(&client->base, "-ERR No such message\r\n");
        return;
    }
    
    Message *msg = client->msgs[idx - 1];
    if (msg->flags & F_DELE) {
        send_response(&client->base, "-ERR Message deleted\r\n");
        return;
    }
    
    snprintf(path, sizeof(path), "%s/cur/%s", client->maildir_path, msg->filename);
    fp = fopen(path, "r");
    if (!fp) {
        send_response(&client->base, "-ERR Cannot open message\r\n");
        return;
    }
    
    char response[256];
    snprintf(response, sizeof(response), "+OK %zu octets\r\n", msg->size);
    send_response(&client->base, response);
    
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '.') {
            send_response(&client->base, ".");
        }
        
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            if (len > 1 && line[len-2] == '\r') {
                send_response(&client->base, line);
            } else {
                line[len-1] = '\0';
                send_response(&client->base, line);
                send_response(&client->base, "\r\n");
            }
        } else {
            send_response(&client->base, line);
        }
    }
    
    fclose(fp);
    send_response(&client->base, ".\r\n");
}

static void handle_dele(Pop3Client *client, const char *arg)
{
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (!arg || !*arg) {
        send_response(&client->base, "-ERR Message number required\r\n");
        return;
    }
    
    char *endptr;
    unsigned long idx = strtoul(arg, &endptr, 10);
    if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
        send_response(&client->base, "-ERR No such message\r\n");
        return;
    }
    
    Message *msg = client->msgs[idx - 1];
    if (msg->flags & F_DELE) {
        send_response(&client->base, "-ERR Message already deleted\r\n");
        return;
    }
    
    msg->flags |= F_DELE;
    send_response(&client->base, "+OK Message deleted\r\n");
}

static void handle_rset(Pop3Client *client)
{
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
        return;
    }
    
    for (size_t i = 0; i < client->nmsgs; i++) {
        client->msgs[i]->flags &= ~F_DELE;
    }
    
    send_response(&client->base, "+OK Maildrop reset\r\n");
}

static void handle_uidl(Pop3Client *client, const char *arg)
{
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (arg && *arg) {
        char *endptr;
        unsigned long idx = strtoul(arg, &endptr, 10);
        if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
            send_response(&client->base, "-ERR No such message\r\n");
            return;
        }
        
        Message *msg = client->msgs[idx - 1];
        if (msg->flags & F_DELE) {
            send_response(&client->base, "-ERR Message deleted\r\n");
            return;
        }
        
        char response[512];
        snprintf(response, sizeof(response), "+OK %lu %s\r\n", idx, msg->filename);
        send_response(&client->base, response);
    } else {
        send_response(&client->base, "+OK Unique ID list follows\r\n");
        
        for (size_t i = 0; i < client->nmsgs; i++) {
            if (!(client->msgs[i]->flags & F_DELE)) {
                char line[512];
                snprintf(line, sizeof(line), "%zu %s\r\n",
                         i + 1, client->msgs[i]->filename);
                send_response(&client->base, line);
            }
        }
        send_response(&client->base, ".\r\n");
    }
}

static void handle_top(Pop3Client *client, const char *arg)
{
    char path[PATH_MAX];
    FILE *fp = NULL;
    char line[BUFFER_SIZE];
    int in_headers = 1;
    int lines_sent = 0;
    char *msg_str = NULL;
    char *endptr = NULL;
    unsigned long idx = 0;
    long nlines = 0;
    Message *msg = NULL;
    int result = -1;
    
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (!arg || !*arg) {
        send_response(&client->base, "-ERR Message number and line count required\r\n");
        return;
    }
    
    msg_str = strdup(arg);
    if (!msg_str) {
        send_response(&client->base, "-ERR Server error\r\n");
        return;
    }
    
    char *lines_str = strchr(msg_str, ' ');
    if (!lines_str) {
        send_response(&client->base, "-ERR Line count required\r\n");
        goto cleanup;
    }
    *lines_str++ = '\0';
    
    idx = strtoul(msg_str, &endptr, 10);
    if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
        send_response(&client->base, "-ERR No such message\r\n");
        goto cleanup;
    }
    
    nlines = strtol(lines_str, &endptr, 10);
    if (*endptr != '\0' || nlines < 0) {
        send_response(&client->base, "-ERR Invalid line count\r\n");
        goto cleanup;
    }
    
    msg = client->msgs[idx - 1];
    if (msg->flags & F_DELE) {
        send_response(&client->base, "-ERR Message deleted\r\n");
        goto cleanup;
    }
    
    snprintf(path, sizeof(path), "%s/cur/%s", client->maildir_path, msg->filename);
    fp = fopen(path, "r");
    if (!fp) {
        send_response(&client->base, "-ERR Cannot open message\r\n");
        goto cleanup;
    }
    
    result = 0;
    send_response(&client->base, "+OK Top of message follows\r\n");
    
    while (fgets(line, sizeof(line), fp) && lines_sent < nlines) {
        if (!in_headers) {
            lines_sent++;
        } else if (line[0] == '\n' || (line[0] == '\r' && line[1] == '\n')) {
            in_headers = 0;
            lines_sent = 0;
        }
        
        if (line[0] == '.') {
            send_response(&client->base, ".");
        }
        
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            if (len > 1 && line[len-2] == '\r') {
                send_response(&client->base, line);
            } else {
                line[len-1] = '\0';
                send_response(&client->base, line);
                send_response(&client->base, "\r\n");
            }
        } else {
            send_response(&client->base, line);
        }
    }

cleanup:
    if (fp) fclose(fp);
    free(msg_str);
    if (result == 0) {
        send_response(&client->base, ".\r\n");
    }
}

static void handle_stls(Pop3Client *client)
{
    if (client->base.using_ssl) {
        send_response(&client->base, "-ERR TLS already active\r\n");
        return;
    }
    
    if (!g_config.allow_plaintext) {
        send_response(&client->base, "-ERR STLS not available\r\n");
        return;
    }
    
    send_response(&client->base, "+OK Begin TLS negotiation\r\n");
    
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
    log_connection("TLS started", client->base.client_ip, client->base.socket);
}

static void handle_capa(Pop3Client *client)
{
    send_response(&client->base, "+OK Capability list follows\r\n");
    send_response(&client->base, "USER\r\n");
    send_response(&client->base, "TOP\r\n");
    send_response(&client->base, "UIDL\r\n");
    if (!client->base.using_ssl && g_config.allow_plaintext) {
        send_response(&client->base, "STLS\r\n");
    }
    send_response(&client->base, ".\r\n");
}

static void process_command(Pop3Client *client, char *command)
{
    char *cmd, *arg;
    
    if (!validate_input(command, MAX_LINE_LENGTH)) {
        send_response(&client->base, "-ERR Invalid command\r\n");
        return;
    }
    
    /* Remove CRLF */
    char *p = strchr(command, '\r');
    if (p) *p = '\0';
    p = strchr(command, '\n');
    if (p) *p = '\0';
    
    cmd = strtok(command, " ");
    arg = strtok(NULL, "");
    
    if (!cmd) return;
    
    if (strcasecmp(cmd, "PASS") != 0) {
        log_connection(cmd, client->base.client_ip, client->base.socket);
    } else {
        log_connection("PASS [hidden]", client->base.client_ip, client->base.socket);
    }
    
    client->base.last_activity = time(NULL);
    
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
        send_response(&client->base, "+OK\r\n");
    } else if (strcasecmp(cmd, "RSET") == 0) {
        handle_rset(client);
    } else if (strcasecmp(cmd, "QUIT") == 0) {
        if (client->base.authenticated) {
            update_maildir(client);
        }
        send_response(&client->base, "+OK POP3 server signing off\r\n");
        log_connection("QUIT", client->base.client_ip, client->base.socket);
        client->base.socket = -1; /* Signal to close connection */
    } else if (strcasecmp(cmd, "UIDL") == 0) {
        handle_uidl(client, arg);
    } else if (strcasecmp(cmd, "TOP") == 0) {
        handle_top(client, arg);
    } else if (strcasecmp(cmd, "STLS") == 0) {
        handle_stls(client);
    } else if (strcasecmp(cmd, "CAPA") == 0) {
        handle_capa(client);
    } else {
        send_response(&client->base, "-ERR Unknown command\r\n");
    }
}

/* ============================================================================
 * Main entry point
 * ============================================================================ */
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c <file>    Configuration file (default: %s)\n", CONFIG_FILE);
    fprintf(stderr, "  -d           Run in foreground (don't daemonize)\n");
    fprintf(stderr, "  -h           Show this help\n");

}

int main(int argc, char *argv[])
{
    int opt;
    int foreground = 0;
    const char *config_file = CONFIG_FILE;
    MailServer server;
    ClientPool *pool;
    
    /* Set service-specific context */
    g_ctx.service_name = "pop3d";
    g_ctx.protocol_name = "POP3";
    
    while ((opt = getopt(argc, argv, "c:dh")) != -1) {
        switch (opt) {
        case 'c':
            config_file = optarg;
            break;
        case 'd':
            foreground = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }
    
    parse_config(config_file);
    
    if (!g_config.pop3_enabled) {
        fprintf(stderr, "POP3 is disabled in configuration\n");
        return 0;
    }
    
    openlog("pop3d", LOG_PID | LOG_NDELAY, LOG_MAIL);
    
    if (!foreground) {
        daemonize();
    }
    
    syslog(LOG_INFO, "pop3d starting");
    
    if (init_ssl(g_config.cert_file, g_config.key_file) < 0) {
        log_error("SSL initialization failed");
        return 1;
    }
    
    /* Create client pool */
    pool = pool_create(sizeof(Pop3Client), MAX_CLIENTS, 
                       pop3_is_slot_free, pop3_client_init);
    if (!pool) {
        log_error("Failed to create client pool");
        cleanup_ssl();
        return 1;
    }
    
    /* Initialize server */
    server_init(&server, pool, &pop3_handler);
    
    /* Add server sockets */
    ss_add_socket(&server.ss_set, g_config.pop3_port, 0, 0, "POP3");
    ss_add_socket(&server.ss_set, g_config.pop3s_port, 0, 1, "POP3S");
    if (g_config.ipv6_enabled) {
        ss_add_socket(&server.ss_set, g_config.pop3_port, 1, 0, "POP3-IPv6");
        ss_add_socket(&server.ss_set, g_config.pop3s_port, 1, 1, "POP3S-IPv6");
    }
    
    if (server.ss_set.count == 0) {
        log_error("Failed to create any server sockets");
        pool_destroy(pool);
        cleanup_ssl();
        return 1;
    }
    
    setup_signal_handlers();
    
    syslog(LOG_INFO, "pop3d ready - POP3 port %d, POP3S port %d",
           g_config.pop3_port, g_config.pop3s_port);
    
    /* Run server */
    server_run(&server);
    
    syslog(LOG_INFO, "pop3d shutting down");
    
    server_shutdown(&server);
    pool_destroy(pool);
    cleanup_ssl();
    closelog();
    
    return 0;
}
