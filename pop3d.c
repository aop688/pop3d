/*
 * Copyright (c) 2024 POP3D - POP3 Server (Refactored with mail_common)
 */

#include "mail_common.h"
#include <dirent.h>
#include <grp.h>

#define POP3_MAX_LOGIN_ATTEMPTS	3
#define POP3_MAX_MAILDIR_PATH	PATH_MAX

/* Message flags */
#define F_DELE		0x01

/* Message structure for maildir */
typedef struct msg {
    char		*filename;
    size_t		size;
    size_t		nlines;
    int			flags;
} Message;

/* POP3 Client structure - extends ClientBase */
typedef struct {
    ClientBase		base;
    int			login_attempts;
    
    /* Maildir state */
    char		maildir_path[POP3_MAX_MAILDIR_PATH];
    Message		**msgs;
    size_t		nmsgs;
    size_t		maildrop_size;
} Pop3Client;

static Pop3Client clients[MAX_CLIENTS];
static int server_socket = -1, ssl_server_socket = -1;
static int server6_socket = -1, ssl_server6_socket = -1;

/* Forward declarations */
static void free_maildrop(Pop3Client *client);
static int load_maildir(Pop3Client *client);
static int update_maildir(Pop3Client *client);
static void handle_client_data(Pop3Client *client);
static void process_command(Pop3Client *client, char *command);

/* Maildir operations */
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

static int count_lines(const char *path)
{
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

static int load_maildir(Pop3Client *client)
{
    char cur_path[PATH_MAX];
    DIR *dirp;
    struct dirent *dp;
    struct stat st;
    Message **msgs = NULL;
    size_t count = 0;
    size_t total_size = 0;
    
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

/* POP3 command handlers */
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
    
    strncpy(client->base.username, username, sizeof(client->base.username) - 1);
    client->base.username[sizeof(client->base.username) - 1] = '\0';
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
            snprintf(client->maildir_path, sizeof(client->maildir_path),
                     "%s/%s", g_config.maildir_base, client->base.username);
        }
    } else {
        snprintf(client->maildir_path, sizeof(client->maildir_path),
                 "%s/%s", g_config.maildir_base, client->base.username);
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
    FILE *fp;
    char line[BUFFER_SIZE];
    int in_headers = 1;
    int lines_sent = 0;
    
    if (!client->base.authenticated) {
        send_response(&client->base, "-ERR Not authenticated\r\n");
        return;
    }
    
    if (!arg || !*arg) {
        send_response(&client->base, "-ERR Message number and line count required\r\n");
        return;
    }
    
    char *msg_str = strdup(arg);
    char *lines_str = strchr(msg_str, ' ');
    if (!lines_str) {
        free(msg_str);
        send_response(&client->base, "-ERR Line count required\r\n");
        return;
    }
    *lines_str++ = '\0';
    
    char *endptr;
    unsigned long idx = strtoul(msg_str, &endptr, 10);
    if (*endptr != '\0' || idx == 0 || idx > client->nmsgs) {
        free(msg_str);
        send_response(&client->base, "-ERR No such message\r\n");
        return;
    }
    
    long nlines = strtol(lines_str, &endptr, 10);
    if (*endptr != '\0' || nlines < 0) {
        free(msg_str);
        send_response(&client->base, "-ERR Invalid line count\r\n");
        return;
    }
    
    Message *msg = client->msgs[idx - 1];
    if (msg->flags & F_DELE) {
        free(msg_str);
        send_response(&client->base, "-ERR Message deleted\r\n");
        return;
    }
    
    snprintf(path, sizeof(path), "%s/cur/%s", client->maildir_path, msg->filename);
    fp = fopen(path, "r");
    if (!fp) {
        free(msg_str);
        send_response(&client->base, "-ERR Cannot open message\r\n");
        return;
    }
    
    free(msg_str);
    send_response(&client->base, "+OK Top of message follows\r\n");
    
    while (fgets(line, sizeof(line), fp) && lines_sent <= nlines) {
        if (!in_headers) {
            if (lines_sent >= nlines) break;
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
    
    fclose(fp);
    send_response(&client->base, ".\r\n");
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
        client->base.socket = -1;
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

static void check_timeouts(void)
{
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].base.socket == -1) continue;
        
        time_t timeout = clients[i].base.authenticated ?
                         g_config.timeout_command : g_config.timeout_login;
        
        if (now - clients[i].base.last_activity > timeout) {
            int sock = clients[i].base.socket;
            send_response(&clients[i].base, "-ERR Timeout\r\n");
            log_connection("Timeout", clients[i].base.client_ip, sock);
            if (clients[i].base.ssl) {
                SSL_shutdown(clients[i].base.ssl);
                SSL_free(clients[i].base.ssl);
                clients[i].base.ssl = NULL;
            }
            close(sock);
            free_maildrop(&clients[i]);
            memset(&clients[i], 0, sizeof(Pop3Client));
            clients[i].base.socket = -1;
        }
    }
}

static Pop3Client* accept_connection(int server_fd, int is_ssl, int is_ipv6)
{
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_socket;
    Pop3Client *client = NULL;
    int slot = -1;
    
    client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
        if (errno != EINTR && errno != EAGAIN)
            log_error("Accept failed: %s", strerror(errno));
        return NULL;
    }
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].base.socket == -1) {
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
    memset(client, 0, sizeof(Pop3Client));
    client->base.socket = client_socket;
    client->base.last_activity = time(NULL);
    
    if (is_ipv6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, client->base.client_ip,
                  sizeof(client->base.client_ip));
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
        inet_ntop(AF_INET, &sin->sin_addr, client->base.client_ip,
                  sizeof(client->base.client_ip));
    }
    
    log_connection("New connection", client->base.client_ip, client_socket);
    
    if (is_ssl) {
        client->base.ssl = SSL_new(g_ctx.ssl_ctx);
        if (!client->base.ssl) {
            close(client_socket);
            client->base.socket = -1;
            return NULL;
        }
        
        SSL_set_fd(client->base.ssl, client_socket);
        
        if (SSL_accept(client->base.ssl) <= 0) {
            log_security("SSL handshake failed", client->base.client_ip, NULL);
            SSL_free(client->base.ssl);
            close(client_socket);
            client->base.socket = -1;
            return NULL;
        }
        
        client->base.using_ssl = 1;
        log_connection("SSL connection established",
                       client->base.client_ip, client_socket);
    }
    
    send_response(&client->base, "+OK POP3 server ready\r\n");
    return client;
}

static void handle_client_data(Pop3Client *client)
{
    char buffer[BUFFER_SIZE];
    int bytes;
    int sock;
    
    bytes = receive_data(&client->base, buffer, sizeof(buffer));
    
    if (bytes <= 0) {
        if (bytes < 0 && errno == EAGAIN) return;
        
        sock = client->base.socket;
        log_connection("Client disconnected", client->base.client_ip, sock);
        if (client->base.ssl) {
            SSL_shutdown(client->base.ssl);
            SSL_free(client->base.ssl);
            client->base.ssl = NULL;
        }
        close(sock);
        free_maildrop(client);
        memset(client, 0, sizeof(Pop3Client));
        client->base.socket = -1;
        return;
    }
    
    buffer[bytes] = '\0';
    process_command(client, buffer);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c <file>    Configuration file (default: %s)\n", CONFIG_FILE);
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
    fd_set read_fds;
    int max_fd;
    time_t last_timeout_check = 0;
    struct timeval tv;
    
    /* Set service-specific context */
    g_ctx.service_name = "pop3d";
    g_ctx.protocol_name = "POP3";
    
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
                                          g_config.key_file, "pop3d");
    }
    
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
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].base.socket = -1;
    }
    
    server_socket = create_server_socket(g_config.pop3_port, 0);
    if (server_socket < 0) {
        log_error("Failed to create IPv4 server socket on port %d",
                  g_config.pop3_port);
    }
    
    ssl_server_socket = create_server_socket(g_config.pop3s_port, 0);
    if (ssl_server_socket < 0) {
        log_error("Failed to create SSL server socket on port %d",
                  g_config.pop3s_port);
    }
    
    if (g_config.ipv6_enabled) {
        server6_socket = create_server_socket(g_config.pop3_port, 1);
        ssl_server6_socket = create_server_socket(g_config.pop3s_port, 1);
    }
    
    if (server_socket < 0 && ssl_server_socket < 0 &&
        server6_socket < 0 && ssl_server6_socket < 0) {
        log_error("Failed to create any server sockets");
        cleanup_ssl();
        return 1;
    }
    
    setup_signal_handlers();
    
    syslog(LOG_INFO, "pop3d ready - POP3 port %d, POP3S port %d",
           g_config.pop3_port, g_config.pop3s_port);
    
    while (g_ctx.running) {
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
            if (clients[i].base.socket >= 0) {
                FD_SET(clients[i].base.socket, &read_fds);
                if (clients[i].base.socket > max_fd)
                    max_fd = clients[i].base.socket;
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
        
        time_t now = time(NULL);
        if (now - last_timeout_check >= 30) {
            check_timeouts();
            last_timeout_check = now;
        }
        
        if (server_socket >= 0 && FD_ISSET(server_socket, &read_fds))
            accept_connection(server_socket, 0, 0);
        if (ssl_server_socket >= 0 && FD_ISSET(ssl_server_socket, &read_fds))
            accept_connection(ssl_server_socket, 1, 0);
        if (server6_socket >= 0 && FD_ISSET(server6_socket, &read_fds))
            accept_connection(server6_socket, 0, 1);
        if (ssl_server6_socket >= 0 && FD_ISSET(ssl_server6_socket, &read_fds))
            accept_connection(ssl_server6_socket, 1, 1);
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].base.socket >= 0 &&
                FD_ISSET(clients[i].base.socket, &read_fds)) {
                handle_client_data(&clients[i]);
            }
        }
    }
    
    syslog(LOG_INFO, "pop3d shutting down");
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].base.socket >= 0) {
            if (clients[i].base.ssl) {
                SSL_shutdown(clients[i].base.ssl);
                SSL_free(clients[i].base.ssl);
            }
            close(clients[i].base.socket);
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
