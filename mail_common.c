/*
 * Copyright (c) 2024 MailD - Common Library for POP3/SMTP Servers
 */

#include "mail_common.h"

/* ============================================================================
 * Global instances
 * ============================================================================ */
GlobalConfig g_config = {
    .allow_plaintext = 0,
    .max_connections = 50,
    .log_auth = 1,
    .ipv6_enabled = 1,
    
    /* POP3 defaults */
    .pop3_port = 110,
    .pop3s_port = 995,
    .pop3_enabled = 1,
    
    /* SMTP defaults */
    .smtp_port = 25,
    .submission_port = 587,
    .smtps_port = 465,
    .smtp_enabled = 1,
    
    /* SMTP specific */
    .require_auth = 1,
    .max_msg_size = 50 * 1024 * 1024,
    .hostname = "localhost",
    .relay_only = 0,
    .timeout_data = DATA_TIMEOUT,
    
    /* Timeouts */
    .timeout_login = LOGIN_TIMEOUT,
    .timeout_command = COMMAND_TIMEOUT,
    
    /* SSL paths (will be set per-protocol) */
    .cert_file = "/etc/ssl/certs/maild.crt",
    .key_file = "/etc/ssl/private/maild.key",
    
    /* Mail storage */
    .maildir_base = "/var/mail"
};

ServerContext g_ctx = {
    .ssl_ctx = NULL,
    .running = 1,
    .service_name = "maild",
    .protocol_name = "MAIL"
};

/* ============================================================================
 * Authentication
 * ============================================================================ */
#if HAVE_PAM
/* PAM conversation function */
static int pam_conv_func(int num_msg, const struct pam_message **msg,
                         struct pam_response **resp, void *appdata_ptr)
{
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
int authenticate_user(const char *username, const char *password, const char *service)
{
    pam_handle_t *pamh = NULL;
    struct pam_conv conv = { pam_conv_func, (void *)password };
    int retval;
    
    retval = pam_start(service, username, &conv, &pamh);
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
/* Shadow password fallback */
int authenticate_user(const char *username, const char *password, const char *service)
{
    (void)service; /* unused in shadow mode */
    
    /* Test mode - check environment variables */
    char test_user_env[64], test_pass_env[64];
    snprintf(test_user_env, sizeof(test_user_env), "%s_TEST_USER", 
             g_ctx.protocol_name);
    snprintf(test_pass_env, sizeof(test_pass_env), "%s_TEST_PASS",
             g_ctx.protocol_name);
    
    const char *test_user = getenv(test_user_env);
    const char *test_pass = getenv(test_pass_env);
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
    
    const char *correct = sp ? sp->sp_pwdp : pw->pw_passwd;
    
    if (!correct || correct[0] == '\0' || strcmp(correct, "x") == 0) {
        if (sp) correct = sp->sp_pwdp;
        else return 0;
    }
    
    if (!correct || correct[0] == '*' || correct[0] == '!') {
        return 0;
    }
    
    encrypted = crypt(password, correct);
    return encrypted && strcmp(encrypted, correct) == 0;
}
#endif

/* ============================================================================
 * Logging functions
 * ============================================================================ */
void log_connection(const char *message, const char *client_ip, int socket)
{
    if (g_config.log_auth) {
        syslog(LOG_INFO, "%s[%d]: %s - %s (fd=%d)",
               g_ctx.service_name, getpid(), client_ip, message, socket);
    }
}

void log_security(const char *event, const char *client_ip, const char *details)
{
    syslog(LOG_WARNING, "%s[%d]: SECURITY: %s - %s: %s",
           g_ctx.service_name, getpid(), event, client_ip,
           details ? details : "");
}

void log_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsyslog(LOG_ERR, fmt, ap);
    va_end(ap);
}

/* ============================================================================
 * SSL initialization
 * ============================================================================ */
int init_ssl(const char *cert_file, const char *key_file)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_ctx.ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ctx.ssl_ctx) {
        log_error("Unable to create SSL context");
        return -1;
    }
    
    SSL_CTX_set_min_proto_version(g_ctx.ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_ctx.ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                        SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    if (SSL_CTX_use_certificate_file(g_ctx.ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Could not load certificate file: %s", cert_file);
        fprintf(stderr, "Warning: Could not load certificate file: %s\n", cert_file);
    }
    
    if (SSL_CTX_use_PrivateKey_file(g_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        log_error("Could not load private key file: %s", key_file);
        fprintf(stderr, "Warning: Could not load private key file: %s\n", key_file);
    }
    
    return 0;
}

void cleanup_ssl(void)
{
    if (g_ctx.ssl_ctx) {
        SSL_CTX_free(g_ctx.ssl_ctx);
        g_ctx.ssl_ctx = NULL;
    }
    EVP_cleanup();
    ERR_free_strings();
}

/* ============================================================================
 * Network I/O with SSL support
 * ============================================================================ */
int send_response(ClientBase *client, const char *response)
{
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

int receive_line(ClientBase *client, char *buffer, int size)
{
    int ret;
    int pos = 0;
    
    if (size <= 0)
        return -1;
    
    memset(buffer, 0, size);
    
    while (pos < size - 1) {
        char ch;
        
        if (client->using_ssl && client->ssl) {
            ret = SSL_read(client->ssl, &ch, 1);
            if (ret <= 0) {
                int ssl_err = SSL_get_error(client->ssl, ret);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return -1;
            }
        } else {
            ret = recv(client->socket, &ch, 1, 0);
            if (ret <= 0) {
                if (ret < 0 && errno == EINTR)
                    continue;
                return -1;
            }
        }
        
        buffer[pos++] = ch;
        
        if (pos >= 2 && buffer[pos-2] == '\r' && buffer[pos-1] == '\n') {
            buffer[pos-2] = '\0';
            return pos;
        }
    }
    
    /* Buffer full but no CRLF found - line too long */
    return -1;
}

int receive_data(ClientBase *client, char *buffer, int size)
{
    int ret;
    
    if (client->using_ssl && client->ssl) {
        ret = SSL_read(client->ssl, buffer, size - 1);
    } else {
        ret = recv(client->socket, buffer, size - 1, 0);
    }
    
    return ret;
}

/* ============================================================================
 * Input validation
 * ============================================================================ */
int validate_input(const char *input, size_t max_len)
{
    if (!input || strlen(input) > max_len)
        return 0;
    
    for (size_t i = 0; input[i]; i++) {
        if (!isprint((unsigned char)input[i]) && input[i] != '\r' && input[i] != '\n')
            return 0;
    }
    
    return 1;
}

/* ============================================================================
 * String utilities
 * ============================================================================ */
void str_trim(char *str)
{
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

int parse_email_address(const char *addr, char *user, size_t user_size,
                        char *domain, size_t domain_size)
{
    const char *at;
    size_t ulen, dlen;
    
    if (!addr || !user || !domain)
        return -1;
    
    at = strchr(addr, '@');
    if (!at)
        return -1;
    
    ulen = at - addr;
    if (ulen == 0 || ulen >= user_size)
        return -1;
    
    dlen = strlen(at + 1);
    if (dlen == 0 || dlen >= domain_size)
        return -1;
    
    memcpy(user, addr, ulen);
    user[ulen] = '\0';
    
    memcpy(domain, at + 1, dlen);
    domain[dlen] = '\0';
    
    return 0;
}

/* ============================================================================
 * Socket creation
 * ============================================================================ */
int create_server_socket(int port, int is_ipv6)
{
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

/* ============================================================================
 * Connection management (Refactored)
 * ============================================================================ */

void ss_init(ServerSocketSet *ss_set)
{
    memset(ss_set, 0, sizeof(ServerSocketSet));
    for (int i = 0; i < SOCK_TYPE_MAX; i++) {
        ss_set->sockets[i].fd = -1;
    }
}

int ss_add_socket(ServerSocketSet *ss_set, int port, int is_ipv6, int is_ssl, const char *name)
{
    if (ss_set->count >= SOCK_TYPE_MAX) {
        log_error("Too many server sockets");
        return -1;
    }
    
    int fd = create_server_socket(port, is_ipv6);
    if (fd < 0) {
        return -1;
    }
    
    ServerSocket *sock = &ss_set->sockets[ss_set->count++];
    sock->fd = fd;
    sock->port = port;
    sock->is_ipv6 = is_ipv6;
    sock->is_ssl = is_ssl;
    sock->name = name;
    
    return 0;
}

void ss_close_all(ServerSocketSet *ss_set)
{
    for (int i = 0; i < ss_set->count; i++) {
        if (ss_set->sockets[i].fd >= 0) {
            close(ss_set->sockets[i].fd);
            ss_set->sockets[i].fd = -1;
        }
    }
    ss_set->count = 0;
}

int ss_get_max_fd(ServerSocketSet *ss_set)
{
    int max_fd = -1;
    for (int i = 0; i < ss_set->count; i++) {
        if (ss_set->sockets[i].fd > max_fd) {
            max_fd = ss_set->sockets[i].fd;
        }
    }
    return max_fd;
}

void ss_build_fdset(ServerSocketSet *ss_set, fd_set *fds)
{
    FD_ZERO(fds);
    for (int i = 0; i < ss_set->count; i++) {
        if (ss_set->sockets[i].fd >= 0) {
            FD_SET(ss_set->sockets[i].fd, fds);
        }
    }
}

int ss_accept_client(ServerSocketSet *ss_set, fd_set *fds, ClientBase *client)
{
    for (int i = 0; i < ss_set->count; i++) {
        ServerSocket *sock = &ss_set->sockets[i];
        if (sock->fd >= 0 && FD_ISSET(sock->fd, fds)) {
            int is_ssl = sock->is_ssl;
            int is_ipv6 = sock->is_ipv6;
            
            if (accept_client_connection(sock->fd, client, is_ssl, is_ipv6) == 0) {
                return 1; /* Client accepted */
            }
            return -1; /* Accept failed */
        }
    }
    return 0; /* No socket ready */
}

/* ============================================================================
 * Client pool management
 * ============================================================================ */
ClientPool* pool_create(size_t client_size, int max_clients,
                        int (*is_slot_free)(void *client),
                        void (*init_client)(void *client))
{
    ClientPool *pool = calloc(1, sizeof(ClientPool));
    if (!pool) return NULL;
    
    pool->clients = calloc(max_clients, client_size);
    if (!pool->clients) {
        free(pool);
        return NULL;
    }
    
    pool->client_size = client_size;
    pool->max_clients = max_clients;
    pool->is_slot_free = is_slot_free;
    pool->init_client = init_client;
    
    /* Initialize all clients */
    for (int i = 0; i < max_clients; i++) {
        void *client = (char *)pool->clients + (i * client_size);
        init_client(client);
    }
    
    return pool;
}

void pool_destroy(ClientPool *pool)
{
    if (pool) {
        free(pool->clients);
        free(pool);
    }
}

void* pool_find_free_slot(ClientPool *pool)
{
    for (int i = 0; i < pool->max_clients; i++) {
        void *client = (char *)pool->clients + (i * pool->client_size);
        if (pool->is_slot_free(client)) {
            return client;
        }
    }
    return NULL;
}

int pool_is_full(ClientPool *client)
{
    (void)client;
    return 0; /* Handled by pool_find_free_slot returning NULL */
}

void pool_cleanup_all(ClientPool *pool, ProtocolHandler *handler)
{
    for (int i = 0; i < pool->max_clients; i++) {
        void *client = (char *)pool->clients + (i * pool->client_size);
        ClientBase *base = (ClientBase *)client;
        if (base->socket >= 0) {
            close_client_connection(base, handler, client);
        }
    }
}

/* ============================================================================
 * Connection handling
 * ============================================================================ */
int accept_client_connection(int server_fd, ClientBase *client, int is_ssl, int is_ipv6)
{
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_socket;
    
    client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
        if (errno != EINTR && errno != EAGAIN)
            log_error("Accept failed: %s", strerror(errno));
        return -1;
    }
    
    memset(client, 0, sizeof(ClientBase));
    client->socket = client_socket;
    client->last_activity = time(NULL);
    
    if (is_ipv6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&client_addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, client->client_ip,
                  sizeof(client->client_ip));
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&client_addr;
        inet_ntop(AF_INET, &sin->sin_addr, client->client_ip,
                  sizeof(client->client_ip));
    }
    
    log_connection("New connection", client->client_ip, client_socket);
    
    if (is_ssl) {
        if (perform_ssl_handshake(client) < 0) {
            close(client_socket);
            client->socket = -1;
            return -1;
        }
    }
    
    return 0;
}

void close_client_connection(ClientBase *client, ProtocolHandler *handler, void *protocol_client)
{
    /* Save socket fd early, as cleanup might modify the structure */
    int sock = client->socket;
    
    if (handler && handler->cleanup_client) {
        handler->cleanup_client(protocol_client);
    }
    
    if (client->ssl) {
        /* SSL_shutdown requires the underlying socket to be open */
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    
    if (sock >= 0) {
        close(sock);
    }
    client->socket = -1;
}

int perform_ssl_handshake(ClientBase *client)
{
    client->ssl = SSL_new(g_ctx.ssl_ctx);
    if (!client->ssl) {
        return -1;
    }
    
    SSL_set_fd(client->ssl, client->socket);
    
    if (SSL_accept(client->ssl) <= 0) {
        log_security("SSL handshake failed", client->client_ip, NULL);
        SSL_free(client->ssl);
        client->ssl = NULL;
        return -1;
    }
    
    client->using_ssl = 1;
    log_connection("SSL connection established", client->client_ip, client->socket);
    return 0;
}

int check_client_timeout(ClientBase *client, time_t now, int timeout_seconds)
{
    return (now - client->last_activity > timeout_seconds);
}

/* ============================================================================
 * Main server loop
 * ============================================================================ */
int server_init(MailServer *server, ClientPool *pool, ProtocolHandler *handler)
{
    memset(server, 0, sizeof(MailServer));
    server->pool = pool;
    server->handler = handler;
    ss_init(&server->ss_set);
    return 0;
}

int server_run(MailServer *server)
{
    fd_set read_fds;
    struct timeval tv;
    int max_fd;
    
    while (g_ctx.running) {
        /* Build fdset from server sockets */
        ss_build_fdset(&server->ss_set, &read_fds);
        max_fd = ss_get_max_fd(&server->ss_set);
        
        /* Add client sockets to fdset */
        for (int i = 0; i < server->pool->max_clients; i++) {
            void *client = (char *)server->pool->clients + (i * server->pool->client_size);
            ClientBase *base = (ClientBase *)client;
            if (base->socket >= 0) {
                FD_SET(base->socket, &read_fds);
                if (base->socket > max_fd)
                    max_fd = base->socket;
            }
        }
        
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("select error: %s", strerror(errno));
            return -1;
        }
        
        /* Check timeouts */
        time_t now = time(NULL);
        if (now - server->last_timeout_check >= 30) {
            for (int i = 0; i < server->pool->max_clients; i++) {
                void *client = (char *)server->pool->clients + (i * server->pool->client_size);
                ClientBase *base = (ClientBase *)client;
                if (base->socket >= 0) {
                    int timeout = server->handler->get_timeout(client);
                    if (check_client_timeout(base, now, timeout)) {
                        if (server->handler->handle_timeout) {
                            server->handler->handle_timeout(client);
                        }
                        int sock = base->socket;
                        log_connection("Timeout", base->client_ip, sock);
                        close_client_connection(base, server->handler, client);
                        server->pool->init_client(client);
                    }
                }
            }
            server->last_timeout_check = now;
        }
        
        /* Accept new connections */
        ClientBase new_client;
        int accept_result = ss_accept_client(&server->ss_set, &read_fds, &new_client);
        if (accept_result == 1) {
            void *slot = pool_find_free_slot(server->pool);
            if (!slot) {
                const char *busy_msg = "-ERR Server busy\r\n";
                send(new_client.socket, busy_msg, strlen(busy_msg), MSG_NOSIGNAL);
                close(new_client.socket);
                log_security("Connection limit reached", new_client.client_ip, NULL);
            } else {
                memcpy(slot, &new_client, sizeof(ClientBase));
                if (server->handler->send_greeting) {
                    server->handler->send_greeting((ClientBase *)slot);
                }
            }
        }
        
        /* Handle client data */
        for (int i = 0; i < server->pool->max_clients; i++) {
            void *client = (char *)server->pool->clients + (i * server->pool->client_size);
            ClientBase *base = (ClientBase *)client;
            if (base->socket >= 0 && FD_ISSET(base->socket, &read_fds)) {
                int result = server->handler->process_data(client);
                if (result < 0) {
                    int sock = base->socket;
                    log_connection("Client disconnected", base->client_ip, sock);
                    close_client_connection(base, server->handler, client);
                    server->pool->init_client(client);
                }
            }
        }
    }
    
    return 0;
}

void server_shutdown(MailServer *server)
{
    pool_cleanup_all(server->pool, server->handler);
    ss_close_all(&server->ss_set);
}

/* ============================================================================
 * Configuration parsing
 * ============================================================================ */
int parse_config(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    
    if (!fp) {
        /* Config file is optional - use defaults */
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        str_trim(line);
        
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#')
            continue;
        
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "");
        
        if (!key || !value) {
            log_error("Config line %d: invalid syntax", line_num);
            continue;
        }
        
        str_trim(key);
        str_trim(value);
        
        /* Common settings */
        if (strcmp(key, "allow_plaintext") == 0) {
            g_config.allow_plaintext = atoi(value);
        } else if (strcmp(key, "max_connections") == 0) {
            g_config.max_connections = atoi(value);
        } else if (strcmp(key, "log_auth") == 0) {
            g_config.log_auth = atoi(value);
        } else if (strcmp(key, "ipv6_enabled") == 0) {
            g_config.ipv6_enabled = atoi(value);
        } else if (strcmp(key, "timeout_login") == 0) {
            g_config.timeout_login = atoi(value);
        } else if (strcmp(key, "timeout_command") == 0) {
            g_config.timeout_command = atoi(value);
        } else if (strcmp(key, "timeout_data") == 0) {
            g_config.timeout_data = atoi(value);
        } else if (strcmp(key, "cert_file") == 0) {
            strncpy(g_config.cert_file, value, sizeof(g_config.cert_file) - 1);
            g_config.cert_file[sizeof(g_config.cert_file) - 1] = '\0';
        } else if (strcmp(key, "key_file") == 0) {
            strncpy(g_config.key_file, value, sizeof(g_config.key_file) - 1);
            g_config.key_file[sizeof(g_config.key_file) - 1] = '\0';
        } else if (strcmp(key, "maildir_base") == 0) {
            strncpy(g_config.maildir_base, value, sizeof(g_config.maildir_base) - 1);
            g_config.maildir_base[sizeof(g_config.maildir_base) - 1] = '\0';
        }
        /* POP3 settings */
        else if (strcmp(key, "pop3_port") == 0) {
            g_config.pop3_port = atoi(value);
        } else if (strcmp(key, "pop3s_port") == 0) {
            g_config.pop3s_port = atoi(value);
        } else if (strcmp(key, "pop3_enabled") == 0) {
            g_config.pop3_enabled = atoi(value);
        }
        /* SMTP settings */
        else if (strcmp(key, "smtp_port") == 0) {
            g_config.smtp_port = atoi(value);
        } else if (strcmp(key, "submission_port") == 0) {
            g_config.submission_port = atoi(value);
        } else if (strcmp(key, "smtps_port") == 0) {
            g_config.smtps_port = atoi(value);
        } else if (strcmp(key, "smtp_enabled") == 0) {
            g_config.smtp_enabled = atoi(value);
        } else if (strcmp(key, "require_auth") == 0) {
            g_config.require_auth = atoi(value);
        } else if (strcmp(key, "max_msg_size") == 0) {
            g_config.max_msg_size = strtoul(value, NULL, 10);
        } else if (strcmp(key, "hostname") == 0) {
            strncpy(g_config.hostname, value, sizeof(g_config.hostname) - 1);
            g_config.hostname[sizeof(g_config.hostname) - 1] = '\0';
        } else if (strcmp(key, "relay_only") == 0) {
            g_config.relay_only = atoi(value);
        }
    }
    
    fclose(fp);
    return 0;
}

/* ============================================================================
 * Daemonization
 * ============================================================================ */
void daemonize(void)
{
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

/* ============================================================================
 * Signal handling
 * ============================================================================ */
void signal_handler(int sig)
{
    (void)sig;
    g_ctx.running = 0;
}

void setup_signal_handlers(void)
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
}

/* ============================================================================
 * Utility
 * ============================================================================ */
int is_local_user(const char *user)
{
    struct passwd *pw = getpwnam(user);
    return pw != NULL;
}
