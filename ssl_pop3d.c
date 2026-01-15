/*
 * SSL-enabled POP3 server for Linux with security features
 * STILL NOT RECOMMENDED FOR PRODUCTION USE
 */

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
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define POP3_PORT 1110
#define POP3S_PORT 1995
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define MAX_LOGIN_ATTEMPTS 3
#define LOGIN_TIMEOUT 60
#define COMMAND_TIMEOUT 300

typedef struct {
    int socket;
    SSL *ssl;
    int authenticated;
    int using_ssl;
    char username[256];
    int login_attempts;
    time_t last_activity;
    char client_ip[INET6_ADDRSTRLEN];
    int failed_logins;
} Client;

Client clients[MAX_CLIENTS];
int server_socket, ssl_server_socket;
int client_count = 0;
SSL_CTX *ssl_ctx;

// Security configuration
struct {
    int allow_plaintext;
    int max_connections;
    int log_failures;
    char cert_file[256];
    char key_file[256];
} security_config = {
    .allow_plaintext = 1,
    .max_connections = 10,
    .log_failures = 1,
    .cert_file = "/etc/ssl/certs/server.crt",
    .key_file = "/etc/ssl/private/server.key"
};

// SSL initialization
void init_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }
    
    // Set certificate and key
    if (SSL_CTX_use_certificate_file(ssl_ctx, security_config.cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Warning: Could not load certificate file: %s\n", security_config.cert_file);
        fprintf(stderr, "Generate one with: openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 365 -nodes\n", 
                security_config.key_file, security_config.cert_file);
    }
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, security_config.key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Warning: Could not load private key file: %s\n", security_config.key_file);
    }
    
    // Set SSL options
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    
    // Require client certificate (optional)
    // SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
}

void cleanup_ssl() {
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    ERR_free_strings();
}

void log_connection(const char *message, const char *client_ip, int socket) {
    openlog("pop3d", LOG_PID | LOG_NDELAY, LOG_MAIL);
    if (security_config.log_failures) {
        syslog(LOG_INFO, "Client %s (fd=%d): %s", client_ip, socket, message);
    }
    closelog();
}

void log_security(const char *event, const char *details) {
    openlog("pop3d", LOG_PID | LOG_NDELAY, LOG_AUTH);
    syslog(LOG_WARNING, "SECURITY: %s - %s", event, details);
    closelog();
}

int is_ip_allowed(const char *client_ip) {
    // Simple localhost and private network check
    if (strncmp(client_ip, "127.", 4) == 0) return 1;
    if (strncmp(client_ip, "192.168.", 8) == 0) return 1;
    if (strncmp(client_ip, "10.", 3) == 0) return 1;
    if (strncmp(client_ip, "172.16.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.17.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.18.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.19.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.20.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.21.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.22.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.23.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.24.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.25.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.26.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.27.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.28.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.29.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.30.", 7) == 0) return 1;
    if (strncmp(client_ip, "172.31.", 7) == 0) return 1;
    
    return 0;
}

int validate_input(const char *input) {
    if (!input || strlen(input) > 512) return 0;
    
    for (int i = 0; input[i]; i++) {
        if (!isprint(input[i])) return 0;
        if (input[i] == '\r' || input[i] == '\n') break;
    }
    
    return 1;
}

int send_response(Client *client, const char *response) {
    int len = strlen(response);
    if (client->using_ssl && client->ssl) {
        return SSL_write(client->ssl, response, len);
    } else {
        return send(client->socket, response, len, 0);
    }
}

int receive_data(Client *client, char *buffer, int size) {
    if (client->using_ssl && client->ssl) {
        return SSL_read(client->ssl, buffer, size - 1);
    } else {
        return recv(client->socket, buffer, size - 1, 0);
    }
}

void handle_stls(Client *client) {
    if (client->using_ssl) {
        send_response(client, "-ERR TLS already active\r\n");
        return;
    }
    
    if (!security_config.allow_plaintext) {
        send_response(client, "-ERR TLS not available\r\n");
        return;
    }
    
    send_response(client, "+OK Begin TLS negotiation\r\n");
    
    // Create SSL object
    client->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(client->ssl, client->socket);
    
    // Perform TLS handshake
    int ret = SSL_accept(client->ssl);
    if (ret <= 0) {
        SSL_free(client->ssl);
        client->ssl = NULL;
        log_security("TLS handshake failed", client->client_ip);
        return;
    }
    
    client->using_ssl = 1;
    log_connection("TLS negotiation successful", client->client_ip, client->socket);
}

void handle_user(Client *client, const char *username) {
    if (!validate_input(username)) {
        send_response(client, "-ERR Invalid input\r\n");
        log_security("Invalid input in USER command", client->client_ip);
        return;
    }
    
    if (client->login_attempts >= MAX_LOGIN_ATTEMPTS) {
        send_response(client, "-ERR Too many failed attempts\r\n");
        log_security("Login attempt limit exceeded", client->client_ip);
        return;
    }
    
    if (strcmp(username, "aptuser") == 0) {
        strncpy(client->username, username, sizeof(client->username) - 1);
        client->username[sizeof(client->username) - 1] = '\0';
        send_response(client, "+OK User accepted\r\n");
        log_connection("USER command accepted", client->client_ip, client->socket);
    } else {
        send_response(client, "-ERR Invalid username\r\n");
        client->login_attempts++;
        log_security("Invalid username attempt", client->client_ip);
    }
    
    client->last_activity = time(NULL);
}

void handle_pass(Client *client, const char *password) {
    if (!validate_input(password)) {
        send_response(client, "-ERR Invalid input\r\n");
        log_security("Invalid input in PASS command", client->client_ip);
        return;
    }
    
    if (client->login_attempts >= MAX_LOGIN_ATTEMPTS) {
        send_response(client, "-ERR Too many failed attempts\r\n");
        log_security("Login attempt limit exceeded", client->client_ip);
        return;
    }
    
    if (strcmp(client->username, "aptuser") == 0 && strcmp(password, "pop3dabc123") == 0) {
        client->authenticated = 1;
        send_response(client, "+OK Maildrop ready\r\n");
        log_connection("Authentication successful", client->client_ip, client->socket);
    } else {
        send_response(client, "-ERR Invalid credentials\r\n");
        client->login_attempts++;
        client->failed_logins++;
        log_security("Authentication failure", client->client_ip);
        
        if (client->login_attempts >= MAX_LOGIN_ATTEMPTS) {
            log_security("Account locked due to failed attempts", client->client_ip);
        }
    }
    
    client->last_activity = time(NULL);
}

void check_timeouts() {
    time_t now = time(NULL);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1) {
            time_t timeout = clients[i].authenticated ? COMMAND_TIMEOUT : LOGIN_TIMEOUT;
            
            if (now - clients[i].last_activity > timeout) {
                send_response(&clients[i], "-ERR Timeout\r\n");
                if (clients[i].ssl) {
                    SSL_shutdown(clients[i].ssl);
                    SSL_free(clients[i].ssl);
                }
                close(clients[i].socket);
                log_connection("Connection timeout", clients[i].client_ip, clients[i].socket);
                clients[i].socket = -1;
                clients[i].authenticated = 0;
                clients[i].using_ssl = 0;
                clients[i].ssl = NULL;
            }
        }
    }
}

void process_client_command(Client *client, char *command) {
    if (!validate_input(command)) {
        send_response(client, "-ERR Invalid input\r\n");
        log_security("Invalid command received", client->client_ip);
        return;
    }
    
    char *cmd = strtok(command, " \r\n");
    char *arg = strtok(NULL, "\r\n");
    
    if (cmd == NULL) return;
    
    // Log command (but not passwords)
    if (strcasecmp(cmd, "PASS") != 0) {
        log_connection(cmd, client->client_ip, client->socket);
    } else {
        log_connection("PASS [REDACTED]", client->client_ip, client->socket);
    }
    
    client->last_activity = time(NULL);
    
    if (strcasecmp(cmd, "STLS") == 0) {
        handle_stls(client);
    } else if (strcasecmp(cmd, "USER") == 0) {
        handle_user(client, arg ?: "");
    } else if (strcasecmp(cmd, "PASS") == 0) {
        handle_pass(client, arg ?: "");
    } else if (strcasecmp(cmd, "STAT") == 0) {
        if (!client->authenticated) {
            send_response(client, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client, "+OK 0 0\r\n");
    } else if (strcasecmp(cmd, "LIST") == 0) {
        if (!client->authenticated) {
            send_response(client, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client, "+OK 0 messages\r\n.\r\n");
    } else if (strcasecmp(cmd, "RETR") == 0) {
        if (!client->authenticated) {
            send_response(client, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client, "-ERR No such message\r\n");
    } else if (strcasecmp(cmd, "DELE") == 0) {
        if (!client->authenticated) {
            send_response(client, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client, "-ERR No such message\r\n");
    } else if (strcasecmp(cmd, "RSET") == 0) {
        if (!client->authenticated) {
            send_response(client, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client, "+OK Maildrop reset\r\n");
    } else if (strcasecmp(cmd, "QUIT") == 0) {
        send_response(client, "+OK POP3 server signing off\r\n");
        log_connection("QUIT", client->client_ip, client->socket);
        client->authenticated = 0;
        client->socket = -1;
    } else if (strcasecmp(cmd, "NOOP") == 0) {
        send_response(client, "+OK\r\n");
    } else if (strcasecmp(cmd, "CAPA") == 0) {
        send_response(client, "+OK Capability list follows\r\n");
        send_response(client, "USER\r\n");
        if (!client->using_ssl && security_config.allow_plaintext) {
            send_response(client, "STLS\r\n");
        }
        send_response(client, "TOP\r\n");
        send_response(client, "UIDL\r\n");
        send_response(client, ".\r\n");
    } else {
        send_response(client, "-ERR Unknown command\r\n");
    }
}

Client* accept_new_connection(int server_fd, int is_ssl) {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
        perror("Accept failed");
        return NULL;
    }
    
    // Find free client slot
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) {
            clients[i].socket = client_socket;
            clients[i].authenticated = 0;
            clients[i].using_ssl = is_ssl;
            clients[i].username[0] = '\0';
            clients[i].login_attempts = 0;
            clients[i].failed_logins = 0;
            clients[i].ssl = NULL;
            clients[i].last_activity = time(NULL);
            
            inet_ntop(AF_INET, &client_addr.sin_addr, clients[i].client_ip, 
                      INET_ADDRSTRLEN);
            
            // Check if IP is allowed
            if (!is_ip_allowed(clients[i].client_ip)) {
                send_response(&clients[i], "-ERR Access denied\r\n");
                log_security("Connection from unauthorized IP", clients[i].client_ip);
                close(client_socket);
                clients[i].socket = -1;
                return NULL;
            }
            
            // Check connection limit
            int active_connections = 0;
            for (int j = 0; j < MAX_CLIENTS; j++) {
                if (clients[j].socket != -1) active_connections++;
            }
            
            if (active_connections >= security_config.max_connections) {
                send_response(&clients[i], "-ERR Too many connections\r\n");
                log_security("Connection limit exceeded", clients[i].client_ip);
                close(client_socket);
                clients[i].socket = -1;
                return NULL;
            }
            
            log_connection("New connection", clients[i].client_ip, client_socket);
            
            // If this is SSL connection, perform handshake
            if (is_ssl) {
                clients[i].ssl = SSL_new(ssl_ctx);
                SSL_set_fd(clients[i].ssl, client_socket);
                
                int ret = SSL_accept(clients[i].ssl);
                if (ret <= 0) {
                    SSL_free(clients[i].ssl);
                    close(client_socket);
                    clients[i].socket = -1;
                    clients[i].ssl = NULL;
                    log_security("SSL handshake failed", clients[i].client_ip);
                    return NULL;
                }
                
                log_connection("SSL connection established", clients[i].client_ip, client_socket);
            }
            
            send_response(&clients[i], "+OK POP3 server ready\r\n");
            return &clients[i];
        }
    }
    
    close(client_socket);
    return NULL;
}

void handle_client_data(Client *client) {
    char buffer[BUFFER_SIZE];
    int bytes_received = receive_data(client, buffer, BUFFER_SIZE - 1);
    
    if (bytes_received <= 0) {
        if (client->ssl) {
            SSL_shutdown(client->ssl);
            SSL_free(client->ssl);
        }
        close(client->socket);
        log_connection("Client disconnected", client->client_ip, client->socket);
        client->socket = -1;
        client->authenticated = 0;
        client->using_ssl = 0;
        client->ssl = NULL;
        return;
    }
    
    buffer[bytes_received] = '\0';
    process_client_command(client, buffer);
}

void drop_privileges() {
    struct passwd *pw = getpwnam("nobody");
    if (pw == NULL) {
        fprintf(stderr, "Warning: Could not drop privileges\n");
        return;
    }
    
    if (setgid(pw->pw_gid) != 0 || setuid(pw->pw_uid) != 0) {
        fprintf(stderr, "Warning: Failed to drop privileges\n");
    }
}

void create_server_socket(int port, int *server_fd) {
    *server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (*server_fd < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    int opt_val = 1;
    setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(*server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    
    if (listen(*server_fd, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
}

void generate_self_signed_cert() {
    char command[1024];
    snprintf(command, sizeof(command),
        "openssl req -x509 -newkey rsa:2048 -keyout %s -out %s -days 365 -nodes "
        "-subj '/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost'",
        security_config.key_file, security_config.cert_file);
    
    printf("Generating self-signed certificate...\n");
    printf("Running: %s\n", command);
    
    if (system(command) == 0) {
        printf("Certificate generated successfully!\n");
    } else {
        printf("Failed to generate certificate. Please run manually:\n%s\n", command);
    }
}

void sigint_handler(int sig) {
    printf("\nShutting down server...\n");
    close(server_socket);
    if (ssl_server_socket > 0) close(ssl_server_socket);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1) {
            if (clients[i].ssl) {
                SSL_shutdown(clients[i].ssl);
                SSL_free(clients[i].ssl);
            }
            close(clients[i].socket);
        }
    }
    
    cleanup_ssl();
    exit(0);
}

int main(int argc, char *argv[]) {
    int opt;
    int generate_cert = 0;
    
    while ((opt = getopt(argc, argv, "p:l:c:k:g")) != -1) {
        switch (opt) {
            case 'p':
                security_config.allow_plaintext = atoi(optarg);
                break;
            case 'c':
                strncpy(security_config.cert_file, optarg, sizeof(security_config.cert_file) - 1);
                break;
            case 'k':
                strncpy(security_config.key_file, optarg, sizeof(security_config.key_file) - 1);
                break;
            case 'g':
                generate_cert = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p 0|1] [-c cert_file] [-k key_file] [-g]\n", argv[0]);
                fprintf(stderr, "  -p 0|1: Allow plaintext connections (default: 1)\n");
                fprintf(stderr, "  -c file: Certificate file path\n");
                fprintf(stderr, "  -k file: Private key file path\n");
                fprintf(stderr, "  -g: Generate self-signed certificate\n");
                exit(1);
        }
    }
    
    // Generate certificate if requested
    if (generate_cert) {
        generate_self_signed_cert();
    }
    
    // Initialize SSL
    init_ssl();
    
    // Initialize clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
        clients[i].authenticated = 0;
        clients[i].using_ssl = 0;
        clients[i].ssl = NULL;
    }
    
    // Create server sockets
    create_server_socket(POP3_PORT, &server_socket);
    
    // Create SSL server socket
    create_server_socket(POP3S_PORT, &ssl_server_socket);
    
    // Drop privileges after binding to ports
    drop_privileges();
    
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
    printf("SSL-enabled POP3 server started\n");
    printf("Listening on ports:\n");
    if (security_config.allow_plaintext) {
        printf("- Port 110 (POP3 with STARTTLS)\n");
    }
    printf("- Port 995 (POP3S - direct SSL)\n");
    printf("Certificate: %s\n", security_config.cert_file);
    printf("Private key: %s\n", security_config.key_file);
    printf("\nSecurity features:\n");
    printf("- SSL/TLS encryption support\n");
    printf("- STARTTLS support\n");
    printf("- Input validation\n");
    printf("- Connection timeout\n");
    printf("- IP filtering\n");
    printf("- Login attempt limits\n");
    printf("- Activity logging\n");
    
    fd_set read_fds;
    int max_fd = (server_socket > ssl_server_socket) ? server_socket : ssl_server_socket;
    time_t last_timeout_check = 0;
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        if (ssl_server_socket > 0) {
            FD_SET(ssl_server_socket, &read_fds);
        }
        
        max_fd = server_socket;
        if (ssl_server_socket > max_fd) max_fd = ssl_server_socket;
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket > max_fd) {
                max_fd = clients[i].socket;
            }
            if (clients[i].socket != -1) {
                FD_SET(clients[i].socket, &read_fds);
            }
        }
        
        struct timeval timeout = {5, 0};
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }
        
        // Check timeouts
        time_t now = time(NULL);
        if (now - last_timeout_check > 30) {
            check_timeouts();
            last_timeout_check = now;
        }
        
        // Accept new connections
        if (FD_ISSET(server_socket, &read_fds) && security_config.allow_plaintext) {
            accept_new_connection(server_socket, 0);
        }
        
        if (FD_ISSET(ssl_server_socket, &read_fds) && ssl_server_socket > 0) {
            accept_new_connection(ssl_server_socket, 1);
        }
        
        // Handle client data
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket != -1 && FD_ISSET(clients[i].socket, &read_fds)) {
                handle_client_data(&clients[i]);
            }
        }
    }
    
    return 0;
}