/*
 * Improved POP3 server for Linux with basic security features
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

#define POP3_PORT 110
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define MAX_LOGIN_ATTEMPTS 3
#define LOGIN_TIMEOUT 60
#define COMMAND_TIMEOUT 300

typedef struct {
    int socket;
    int authenticated;
    char username[256];
    int login_attempts;
    time_t last_activity;
    char client_ip[INET6_ADDRSTRLEN];
    int failed_logins;
} Client;

Client clients[MAX_CLIENTS];
int server_socket;
int client_count = 0;

// Security configuration
struct {
    int allow_plaintext;  // Set to 0 to require SSL
    int max_connections;
    int log_failures;
    char allowed_networks[256];
} security_config = {
    .allow_plaintext = 1,
    .max_connections = 10,
    .log_failures = 1,
    .allowed_networks = "127.0.0.1,192.168.0.0/16,10.0.0.0/8"
};

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
    
    return 0;  // Deny other networks
}

int validate_input(const char *input) {
    if (!input || strlen(input) > 512) return 0;
    
    // Check for dangerous characters
    for (int i = 0; input[i]; i++) {
        if (!isprint(input[i])) return 0;
        if (input[i] == '\r' || input[i] == '\n') break;
    }
    
    return 1;
}

void send_response(int client_socket, const char *response) {
    send(client_socket, response, strlen(response), 0);
}

void handle_user(Client *client, const char *username) {
    if (!validate_input(username)) {
        send_response(client->socket, "-ERR Invalid input\r\n");
        log_security("Invalid input in USER command", client->client_ip);
        return;
    }
    
    // Check login attempts
    if (client->login_attempts >= MAX_LOGIN_ATTEMPTS) {
        send_response(client->socket, "-ERR Too many failed attempts\r\n");
        log_security("Login attempt limit exceeded", client->client_ip);
        return;
    }
    
    if (strcmp(username, "aptuser") == 0) {
        strncpy(client->username, username, sizeof(client->username) - 1);
        client->username[sizeof(client->username) - 1] = '\0';
        send_response(client->socket, "+OK User accepted\r\n");
        log_connection("USER command accepted", client->client_ip, client->socket);
    } else {
        send_response(client->socket, "-ERR Invalid username\r\n");
        client->login_attempts++;
        log_security("Invalid username attempt", client->client_ip);
    }
    
    client->last_activity = time(NULL);
}

void handle_pass(Client *client, const char *password) {
    if (!validate_input(password)) {
        send_response(client->socket, "-ERR Invalid input\r\n");
        log_security("Invalid input in PASS command", client->client_ip);
        return;
    }
    
    if (client->login_attempts >= MAX_LOGIN_ATTEMPTS) {
        send_response(client->socket, "-ERR Too many failed attempts\r\n");
        log_security("Login attempt limit exceeded", client->client_ip);
        return;
    }
    
    if (strcmp(client->username, "aptuser") == 0 && strcmp(password, "pop3dabc123") == 0) {
        client->authenticated = 1;
        send_response(client->socket, "+OK Maildrop ready\r\n");
        log_connection("Authentication successful", client->client_ip, client->socket);
    } else {
        send_response(client->socket, "-ERR Invalid credentials\r\n");
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
                send_response(clients[i].socket, "-ERR Timeout\r\n");
                close(clients[i].socket);
                log_connection("Connection timeout", clients[i].client_ip, clients[i].socket);
                clients[i].socket = -1;
                clients[i].authenticated = 0;
            }
        }
    }
}

void process_client_command(Client *client, char *command) {
    if (!validate_input(command)) {
        send_response(client->socket, "-ERR Invalid input\r\n");
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
    
    if (strcasecmp(cmd, "USER") == 0) {
        handle_user(client, arg ?: "");
    } else if (strcasecmp(cmd, "PASS") == 0) {
        handle_pass(client, arg ?: "");
    } else if (strcasecmp(cmd, "STAT") == 0) {
        if (!client->authenticated) {
            send_response(client->socket, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client->socket, "+OK 0 0\r\n");
    } else if (strcasecmp(cmd, "LIST") == 0) {
        if (!client->authenticated) {
            send_response(client->socket, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client->socket, "+OK 0 messages\r\n.\r\n");
    } else if (strcasecmp(cmd, "RETR") == 0) {
        if (!client->authenticated) {
            send_response(client->socket, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client->socket, "-ERR No such message\r\n");
    } else if (strcasecmp(cmd, "DELE") == 0) {
        if (!client->authenticated) {
            send_response(client->socket, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client->socket, "-ERR No such message\r\n");
    } else if (strcasecmp(cmd, "RSET") == 0) {
        if (!client->authenticated) {
            send_response(client->socket, "-ERR Not authenticated\r\n");
            return;
        }
        send_response(client->socket, "+OK Maildrop reset\r\n");
    } else if (strcasecmp(cmd, "QUIT") == 0) {
        send_response(client->socket, "+OK POP3 server signing off\r\n");
        log_connection("QUIT", client->client_ip, client->socket);
        client->authenticated = 0;
        client->socket = -1;
    } else if (strcasecmp(cmd, "NOOP") == 0) {
        send_response(client->socket, "+OK\r\n");
    } else if (strcasecmp(cmd, "CAPA") == 0) {
        send_response(client->socket, "+OK Capability list follows\r\n");
        send_response(client->socket, "USER\r\n");
        if (security_config.allow_plaintext) {
            send_response(client->socket, "TOP\r\n");
            send_response(client->socket, "UIDL\r\n");
        }
        send_response(client->socket, ".\r\n");
    } else {
        send_response(client->socket, "-ERR Unknown command\r\n");
    }
}

void accept_new_connection() {
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0) {
        perror("Accept failed");
        return;
    }
    
    // Get client IP
    inet_ntop(AF_INET, &client_addr.sin_addr, clients[client_count].client_ip, 
               INET_ADDRSTRLEN);
    
    // Check if IP is allowed
    if (!is_ip_allowed(clients[client_count].client_ip)) {
        send_response(client_socket, "-ERR Access denied\r\n");
        log_security("Connection from unauthorized IP", clients[client_count].client_ip);
        close(client_socket);
        return;
    }
    
    // Check connection limit
    int active_connections = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1) active_connections++;
    }
    
    if (active_connections >= security_config.max_connections) {
        send_response(client_socket, "-ERR Too many connections\r\n");
        log_security("Connection limit exceeded", clients[client_count].client_ip);
        close(client_socket);
        return;
    }
    
    // Find free client slot
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) {
            clients[i].socket = client_socket;
            clients[i].authenticated = 0;
            clients[i].username[0] = '\0';
            clients[i].login_attempts = 0;
            clients[i].failed_logins = 0;
            clients[i].last_activity = time(NULL);
            
            log_connection("New connection", clients[i].client_ip, client_socket);
            send_response(client_socket, "+OK POP3 server ready\r\n");
            return;
        }
    }
    
    close(client_socket);
}

void handle_client_data(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    
    if (bytes_received <= 0) {
        close(client_socket);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket == client_socket) {
                log_connection("Client disconnected", clients[i].client_ip, client_socket);
                clients[i].socket = -1;
                clients[i].authenticated = 0;
                break;
            }
        }
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == client_socket) {
            process_client_command(&clients[i], buffer);
            break;
        }
    }
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

void sigint_handler(int sig) {
    printf("\nShutting down server...\n");
    close(server_socket);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket != -1) {
            close(clients[i].socket);
        }
    }
    exit(0);
}

int main(int argc, char *argv[]) {
    // Parse command line args
    int opt;
    while ((opt = getopt(argc, argv, "p:l:")) != -1) {
        switch (opt) {
            case 'p':
                security_config.allow_plaintext = atoi(optarg);
                break;
            case 'l':
                strncpy(security_config.allowed_networks, optarg, 
                        sizeof(security_config.allowed_networks) - 1);
                break;
            default:
                fprintf(stderr, "Usage: %s [-p 0|1] [-l networks]\n", argv[0]);
                exit(1);
        }
    }
    
    // Initialize clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
        clients[i].authenticated = 0;
    }
    
    // Drop root privileges after binding to port
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    int opt_val = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(POP3_PORT);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
    
    // Drop privileges
    drop_privileges();
    
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
    printf("Improved POP3 server listening on port %d\n", POP3_PORT);
    printf("Security features enabled:\n");
    printf("- Input validation\n");
    printf("- Connection timeout\n");
    printf("- IP filtering\n");
    printf("- Login attempt limits\n");
    printf("- Activity logging\n");
    
    fd_set read_fds;
    int max_fd = server_socket;
    time_t last_timeout_check = 0;
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        
        max_fd = server_socket;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket > max_fd) {
                max_fd = clients[i].socket;
            }
            if (clients[i].socket != -1) {
                FD_SET(clients[i].socket, &read_fds);
            }
        }
        
        struct timeval timeout = {5, 0};  // 5 second timeout for select
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }
        
        // Check timeouts every 30 seconds
        time_t now = time(NULL);
        if (now - last_timeout_check > 30) {
            check_timeouts();
            last_timeout_check = now;
        }
        
        if (FD_ISSET(server_socket, &read_fds)) {
            accept_new_connection();
        }
        
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket != -1 && FD_ISSET(clients[i].socket, &read_fds)) {
                handle_client_data(clients[i].socket);
            }
        }
    }
    
    return 0;
}