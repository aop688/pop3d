/*
 * Simplified POP3 server for Linux with fixed credentials
 * User: aptuser, Password: pop3dabc123
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

#define POP3_PORT 110
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define FIXED_USER "aptuser"
#define FIXED_PASS "pop3dabc123"

typedef struct {
    int socket;
    int authenticated;
    char username[256];
    char current_dir[512];
} Client;

Client clients[MAX_CLIENTS];
int server_socket;
int client_count = 0;

void log_message(const char *message) {
    time_t now;
    time(&now);
    printf("[%.*s] %s\n", 24, ctime(&now), message);
}

void send_response(int client_socket, const char *response) {
    send(client_socket, response, strlen(response), 0);
    printf("Sent: %s", response);
}

void handle_user(Client *client, const char *username) {
    if (strcmp(username, FIXED_USER) == 0) {
        strcpy(client->username, username);
        send_response(client->socket, "+OK User accepted\r\n");
    } else {
        send_response(client->socket, "-ERR Invalid username\r\n");
    }
}

void handle_pass(Client *client, const char *password) {
    if (strcmp(client->username, FIXED_USER) == 0 && strcmp(password, FIXED_PASS) == 0) {
        client->authenticated = 1;
        send_response(client->socket, "+OK Maildrop ready\r\n");
    } else {
        send_response(client->socket, "-ERR Invalid credentials\r\n");
    }
}

void handle_stat(Client *client) {
    if (!client->authenticated) {
        send_response(client->socket, "-ERR Not authenticated\r\n");
        return;
    }
    
    // Simple maildir check
    char maildir_path[512];
    snprintf(maildir_path, sizeof(maildir_path), "%s/Maildir/new", getenv("HOME") ?: "/var/mail");
    
    DIR *dir = opendir(maildir_path);
    int count = 0;
    long total_size = 0;
    
    if (dir) {
        struct dirent *entry;
        struct stat st;
        char filepath[1024];
        
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                snprintf(filepath, sizeof(filepath), "%s/%s", maildir_path, entry->d_name);
                if (stat(filepath, &st) == 0) {
                    count++;
                    total_size += st.st_size;
                }
            }
        }
        closedir(dir);
    }
    
    char response[256];
    snprintf(response, sizeof(response), "+OK %d %ld\r\n", count, total_size);
    send_response(client->socket, response);
}

void handle_list(Client *client, const char *msg_num) {
    if (!client->authenticated) {
        send_response(client->socket, "-ERR Not authenticated\r\n");
        return;
    }
    
    send_response(client->socket, "+OK Mail listing follows\r\n");
    
    char maildir_path[512];
    snprintf(maildir_path, sizeof(maildir_path), "%s/Maildir/new", getenv("HOME") ?: "/var/mail");
    
    DIR *dir = opendir(maildir_path);
    if (dir) {
        struct dirent *entry;
        struct stat st;
        char filepath[1024];
        int msg_count = 0;
        
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                msg_count++;
                snprintf(filepath, sizeof(filepath), "%s/%s", maildir_path, entry->d_name);
                if (stat(filepath, &st) == 0) {
                    char response[256];
                    snprintf(response, sizeof(response), "%d %ld\r\n", msg_count, st.st_size);
                    send_response(client->socket, response);
                }
            }
        }
        closedir(dir);
    }
    
    send_response(client->socket, ".\r\n");
}

void handle_retr(Client *client, const char *msg_num) {
    if (!client->authenticated) {
        send_response(client->socket, "-ERR Not authenticated\r\n");
        return;
    }
    
    send_response(client->socket, "+OK Message follows\r\n");
    
    // For simplicity, send a dummy message
    send_response(client->socket, "From: test@example.com\r\n");
    send_response(client->socket, "To: user@example.com\r\n");
    send_response(client->socket, "Subject: Test Message\r\n");
    send_response(client->socket, "\r\n");
    send_response(client->socket, "This is a test message.\r\n");
    send_response(client->socket, ".\r\n");
}

void handle_dele(Client *client, const char *msg_num) {
    if (!client->authenticated) {
        send_response(client->socket, "-ERR Not authenticated\r\n");
        return;
    }
    
    send_response(client->socket, "+OK Message deleted\r\n");
}

void handle_rset(Client *client) {
    if (!client->authenticated) {
        send_response(client->socket, "-ERR Not authenticated\r\n");
        return;
    }
    
    send_response(client->socket, "+OK Maildrop reset\r\n");
}

void handle_quit(Client *client) {
    send_response(client->socket, "+OK POP3 server signing off\r\n");
    client->authenticated = 0;
    client->socket = -1;
}

void handle_noop(Client *client) {
    if (!client->authenticated) {
        send_response(client->socket, "-ERR Not authenticated\r\n");
        return;
    }
    
    send_response(client->socket, "+OK\r\n");
}

void handle_capa(Client *client) {
    send_response(client->socket, "+OK Capability list follows\r\n");
    send_response(client->socket, "USER\r\n");
    send_response(client->socket, "TOP\r\n");
    send_response(client->socket, "UIDL\r\n");
    send_response(client->socket, ".\r\n");
}

void process_client_command(Client *client, char *command) {
    printf("Received from client %d: %s", client->socket, command);
    
    char *cmd = strtok(command, " \r\n");
    char *arg = strtok(NULL, "\r\n");
    
    if (cmd == NULL) return;
    
    if (strcasecmp(cmd, "USER") == 0) {
        handle_user(client, arg ?: "");
    } else if (strcasecmp(cmd, "PASS") == 0) {
        handle_pass(client, arg ?: "");
    } else if (strcasecmp(cmd, "STAT") == 0) {
        handle_stat(client);
    } else if (strcasecmp(cmd, "LIST") == 0) {
        handle_list(client, arg);
    } else if (strcasecmp(cmd, "RETR") == 0) {
        handle_retr(client, arg);
    } else if (strcasecmp(cmd, "DELE") == 0) {
        handle_dele(client, arg);
    } else if (strcasecmp(cmd, "RSET") == 0) {
        handle_rset(client);
    } else if (strcasecmp(cmd, "QUIT") == 0) {
        handle_quit(client);
    } else if (strcasecmp(cmd, "NOOP") == 0) {
        handle_noop(client);
    } else if (strcasecmp(cmd, "CAPA") == 0) {
        handle_capa(client);
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
    
    // Find free client slot
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == -1) {
            clients[i].socket = client_socket;
            clients[i].authenticated = 0;
            clients[i].username[0] = '\0';
            
            printf("New connection from %s:%d on socket %d\n", 
                   inet_ntoa(client_addr.sin_addr), 
                   ntohs(client_addr.sin_port), 
                   client_socket);
            
            send_response(client_socket, "+OK POP3 server ready\r\n");
            return;
        }
    }
    
    // No free slots
    close(client_socket);
}

void handle_client_data(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    
    if (bytes_received <= 0) {
        // Client disconnected
        close(client_socket);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket == client_socket) {
                clients[i].socket = -1;
                clients[i].authenticated = 0;
                printf("Client on socket %d disconnected\n", client_socket);
                break;
            }
        }
        return;
    }
    
    buffer[bytes_received] = '\0';
    
    // Find client and process command
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket == client_socket) {
            process_client_command(&clients[i], buffer);
            break;
        }
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

int main() {
    // Initialize clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = -1;
        clients[i].authenticated = 0;
    }
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
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
    
    // Set up signal handler
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    
    printf("POP3 server listening on port %d\n", POP3_PORT);
    printf("Fixed credentials - User: %s, Password: %s\n", FIXED_USER, FIXED_PASS);
    
    fd_set read_fds;
    int max_fd = server_socket;
    
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
        
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            perror("Select error");
            break;
        }
        
        // Check for new connections
        if (FD_ISSET(server_socket, &read_fds)) {
            accept_new_connection();
        }
        
        // Check for client data
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket != -1 && FD_ISSET(clients[i].socket, &read_fds)) {
                handle_client_data(clients[i].socket);
            }
        }
    }
    
    return 0;
}