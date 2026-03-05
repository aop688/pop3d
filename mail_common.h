/*
 * Copyright (c) 2024 MailD - Common Library for POP3/SMTP Servers
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#ifndef MAIL_COMMON_H
#define MAIL_COMMON_H

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
#include <pwd.h>
#include <syslog.h>
#include <ctype.h>
#include <stdarg.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

/* Check for PAM headers */
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
  #if defined(HAVE_SECURITY_PAM_APPL_H) || defined(__linux__)
    #include <security/pam_appl.h>
    #define HAVE_PAM 1
  #else
    #define HAVE_PAM 0
  #endif
#endif

#if !HAVE_PAM
  #include <shadow.h>
  #include <crypt.h>
#endif

/* ============================================================================
 * Common constants
 * ============================================================================ */
#define BUFFER_SIZE		4096
#define MAX_CLIENTS		50
#define MAX_LINE_LENGTH		1024
#define CONFIG_FILE		"/etc/maild.conf"
#define LOGIN_TIMEOUT		60
#define COMMAND_TIMEOUT		300
#define DATA_TIMEOUT		600

/* ============================================================================
 * Client base structure - common fields for both protocols
 * ============================================================================ */
typedef struct ClientBase {
    int			socket;
    SSL			*ssl;
    int			using_ssl;
    int			authenticated;
    char		username[256];
    time_t		last_activity;
    char		client_ip[INET6_ADDRSTRLEN];
} ClientBase;

/* ============================================================================
 * Global configuration - shared between POP3 and SMTP
 * ============================================================================ */
typedef struct GlobalConfig {
    int			allow_plaintext;
    int			max_connections;
    int			log_auth;
    int			ipv6_enabled;
    
    /* POP3 ports */
    int			pop3_port;
    int			pop3s_port;
    int			pop3_enabled;
    
    /* SMTP ports */
    int			smtp_port;
    int			submission_port;
    int			smtps_port;
    int			smtp_enabled;
    
    /* SMTP specific */
    int			require_auth;
    size_t		max_msg_size;
    char		hostname[256];
    int			relay_only;
    int			timeout_data;
    
    /* Common timeouts */
    int			timeout_login;
    int			timeout_command;
    
    /* SSL paths */
    char		cert_file[PATH_MAX];
    char		key_file[PATH_MAX];
    
    /* Mail storage */
    char		maildir_base[PATH_MAX];
} GlobalConfig;

/* ============================================================================
 * Server context - holds server state
 * ============================================================================ */
typedef struct ServerContext {
    SSL_CTX		*ssl_ctx;
    volatile int	running;
    const char		*service_name;  /* "pop3d" or "smtpd" for PAM */
    const char		*protocol_name; /* "POP3" or "SMTP" for logging */
} ServerContext;

/* ============================================================================
 * Connection management - Refactored abstraction
 * ============================================================================ */

/* Server socket types */
#define SOCK_TYPE_PLAIN		0
#define SOCK_TYPE_SSL		1
#define SOCK_TYPE_MAX		8

typedef struct ServerSocket {
    int			fd;
    int			port;
    int			is_ipv6;
    int			is_ssl;
    const char		*name;          /* "POP3", "POP3S", "SMTP", etc. */
} ServerSocket;

typedef struct ServerSocketSet {
    ServerSocket	sockets[SOCK_TYPE_MAX];
    int			count;
} ServerSocketSet;

/* Client pool for managing client slots */
typedef struct ClientPool {
    void		*clients;       /* Array of protocol-specific clients */
    size_t		client_size;    /* Size of each client structure */
    int			max_clients;
    int			(*is_slot_free)(void *client);  /* Callback to check if slot is free */
    void		(*init_client)(void *client);   /* Callback to initialize client */
} ClientPool;

/* Protocol handler callbacks */
typedef struct ProtocolHandler {
    /* Send greeting to new client */
    void (*send_greeting)(ClientBase *client);
    
    /* Process data from client, returns 0 to keep connection, -1 to close */
    int (*process_data)(void *client);
    
    /* Check if client timed out, returns 1 if timed out, 0 otherwise */
    int (*check_timeout)(void *client, time_t now);
    
    /* Get timeout for client based on state */
    int (*get_timeout)(void *client);
    
    /* Clean up client resources */
    void (*cleanup_client)(void *client);
    
    /* Handle timeout - send message and cleanup */
    void (*handle_timeout)(void *client);
} ProtocolHandler;

/* Main server structure */
typedef struct MailServer {
    ServerSocketSet	ss_set;
    ClientPool		*pool;
    ProtocolHandler	*handler;
    time_t		last_timeout_check;
} MailServer;

/* ============================================================================
 * External globals
 * ============================================================================ */
extern GlobalConfig g_config;
extern ServerContext g_ctx;

/* ============================================================================
 * Authentication
 * ============================================================================ */
int authenticate_user(const char *username, const char *password, const char *service);

/* ============================================================================
 * Logging
 * ============================================================================ */
void log_connection(const char *message, const char *client_ip, int socket);
void log_security(const char *event, const char *client_ip, const char *details);
void log_error(const char *fmt, ...);

/* ============================================================================
 * SSL/TLS
 * ============================================================================ */
int init_ssl(const char *cert_file, const char *key_file);
void cleanup_ssl(void);

/* ============================================================================
 * Network I/O
 * ============================================================================ */
int send_response(ClientBase *client, const char *response);
int receive_line(ClientBase *client, char *buffer, int size);
int receive_data(ClientBase *client, char *buffer, int size);

/* ============================================================================
 * Input validation
 * ============================================================================ */
int validate_input(const char *input, size_t max_len);

/* ============================================================================
 * String utilities
 * ============================================================================ */
void str_trim(char *str);
int parse_email_address(const char *addr, char *user, size_t user_size,
                        char *domain, size_t domain_size);

/* ============================================================================
 * Socket creation
 * ============================================================================ */
int create_server_socket(int port, int is_ipv6);

/* ============================================================================
 * Connection management (Refactored)
 * ============================================================================ */

/* Server socket management */
void ss_init(ServerSocketSet *ss_set);
int ss_add_socket(ServerSocketSet *ss_set, int port, int is_ipv6, int is_ssl, const char *name);
void ss_close_all(ServerSocketSet *ss_set);
int ss_get_max_fd(ServerSocketSet *ss_set);
void ss_build_fdset(ServerSocketSet *ss_set, fd_set *fds);
int ss_accept_client(ServerSocketSet *ss_set, fd_set *fds, ClientBase *client);

/* Client pool management */
ClientPool* pool_create(size_t client_size, int max_clients,
                        int (*is_slot_free)(void *client),
                        void (*init_client)(void *client));
void pool_destroy(ClientPool *pool);
void* pool_find_free_slot(ClientPool *pool);
int pool_is_full(ClientPool *pool);
void pool_cleanup_all(ClientPool *pool, ProtocolHandler *handler);

/* Connection handling */
int accept_client_connection(int server_fd, ClientBase *client, int is_ssl, int is_ipv6);
void close_client_connection(ClientBase *client, ProtocolHandler *handler, void *protocol_client);
int perform_ssl_handshake(ClientBase *client);

/* Main server loop */
int server_init(MailServer *server, ClientPool *pool, ProtocolHandler *handler);
int server_run(MailServer *server);
void server_shutdown(MailServer *server);

/* ============================================================================
 * Configuration
 * ============================================================================ */
int parse_config(const char *filename);

/* ============================================================================
 * Certificate generation
 * ============================================================================ */
int generate_self_signed_cert(const char *cert_file, const char *key_file,
                               const char *cn_name);

/* ============================================================================
 * Daemonization
 * ============================================================================ */
void daemonize(void);

/* ============================================================================
 * Signal handling
 * ============================================================================ */
void setup_signal_handlers(void);
void signal_handler(int sig);

/* ============================================================================
 * Utility
 * ============================================================================ */
int is_local_user(const char *user);

/* ============================================================================
 * Timeout handling helpers
 * ============================================================================ */
int check_client_timeout(ClientBase *client, time_t now, int timeout_seconds);

#endif /* MAIL_COMMON_H */
