#ifndef PQDTLS_SERVER_H
#define PQDTLS_SERVER_H

#if WIN32
 #include <winsock2.h>
 #include <ws2ipdef.h>
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
#endif

#if WIN32
    #define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "common/dtls.h"

typedef struct dtlsServer_t {
    int isRunning;
    WOLFSSL_CTX* ctx;
    SockAddress local;
    int socket;
    int timeoutSeconds;
    hashtable* connections;
} DtlsServer;

typedef struct dtlsConnection_t {
    WOLFSSL* ssl;
    int port;
    char address[INET_ADDRSTRLEN];
} DtlsConnection;

void server_init(DtlsServer* server, const char* ciphers, const char* certChain, const char* certFile, const char* privKey, int mode);
void server_connection_setup(DtlsServer* server, int port, unsigned int connectionTableSize, void* free_func(void *));

void server_connection_loop(DtlsServer* server);

int server_dtls_accept(DtlsServer* server, struct sockaddr* clientSockAddr);

void server_free(DtlsServer* server);
void server_connection_free(DtlsConnection* connection);

#endif // PQDTLS_SERVER_H