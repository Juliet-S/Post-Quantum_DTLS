#ifndef PQDTLS_DTLS_H
#define PQDTLS_DTLS_H

#if WIN32
 #include <WinSock2.h>
 #include <ws2ipdef.h>
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
#endif

#include <openssl/ssl.h>
#include "hashtable.h"

typedef union sockAddress_t {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
} SockAddress;

typedef struct dtlsServer_t {
    int isRunning;
    SSL_CTX* ctx;
    SockAddress local;
    int socket;
    int timeoutSeconds;
    hashtable* connections;
} DtlsServer;

typedef struct dtlsConnection_t {
    SSL* ssl;
    int port;
    char address[INET_ADDRSTRLEN];
} DtlsConnection;

int connection_recv(DtlsConnection* connection, void* buffer, int size);

size_t hash_connection(const char* str, int port);

void free_server(DtlsServer* server);
void free_connection(DtlsConnection* connection);

#endif // PQDTLS_DTLS_H