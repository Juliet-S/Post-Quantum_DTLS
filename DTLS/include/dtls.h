#ifndef PQDTLS_DTLS_H
#define PQDTLS_DTLS_H

#if WIN32
 #include <WinSock2.h>
 #include <ws2ipdef.h>
#else
 #include <unistd.h>
 #include <sys/socket.h>
#endif

#include <openssl/ssl.h>
#include "hashtable.h"

//Maybe
typedef union sockAddress_t {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
} sockAddress;

typedef struct dtlsServer_t {
    int isRunning;
    SSL_CTX* ctx;
    sockAddress local;
    int socket;
    int timeoutSeconds;
    hashtable* connections;
} dtlsServer;

typedef struct dtlsClient_t {
    SSL *ssl;
    int port;
    char address[INET_ADDRSTRLEN];
} dtlsClient;

int client_recv(dtlsClient* client, void* buffer, int size);

size_t hash_connection(const char* str, int port);

void free_server(dtlsServer* server);
void free_client(dtlsClient* client);

#endif // PQDTLS_DTLS_H