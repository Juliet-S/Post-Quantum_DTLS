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

#include "dtls.h"

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

void init_server(DtlsServer* server, const char* cipher, const char* certChain, const char* certFile, const char* privKey, int mode);
void connection_setup(DtlsServer* server, int port, unsigned int connectionTableSize, void* free_func(void *));

void connection_loop(DtlsServer* server);

int dtls_server_accept(DtlsServer* server);

int connection_recv(DtlsConnection* connection, void* buffer, int size);
void free_server(DtlsServer* server);
void free_connection(DtlsConnection* connection);

#endif // PQDTLS_SERVER_H