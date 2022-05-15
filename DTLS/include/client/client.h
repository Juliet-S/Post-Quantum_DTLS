#ifndef PQDTLS_CLIENT_H
#define PQDTLS_CLIENT_H

#include <openssl/ssl.h>

#include "dtls.h"

typedef struct dtlsClient_h {
    SSL_CTX* ctx;
    SSL* ssl;
    BIO* bio;
    SockAddress local;
    int socket;
} DtlsClient;

void init_client(DtlsClient* client, const char* clientCert, const char* clientKey);
int connection_setup(DtlsClient* client, const char* address, int port);
void connection_loop(DtlsClient* client);

int client_recv(DtlsClient* client, char* buffer, int size);
int client_send(DtlsClient* client, char* buffer, int size);

void free_client(DtlsClient* client);

#endif // PQDTLS_CLIENT_H