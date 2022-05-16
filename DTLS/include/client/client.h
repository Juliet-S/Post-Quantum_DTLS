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

void client_init(DtlsClient* client, const char* clientCert, const char* clientKey);
int client_connection_setup(DtlsClient* client, const char* address, int port);
void client_connection_loop(DtlsClient* client);

int client_recv(DtlsClient* client, char* buffer, int size);
int client_send(DtlsClient* client, char* buffer, int size);

void client_free(DtlsClient* client);

#endif // PQDTLS_CLIENT_H