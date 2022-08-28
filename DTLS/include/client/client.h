#ifndef PQDTLS_CLIENT_H
#define PQDTLS_CLIENT_H

#include "common/dtls.h"

typedef struct dtlsClient_h {
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    SockAddress remote;
    int socket;
} DtlsClient;

void client_init(DtlsClient* client, const char* rootChain, const char* clientChain, const char* clientKey);
int client_connection_setup(DtlsClient* client, const char* address, int port, int group);
void client_connection_loop(DtlsClient* client);

void client_get_connection_info(DtlsClient* client, char* address, int* port);

void client_free(DtlsClient* client);

#endif // PQDTLS_CLIENT_H