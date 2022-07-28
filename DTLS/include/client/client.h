#ifndef PQDTLS_CLIENT_H
#define PQDTLS_CLIENT_H

#define WOLFSSL_USER_SETTINGS

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "dtls.h"

typedef struct dtlsClient_h {
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    SockAddress remote;
    int socket;
} DtlsClient;

void client_init(DtlsClient* client, const char* certChain, const char* clientCert, const char* clientKey, int mode);
int client_connection_setup(DtlsClient* client, const char* address, int port);
void client_connection_loop(DtlsClient* client);

void client_get_connection_info(DtlsClient* client, char* address, int* port);

void client_free(DtlsClient* client);

#endif // PQDTLS_CLIENT_H