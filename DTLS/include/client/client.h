#ifndef PQDTLS_CLIENT_H
#define PQDTLS_CLIENT_H

typedef struct dtlsClient_h {
    SSL_CTX* ctx;
} DtlsClient;

void init_client(DtlsClient* client, const char* clientCert, const char* clientKey);
int connection_setup(DtlsClient* client, const char* address, int port);

void free_client(DtlsClient* client);

#endif // PQDTLS_CLIENT_H