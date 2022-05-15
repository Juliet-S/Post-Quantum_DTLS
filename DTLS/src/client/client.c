#include <openssl/ssl.h>
#include <memory.h>

#include "client/client.h"
#include "dtls.h"

/**
 * Print error message and exit program
 *
 * @param msg Error message
 */
void err(const char* msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(EXIT_FAILURE);
}

void init_client(DtlsClient* client, const char* clientCert, const char* clientKey)
{
    memset(client, 0, sizeof(DtlsClient));

    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init(); /* initialize library */

    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    int usingCert = 1;
    if (!SSL_CTX_use_certificate_file(ctx, clientCert, SSL_FILETYPE_PEM)) {
        printf("Client certificate not found\n");
        usingCert = 0;
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, clientKey, SSL_FILETYPE_PEM)) {
        printf("Client private key not found\n");
        usingCert = 0;
    }

    if (usingCert && !SSL_CTX_check_private_key (ctx))
        err("Invalid private key");

    SSL_CTX_set_read_ahead(ctx, 1);
    client->ctx = ctx;
}

/**
 * Connects a client to a specified server
 * @param client
 * @param address
 * @param port
 * @return 0 on success, nonzero otherwise
 */
int connection_setup(DtlsClient* client, const char* address, int port)
{
    int ret = 0;
    SSL* ssl = SSL_new(client->ctx);

    return ret;
}

void free_client(DtlsClient* client)
{

}