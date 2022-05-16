#include <openssl/ssl.h>

#include "server/sverify.h"

int sverify_cert(int ok, X509_STORE_CTX *ctx)
{
    // Certificates always valid
    return 1;
}

int sverify_generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
    memcpy(cookie, "123456789", 9);
    *cookie_len = 9;

    return 1;
}

int sverify_cookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
{
    return 1;
}