#ifndef PQDTLS_VERIFICATION_H
#define PQDTLS_VERIFICATION_H

#include <openssl/ssl.h>

void print_ssl_summary(SSL* con);

int verify_cert(int ok, X509_STORE_CTX *ctx);

int generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len);
int verify_cookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len);

#endif // PQDTLS_VERIFICATION_H