#include <wolfssl/ssl.h>
#include "common/info.h"

void info_print_ssl_summary(WOLFSSL* con) {
    WOLFSSL_CIPHER* cipher = wolfSSL_get_current_cipher(con);
    const char* cipherName = wolfSSL_CIPHER_get_name(cipher);

    printf("\tProtocol version: %s\n", wolfSSL_get_version(con));
    printf("\tCiphersuite: %s\n", cipherName);
}

void info_print_connection_summary(WOLFSSL* ssl)
{
    WOLFSSL_X509* certificate = wolfSSL_get_peer_certificate(ssl);

    char* issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(certificate), 0, 0);
    char* subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(certificate), 0, 0);

    printf("Peer Certificate Settings:\n");
    printf("\tIssuer: %s\n", issuer);
    printf("\tSubject Name: %s\n", subject);

    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
}
