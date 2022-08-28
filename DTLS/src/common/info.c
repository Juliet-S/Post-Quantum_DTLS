#include <wolfssl/ssl.h>
#include "common/info.h"

void info_print_ssl_summary(WOLFSSL* con) {
    printf("\tProtocol version: %s\n", wolfSSL_get_version(con));
    printf("\tCiphersuite: %s\n", wolfSSL_get_cipher(con));
    printf("\tCurve: %s\n", wolfSSL_get_curve_name(con));
}

void info_print_connection_summary(WOLFSSL* ssl)
{
    WOLFSSL_X509* certificate = wolfSSL_get_peer_certificate(ssl);

    char* issuer = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(certificate), 0, 0);
    char* subject = wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name(certificate), 0, 0);

    printf("Peer Certificate Settings:\n");
    printf("\tIssuer: %s\n", issuer);
    printf("\tSubject Name: %s\n", subject);
    printf("\tPublic Key OID: %d\n", wolfSSL_X509_get_pubkey_type(certificate));

    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);
    XFREE(issuer,  0, DYNAMIC_TYPE_OPENSSL);
}
