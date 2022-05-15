#include <openssl/ssl.h>

#include "server/verification.h"

static const char* get_sigtype(int nid) {
    switch (nid) {
        case EVP_PKEY_RSA:
            return "RSA";

        case EVP_PKEY_RSA_PSS:
            return "RSA-PSS";

        case EVP_PKEY_DSA:
            return "DSA";

        case EVP_PKEY_EC:
            return "ECDSA";

        case NID_ED25519:
            return "Ed25519";

        case NID_ED448:
            return "Ed448";

        case NID_id_GostR3410_2001:
            return "gost2001";

        case NID_id_GostR3410_2012_256:
            return "gost2012_256";

        case NID_id_GostR3410_2012_512:
            return "gost2012_512";

        default:
            return NULL;
    }
}

void print_ssl_summary(SSL* s) {
    const SSL_CIPHER *c;
    X509 *peer;

    printf("\tProtocol version: %s\n", SSL_get_version(s));
    c = SSL_get_current_cipher(s);
    printf("\tCiphersuite: %s\n", SSL_CIPHER_get_name(c));

    peer = SSL_get_peer_certificate(s);
    if (peer != NULL) {
        int nid;

        printf("\tPeer certificate: ");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(peer), 2, 0);
        printf("\n");
        if (SSL_get_peer_signature_nid(s, &nid))
            printf("\t\tHash used: %s\n", OBJ_nid2sn(nid));
        if (SSL_get_peer_signature_type_nid(s, &nid))
            printf("\t\tSignature type: %s\n", get_sigtype(nid));
    } else {
        printf("\tNo peer certificate\n");
    }
}

int verify_cert(int ok, X509_STORE_CTX *ctx)
{
    // Certificates always valid
    return 1;
}

int generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
    memcpy(cookie, "123456789", 9);
    *cookie_len = 9;

    return 1;
}

int verify_cookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
{
    return 1;
}