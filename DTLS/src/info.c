#include "info.h"

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

void info_print_ssl_summary(SSL* con) {
    const SSL_CIPHER* c;
    X509 *peer;

    printf("\tProtocol version: %s\n", SSL_get_version(con));
    c = SSL_get_current_cipher(con);
    printf("\tCiphersuite: %s\n", SSL_CIPHER_get_name(c));

    peer = SSL_get_peer_certificate(con);
    if (peer != NULL) {
        int nid;

        printf("\tPeer certificate: ");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(peer), 2, 0);
        printf("\n");
        if (SSL_get_peer_signature_nid(con, &nid))
            printf("\t\tHash used: %s\n", OBJ_nid2sn(nid));
        if (SSL_get_peer_signature_type_nid(con, &nid))
            printf("\t\tSignature type: %s\n", get_sigtype(nid));
    } else {
        printf("\tNo peer certificate\n");
    }
}

void info_print_server_summary(DtlsClient* client)
{
    BIO* bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509 *peer = NULL;
    STACK_OF(X509) *sk;
    EVP_PKEY *public_key;
    int i;

    sk = SSL_get_peer_cert_chain(client->ssl);
    if (sk != NULL) {
        BIO_printf(bio, "---\nCertificate chain\n");
        for (i = 0; i < sk_X509_num(sk); i++) {
            BIO_printf(bio, "%2d subject:", i);
            X509_NAME_print_ex(bio, X509_get_subject_name(sk_X509_value(sk, i)), 0, XN_FLAG_ONELINE);
            BIO_puts(bio, "\n");
            BIO_printf(bio, "   issuer:");
            X509_NAME_print_ex(bio, X509_get_issuer_name(sk_X509_value(sk, i)), 0, XN_FLAG_ONELINE);
            BIO_puts(bio, "\n");
            public_key = X509_get_pubkey(sk_X509_value(sk, i));
            if (public_key != NULL) {
                BIO_printf(bio, "   a:PKEY: %s, %d (bit); sigalg: %s\n",
                           OBJ_nid2sn(EVP_PKEY_get_base_id(public_key)),
                           EVP_PKEY_get_bits(public_key),
                           OBJ_nid2sn(X509_get_signature_nid(sk_X509_value(sk, i))));
                EVP_PKEY_free(public_key);
            }
            BIO_puts(bio, "\n");
        }

        BIO_printf(bio, "---\n");
        peer = SSL_get0_peer_certificate(client->ssl);
        if (peer != NULL) {
            BIO_printf(bio, "Server certificate\n");
            PEM_write_bio_X509(bio, peer);
        } else {
            BIO_printf(bio, "no peer certificate available\n");
        }
    }

    BIO_free(bio);
}
