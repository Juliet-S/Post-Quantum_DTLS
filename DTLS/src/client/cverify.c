#include "client/cverify.h"

void print_server_info(DtlsClient* client)
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
