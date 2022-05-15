#ifndef PQDTLS_CVERIFY_H
#define PQDTLS_CVERIFY_H

#include <openssl/ssl.h>

#include "client/client.h"

void print_server_info(DtlsClient* client);

#endif // PQDTLS_CVERIFY_H