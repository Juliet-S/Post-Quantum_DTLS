#ifndef PQDTLS_INFO_H
#define PQDTLS_INFO_H

#include <openssl/ssl.h>

#include "client/client.h"

void info_print_ssl_summary(SSL* con);
void info_print_server_summary(DtlsClient* client);

#endif // PQDTLS_INFO_H