#ifndef PQDTLS_INFO_H
#define PQDTLS_INFO_H

#define WOLFSSL_USER_SETTINGS

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "client/client.h"

void info_print_ssl_summary(WOLFSSL* con);
void info_print_server_summary(DtlsClient* client);

#endif // PQDTLS_INFO_H