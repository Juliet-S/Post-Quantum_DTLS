#ifndef PQDTLS_INFO_H
#define PQDTLS_INFO_H

#include <wolfssl/ssl.h>

void info_print_ssl_summary(WOLFSSL* con);
void info_print_connection_summary(WOLFSSL* ssl);

#endif // PQDTLS_INFO_H