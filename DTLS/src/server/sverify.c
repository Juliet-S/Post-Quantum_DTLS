//#include <openssl/ssl.h>
//
//#include "server/sverify.h"
//
//int sverify_generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
//{
//    memcpy(cookie, "123456789", 9);
//    *cookie_len = 9;
//
//    return 1;
//}
//
//int sverify_cookie(SSL* ssl, const unsigned char* cookie, unsigned int cookie_len)
//{
//    return 1;
//}