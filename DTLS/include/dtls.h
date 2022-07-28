#ifndef PQDTLS_DTLS_H
#define PQDTLS_DTLS_H

#if WIN32
 #include <WinSock2.h>
 #include <ws2ipdef.h>
 typedef int socklen_t;
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
#endif

#define CONNECTION_MTU_SIZE 1500
#define MAX_PACKET_SIZE 1200

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include "hashtable.h"

typedef union sockAddress_t {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
} SockAddress;

void err(const char* msg);
int check_ssl(WOLFSSL* ssl, char* buffer, int code);
int dtls_recv(WOLFSSL* ssl, char* buffer, int size);
int dtls_send(WOLFSSL* ssl, char* buffer, int size);

int new_socket(const struct sockaddr* bindingAddress);

size_t hash_connection(const char* str, int port);

#endif // PQDTLS_DTLS_H