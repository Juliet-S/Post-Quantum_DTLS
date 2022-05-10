#ifndef PQDTLS_SERVER_H
#define PQDTLS_SERVER_H

#if WIN32
 #include <winsock2.h>
 #include <ws2ipdef.h>

typedef int socklen_t;
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
#endif

#include "dtls.h"

#define MAX_PACKET_SIZE 1500

void err(const char* msg);

void init_server(DtlsServer* server, const char* cipher, const char* certChain, const char* certFile, const char* privKey);
void connection_setup(DtlsServer* server, int port, unsigned int connectionTableSize, void* free_func(void *));
int new_socket(const struct sockaddr* bindingAddress);

void connection_loop(DtlsServer* server);

int dtls_server_accept(DtlsServer* server);

#endif // PQDTLS_SERVER_H