#include <signal.h>

#include "server/server.h"

DtlsServer server = {0};

static void interrupt_handler(int _) {
    (void)_;
    server.isRunning = 0;
}

int main(int argc, char** argv)
{
    signal(SIGINT, interrupt_handler);

    const int port = 8443;
    const unsigned int tablesize = 100;
    const char* cipher = "TLS_RSA_WITH_AES_128_GCM_SHA256";
    const char* certChain = "certs/bundle.pem";
    const char* certFile = "certs/clientC.crt";
    const char* privateKey = "certs/clientC.key";

#if WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    server_init(&server, cipher, certChain, certFile, privateKey, SSL_VERIFY_NONE);
    server_connection_setup(&server, port, tablesize, (void *(*)(void *)) &server_connection_free);
    server_connection_loop(&server);
    server_free(&server);

#if WIN32
    WSACleanup();
#endif

    return 0;
}