#include <signal.h>

#include "server.h"

dtlsServer server;

static void interrupt_handler(int _) {
    (void)_;
    server.isRunning = 0;
}

int main(int argc, char** argv)
{
    signal(SIGINT, interrupt_handler);

    const int port = 8443;
    const unsigned int tablesize = 2;
    const char* cipher = "TLS_RSA_WITH_AES_128_GCM_SHA256";
    const char* certChain = "certs/bundle.pem";
    const char* certFile = "certs/clientA.crt";
    const char* privateKey = "certs/clientA.key";

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    init_server(&server, cipher, certChain, certFile, privateKey);
    connection_setup(&server, port, tablesize, (void *(*)(void *)) &free_client);
    connection_loop(&server);
    free_server(&server);

    WSACleanup();

    return 0;
}