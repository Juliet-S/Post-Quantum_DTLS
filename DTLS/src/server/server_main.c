#include <signal.h>
#include <string.h>

#include "server/server.h"

DtlsServer server = {0};

static void interrupt_handler(int _) {
    (void)_;
    server.isRunning = 0;
}

void opt_err(char** argv)
{
    fprintf(stderr, "Usage: %s -cipher [string] -cert [file] -key [file] -chain [file] -port [int] -verify\n", argv[0]);
    exit(EXIT_FAILURE);
}

void parse_opt(int argc, char** argv, char** cipher, char** certChain, char** certFile, char** privateKey, int* port, int* verifyClient)
{
    for (int i = 1; i < argc; i++) {
        //Cipher
        if (strcmp("-cipher", argv[i]) == 0 && (i + 1) <= argc) {
            *cipher = argv[i + 1];
            i++;
        }
        //Certificate
        else if (strcmp("-cert", argv[i]) == 0 && (i + 1) <= argc) {
            *certFile = argv[i+1];
            i++;
        }
        //Private key
        else if (strcmp("-key", argv[i]) == 0 && (i + 1) <= argc) {
            *privateKey = argv[i + 1];
            i++;
        }
        //Certificate chain
        else if (strcmp("-chain", argv[i]) == 0 && (i + 1) <= argc) {
            *certChain = argv[i + 1];
            i++;
        }
        //Port
        else if (strcmp("-port", argv[i]) == 0 && (i + 1) <= argc) {
            *port = strtol(argv[i + 1], NULL, 10);
            i++;
        }
        //Verify peer
        else if (strcmp("-verify", argv[i]) == 0) {
            *verifyClient = 1;
        }
    }
}

int main(int argc, char** argv)
{
    signal(SIGINT, interrupt_handler);

    const unsigned int tablesize = 100;
    int port = 0;                         // 8443
    char* cipher = NULL;                  // TLS_RSA_WITH_AES_128_GCM_SHA256
    char* certChain = NULL;               // certs/bundle.pem
    char* certFile = NULL;                // certs/server.crt
    char* privateKey = NULL;              // certs/server.key
    int verifyClient = 0;

    parse_opt(argc, argv, &cipher, &certChain, &certFile, &privateKey, &port, &verifyClient);
    if (!cipher || !certChain || !certFile || !privateKey || port == 0)
        opt_err(argv);

    verifyClient = verifyClient ? SSL_VERIFY_PEER : SSL_VERIFY_NONE;
    printf("Settings:\n\tPort: %d\n\tCipher: %s\n\tCertificate File: %s\n\tCertificate Key File: %s\n\tCertificate Chain File: %s\n\tVerify Client: %s\n",
           port, cipher, certFile, privateKey, certChain, verifyClient ? "Yes" : "No");

#if WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    server_init(&server, cipher, certChain, certFile, privateKey, verifyClient);
    server_connection_setup(&server, port, tablesize, (void *(*)(void *)) &server_connection_free);
    server_connection_loop(&server);
    server_free(&server);

#if WIN32
    WSACleanup();
#endif

    return 0;
}