#include <signal.h>
#include <string.h>

#include "server/server.h"
#include "common/debug.h"

DtlsServer server = {0};

static void interrupt_handler(int _) {
    (void)_;
    server.isRunning = 0;
}

void opt_err(char** argv)
{
    fprintf(stderr, "Usage: %s -cipher [string] -key [file] -root [file] -chain [file] -port [int] -verify [optional]\n"
                            "\tExample: %s -cipher \"TLS_AES_256_GCM_SHA384\" -key certs/server.key -root certs/intermediate.pem -chain certs/s_bundle.pem -port 8443 -verify",
                            argv[0], argv[0]);
    exit(EXIT_FAILURE);
}

void parse_opt(int argc, char** argv, char** cipher, char** rootChain, char** privateKey, char** serverChain, char** groups, int* port, int* verifyClient)
{
    for (int i = 1; i < argc; i++) {
        //Cipher
        if (strcmp("-cipher", argv[i]) == 0 && (i + 1) <= argc) {
            *cipher = argv[i + 1];
            i++;
        }
        //Private key
        else if (strcmp("-key", argv[i]) == 0 && (i + 1) <= argc) {
            *privateKey = argv[i + 1];
            i++;
        }
        //Certificate chain
        else if (strcmp("-chain", argv[i]) == 0 && (i + 1) <= argc) {
            *serverChain = argv[i + 1];
            i++;
        }
        //Root CA Certificate chain
        else if (strcmp("-root", argv[i]) == 0 && (i + 1) <= argc) {
            *rootChain = argv[i + 1];
            i++;
        }
        //Groups
        else if (strcmp("-group", argv[i]) == 0 && (i + 1) <= argc) {
            *groups = argv[i + 1];
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
    fdprint(stdout, "Debug build");

    signal(SIGINT, interrupt_handler);

    const unsigned int tablesize = 100;
    int port = 0;                         // 8443
    char* cipher = NULL;                  // TLS_RSA_WITH_AES_128_GCM_SHA256
    char* rootChain = NULL;               // certs/ca.crt or certs/intermediate.pem
    char* privateKey = NULL;              // certs/server.key
    char* serverChain = NULL;             // certs/s_bundle.pem
    char* groups = NULL;                  // KYBER_LEVEL3
    int verifyClient = 0;

    parse_opt(argc, argv, &cipher, &rootChain, &privateKey, &serverChain, &groups, &port, &verifyClient);
    if (!cipher || !rootChain || !privateKey || !serverChain || port == 0)
        opt_err(argv);

    verifyClient = verifyClient ? SSL_VERIFY_PEER : SSL_VERIFY_NONE;
    printf("Settings:\n\tPort: %d\n\tCipher: %s\n\tRoot Certificate Chain: %s\n\tCertificate Key File: %s\n\tServer Certificate Chain: %s\n\tVerify Client: %s\n",
           port, cipher, rootChain, privateKey, serverChain, verifyClient ? "Yes" : "No");

#if WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    server_init(&server, cipher, rootChain, serverChain, privateKey, groups, verifyClient);
    server_connection_setup(&server, port, tablesize, (void *(*)(void *)) &server_connection_free);
    server_connection_loop(&server);
    server_free(&server);

#if WIN32
    WSACleanup();
#endif

    return 0;
}