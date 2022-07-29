#include <stdio.h>

#include "client/client.h"

void opt_err(char** argv)
{
    fprintf(stderr, "Usage: %s <IP Address>:<Port> -cert [file] -key [file] -chain [file]\n", argv[0]);
    exit(EXIT_FAILURE);
}

void parse_opt(int argc, char** argv, char** certChain, char** certFile, char** privateKey)
{
    for (int i = 2; i < argc; i++) {
        //Certificate
        if (strcmp("-cert", argv[i]) == 0 && (i + 1) <= argc) {
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
    }
}

void parse_address(char* address, int* port) {
    int hasColon = 0;
    while (*address) {
        if (*address == ':') {
            *address = '\0';
            hasColon = 1;
            break;
        }
        address++;
    }

    if (!hasColon) {
        err("Invalid IP address");
    }
    address++;

    if (address) {
        *port = strtol(address, NULL, 10);
    } else {
        err("Invalid IP address");
    }
}

int main(int argc, char** argv)
{
    DtlsClient client = {0};
    char* certChain = NULL;           // certs/bundle.pem
    char* clientCert = NULL;          // certs/client.crt
    char* clientKey = NULL;           // certs/client.key

    if (argc <= 1) {
        opt_err(argv);
    }

    char* address = argv[1];
    int port = 8443;
    parse_opt(argc, argv, &certChain, &clientCert, &clientKey);
    parse_address(address, &port);

    if (port == 0) {
        err("Invalid IP Address");
    }

    printf("Settings:\n\tAddress: %s\n\tPort: %d\n\tCertificate File: %s\n\tCertificate Key File: %s\n\tCertificate Chain File: %s\n",
           address, port, clientCert, clientKey, certChain);

#if WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    client_init(&client, certChain, clientCert, clientKey, SSL_VERIFY_PEER);

    double startTime = (double)clock() / CLOCKS_PER_SEC;
    client_connection_setup(&client, address, port);
    double endTime = (double)clock() / CLOCKS_PER_SEC;
    printf("\tTime to connect: %lf\n", endTime - startTime);

    client_connection_loop(&client);
    client_free(&client);

#if WIN32
    WSACleanup();
#endif
}