#include <memory.h>
#include <stdio.h>

#if WIN32
 #include <WS2tcpip.h>
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include <string.h>
#endif

#include "client/client.h"
#include "common/info.h"

void client_init(DtlsClient* client, const char* certChain, const char* clientCert, const char* clientKey, int mode)
{
    if (wolfSSL_Init() != SSL_SUCCESS) {
        err("WolfSSL init error");
    }

    wolfSSL_Debugging_ON();

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());

    if (!certChain || wolfSSL_CTX_load_verify_locations(ctx, certChain, 0) != SSL_SUCCESS) {
        err("Root CA certificate invalid");
    }

    if (clientCert && wolfSSL_CTX_use_certificate_file(ctx, clientCert, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("Client certificate not found\n");
    }

    if (clientKey && wolfSSL_CTX_use_PrivateKey_file(ctx, clientKey, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("Client private key not found\n");
    }

    client->ctx = ctx;
}

/**
 * Connects a client to a specified server
 * @param client
 * @param address
 * @param port
 * @return 0 on success, nonzero otherwise
 */
int client_connection_setup(DtlsClient* client, const char* address, int port)
{
    int ret = 0;
    SockAddress local = {
        .s4.sin_family = AF_INET,
        .s4.sin_addr.s_addr = htonl(INADDR_ANY),
        .s4.sin_port = htons(0),
    };

    SockAddress remote = {
        .s4.sin_family = AF_INET,
        .s4.sin_port = htons(port)
    };

    if (inet_pton(AF_INET, address, &remote.s4.sin_addr) != 1) {
        err("IP Address parse error");
    }

    int fd = new_socket((const struct sockaddr*)&local);

    WOLFSSL* ssl = wolfSSL_new(client->ctx);

    if (wolfSSL_dtls_set_peer(ssl, &(remote.s4), sizeof(remote.s4)) != SSL_SUCCESS) {
        err("Set peer failed");
    }

    if (wolfSSL_set_fd(ssl, fd) != SSL_SUCCESS) {
        err("Cannot set socket file descriptor");
    }

    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        int errCode = wolfSSL_get_error(ssl, 0);
        fprintf(stderr, "err = %d, %s\n", errCode, wolfSSL_ERR_reason_error_string(errCode));
        ret = -1;
        err("wolfSSL connect failed");
    }

    client->ssl = ssl;
    client->socket = fd;
    client->remote = remote;

    info_print_server_summary(client);
    info_print_ssl_summary(ssl);

    return ret;
}

/**
 * Generate a random string of specified length
 * @param str Char buffer
 * @param size Size of string to generate
 * @return String
 */
static char* rand_string(char* str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK1234567890!@#$%^&*()_+-=,./\\|";
    int length = sizeof(charset) - 1;

    size--;
    for (size_t n = 0; n < size; n++) {
        int key = rand() % length;
        str[n] = charset[key];
    }

    str[size] = '\0';
    return str;
}

/**
 * Client connection loop
 * @param client DTLS Client connection
 */
void client_connection_loop(DtlsClient* client)
{
    char address[INET_ADDRSTRLEN] = {0};
    int port;
    client_get_connection_info(client, address, &port);

    // Select
    int selRet;
    fd_set readset;
    struct timeval timeout;

    char sendBuffer[MAX_PACKET_SIZE];
    char recvBuffer[MAX_PACKET_SIZE];
    while (wolfSSL_get_shutdown(client->ssl) != SSL_RECEIVED_SHUTDOWN)
    {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(client->socket, &readset);

        rand_string(sendBuffer, MAX_PACKET_SIZE);
        if (dtls_send(client->ssl, sendBuffer, strnlen(sendBuffer, MAX_PACKET_SIZE)) != 1) {
            break;
        }

        selRet = select(FD_SETSIZE, &readset, NULL, NULL, &timeout);
        if (selRet == 0) {
            continue;
        }
        else if (selRet < 0) {
            fprintf(stderr,"Select error...\n");
            break;
        }

        if (dtls_recv(client->ssl, recvBuffer, MAX_PACKET_SIZE) != 1) {
            break;
        }

        printf("%s:%d> %.8s ... (%zu)\n", address, port, recvBuffer, strnlen(recvBuffer, MAX_PACKET_SIZE));
#if WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
    }
}

/**
 * Get client connection information
 *
 * @param client DTLS Client
 * @param address Address buffer (At least INET_ADDRESTRLEN in size)
 * @param port Store port of client
 */
void client_get_connection_info(DtlsClient* client, char* address, int* port)
{
    memset(address, '\0', INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &((struct sockaddr_in*)&client->remote.s4)->sin_addr, address, INET_ADDRSTRLEN);
    *port = ntohs(client->remote.s4.sin_port);
}

/**
 * Free client resources
 *
 * @param client DTLS Client
 */
void client_free(DtlsClient* client)
{
    wolfSSL_shutdown(client->ssl);
    wolfSSL_free(client->ssl);

#if WIN32
    closesocket(client->socket);
#else
    close(client->socket);
#endif
    client->socket = 0;

    wolfSSL_CTX_free(client->ctx);
    client->ctx = NULL;
    wolfSSL_Cleanup();
}