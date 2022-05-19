#include <openssl/ssl.h>
#include <memory.h>

#if WIN32
 #include <WS2tcpip.h>
#else
 #include <unistd.h>
 #include <sys/socket.h>
 #include <arpa/inet.h>
 #include <string.h>
#endif

#include <openssl/err.h>

#include "client/client.h"
#include "dtls.h"
#include "info.h"

void client_init(DtlsClient* client, const char* certChain, const char* clientCert, const char* clientKey, int mode)
{
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init(); /* initialize library */

    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
    SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    int usingCert = clientCert && clientKey;
    if (clientCert && !SSL_CTX_use_certificate_file(ctx, clientCert, SSL_FILETYPE_PEM)) {
        printf("Client certificate not found\n");
        usingCert = 0;
    }

    if (clientKey && !SSL_CTX_use_PrivateKey_file(ctx, clientKey, SSL_FILETYPE_PEM)) {
        printf("Client private key not found\n");
        usingCert = 0;
    }

    if (usingCert && !SSL_CTX_check_private_key (ctx)) {
        err("Invalid private key");
    }

    if (usingCert && (!certChain || !SSL_CTX_load_verify_locations(ctx, certChain, NULL) || !SSL_CTX_set_default_verify_paths(ctx))) {
        err("No or invalid certificate chain");
    }

    if (usingCert && certChain) {
        SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(certChain));
    }

    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_verify(ctx, mode, NULL);
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
    int ret;
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

    SSL* ssl = SSL_new(client->ctx);
    DTLS_set_link_mtu(ssl, CONNECTION_MTU_SIZE);

    BIO* bio = BIO_new_dgram(fd, BIO_CLOSE);
    if (connect(fd, (struct sockaddr*)&remote, sizeof(struct sockaddr_in))) {
        err("Connect error");
    }
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote.ss);
    SSL_set_bio(ssl, bio, bio);

    ret = SSL_connect(ssl);
    if (ret <= 0) {
        char buffer[256];
        ERR_error_string_n(ERR_get_error(), buffer, 256);
        fprintf(stderr, "%s\n", buffer);
        err("SSL Connection failed");
    }

    /* Set and activate timeouts */
    struct timeval timeout = {
        .tv_sec = 3,
        .tv_usec = 0
    };
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    client->ssl = ssl;
    client->bio = bio;
    client->socket = fd;
    client->remote = remote;

    info_print_server_summary(client);

    return ret;
}

void client_connection_loop(DtlsClient* client)
{
    char address[INET_ADDRSTRLEN] = {0};
    int port;
    client_get_connection_info(client, address, &port);

    // Select
    int selRet;
    fd_set readset;
    struct timeval timeout;

    char sendBuffer[MAX_PACKET_SIZE] = "Hello World\0";
    char recvBuffer[MAX_PACKET_SIZE] = {0};
    while (!(SSL_get_shutdown(client->ssl) & SSL_RECEIVED_SHUTDOWN))
    {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(client->socket, &readset);

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

        //printf("%s:%d> %s\n", address, port, recvBuffer);
#if WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
    }
}

void client_get_connection_info(DtlsClient* client, char* address, int* port)
{
    memset(address, '\0', INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &((struct sockaddr_in*)&client->remote.s4)->sin_addr, address, INET_ADDRSTRLEN);
    *port = ntohs(client->remote.s4.sin_port);
}

void client_free(DtlsClient* client)
{
#if WIN32
    closesocket(client->socket);
#else
    close(client->socket);
#endif
    client->socket = -1;
    SSL_CTX_free(client->ctx);
    client->ctx = NULL;
}