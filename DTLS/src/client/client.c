#include <openssl/ssl.h>
#include <memory.h>

#if WIN32
 #include <WS2tcpip.h>
#else

#endif

#include "client/client.h"
#include "dtls.h"

void init_client(DtlsClient* client, const char* clientCert, const char* clientKey)
{
    memset(client, 0, sizeof(DtlsClient));

    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init(); /* initialize library */

    SSL_CTX* ctx = SSL_CTX_new(DTLS_client_method());
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

    if (usingCert && !SSL_CTX_check_private_key (ctx))
        err("Invalid private key");

    SSL_CTX_set_read_ahead(ctx, 1);
    client->ctx = ctx;
}

/**
 * Connects a client to a specified server
 * @param client
 * @param address
 * @param port
 * @return 0 on success, nonzero otherwise
 */
int connection_setup(DtlsClient* client, const char* address, int port)
{
    int ret;
    SockAddress local;
    memset(&local, 0, sizeof(struct sockaddr_storage));
    local.s4.sin_family = AF_INET;
    local.s4.sin_addr.s_addr = htonl(INADDR_ANY);
    local.s4.sin_port = htons(0);

    SockAddress remote;
    memset(&remote, 0, sizeof(struct sockaddr_storage));
    remote.s4.sin_family = AF_INET;
    remote.s4.sin_port = htons(port);
    if (inet_pton(AF_INET, address, &remote.s4.sin_addr) != 1) {
        err("IP Address parse error");
    }

    int fd = new_socket((const struct sockaddr*)&local);

    SSL* ssl = SSL_new(client->ctx);
    BIO* bio = BIO_new_dgram(fd, BIO_CLOSE);
    if (connect(fd, (struct sockaddr*)&remote, sizeof(struct sockaddr_in))) {
        err("Connect error");
    }
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote.ss);
    SSL_set_bio(ssl, bio, bio);

    ret = SSL_connect(ssl);
    if (ret <= 0) {
        err("SSL Connection failed");
    }

    /* Set and activate timeouts */
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    client->ssl = ssl;
    client->bio = bio;
    client->socket = fd;

    return ret;
}

void connection_loop(DtlsClient* client)
{
    char sendBuffer[MAX_PACKET_SIZE] = "Hello World\0";
    char writeBuffer[MAX_PACKET_SIZE] = {0};
    while (!(SSL_get_shutdown(client->ssl) & SSL_RECEIVED_SHUTDOWN)) {
        // TODO CLIENT SEND AND RECV
        client_send(client, sendBuffer, MAX_PACKET_SIZE);
        Sleep(1000);
    }
}

int client_recv(DtlsClient* client, char* buffer, int size)
{
    int length = SSL_read(client->ssl, buffer, size);
    return check_ssl_read(client->ssl, buffer, length);
}

int client_send(DtlsClient* client, char* buffer, int size)
{
    SSL_write(client->ssl, buffer, size);
    return 0;
}

void free_client(DtlsClient* client)
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