#include "dtls.h"

#if WIN32
 #include <WinSock2.h>
#else
 #include <unistd.h>
#endif

#include <openssl/err.h>

static int check_ssl_read(SSL* ssl, char* buffer, int len)
{
    int ret = -1;

    switch (SSL_get_error(ssl, len))
    {
        case SSL_ERROR_NONE:
        case SSL_ERROR_ZERO_RETURN:
            /* Reading data is ok */
            ret = 1;
            break;

        case SSL_ERROR_WANT_READ:
            /* Stop reading on socket timeout, otherwise try again */
            if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP,0, NULL)) {
                fprintf(stderr, "No response received!\n");
            }
            break;

        case SSL_ERROR_SYSCALL:
            fprintf(stderr, "Socket read error!\n");
            break;

        case SSL_ERROR_SSL:
            fprintf(stderr, "%s (%d)\n", ERR_error_string(ERR_get_error(), buffer), SSL_get_error(ssl, len));
            break;

        default:
            printf("Unexpected error while reading!\n");
            break;
    }

    return ret;
}

int client_recv(DtlsClient* client, void* buffer, int size)
{
    int length = SSL_read(client->ssl, buffer, size);
    return check_ssl_read(client->ssl, buffer, length);
}

size_t hash_connection(const char* str, int port)
{
    size_t hash = 5381;

    char c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    hash ^= port + 0x9e3779b9 + (hash << 6) + (hash >> 2);

    return hash;
}

void free_server(DtlsServer* server)
{
#if WIN32
    closesocket(server->socket);
#else
    close(server->socket);
#endif
    server->socket = -1;
    free_hashtable(server->connections);
    SSL_CTX_free(server->ctx);
    server->ctx = NULL;
}

void free_client(DtlsClient* client)
{
    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
    client->ssl = NULL;
}