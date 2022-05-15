#include "dtls.h"

#if WIN32
 #include <WinSock2.h>
#else
 #include <unistd.h>
#endif

#include <openssl/err.h>

/**
 * Print error message and exit program
 *
 * @param msg Error message
 */
void err(const char* msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(EXIT_FAILURE);
}

int check_ssl_read(SSL* ssl, char* buffer, int len)
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
            fprintf(stderr, "Unexpected error while reading!\n");
            break;
    }

    return ret;
}

/**
 * Create a new socket and bind to binding address
 *
 * @param bindingAddress Address to bind to
 * @return Socket file descriptor (int)
 */
int new_socket(const struct sockaddr* bindingAddress)
{
    const int on = 1;
    const int off = 0;
    int fd;

    if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        err("Socket creation");
    }

    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, (socklen_t) sizeof(on)) < 0) {
        err("Reuse address");
    }

#if defined(SO_REUSEPORT) && !defined(__linux__)
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const void*)&on, (socklen_t) sizeof(on)) < 0) {
        err("Reuse port");
    }
#endif

    if(bind(fd, bindingAddress, sizeof(struct sockaddr_in)) < 0) {
        err("Binding address");
    }

    if (fd < 0) {
        err("Socket creation error");
    }

    return fd;
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