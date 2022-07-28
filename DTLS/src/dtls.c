#include "dtls.h"

#if WIN32
 #include <WinSock2.h>
#else
 #include <unistd.h>
#endif

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

int check_ssl(WOLFSSL* ssl, char* buffer, int code)
{
    int ret = -1;
    int errCode = wolfSSL_get_error(ssl, 0);
    switch (wolfSSL_get_error(ssl, ret))
    {
        case WOLFSSL_ERROR_NONE:
        case WOLFSSL_ERROR_ZERO_RETURN:
            /* Reading data is ok */
            ret = 1;
            break;

        case WOLFSSL_ERROR_WANT_READ:
            fprintf(stderr, "Want read!\n");
            ret = 1;
            break;

        case WOLFSSL_ERROR_SYSCALL:
            fprintf(stderr, "Socket read error!\n");
            break;

        default:
            fprintf(stderr, "err = %d, %s\n", errCode, wolfSSL_ERR_reason_error_string(errCode));
            break;
    }

    return ret;
}

/**
 * Receive message from DTLS connection
 *
 * @param ssl
 * @param buffer
 * @param size
 * @return
 */
int dtls_recv(WOLFSSL* ssl, char* buffer, int size)
{
    int ret = wolfSSL_read(ssl, buffer, size);
    if (ret == 0) {
        return check_ssl(ssl, buffer, ret);
    }
    return 1;
}

/**
 * Send message to DTLS connection
 *
 * @param ssl
 * @param buffer
 * @param size
 * @return
 */
int dtls_send(WOLFSSL* ssl, char* buffer, int size)
{
    int ret = wolfSSL_write(ssl, buffer, size);
    if (ret == 0) {
        return check_ssl(ssl, buffer, ret);
    }
    return 1;
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