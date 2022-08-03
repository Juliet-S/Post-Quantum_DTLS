#if WIN32
 #include <winsock2.h>
 #include <WS2tcpip.h>
#else
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <string.h>
#endif

#include "server/server.h"
#include "common/info.h"
#include "common/debug.h"

/**
 * Get client info from a socket
 *
 * @param server DtlsServer struct                [in]
 * @param connectionSocket Pointer to sockaddr struct [in]
 * @param address IPv4 formatted address string   [out]
 * @param port port number                        [out]
 */
void get_connection_info(DtlsServer* server, struct sockaddr* connectionSocket, char* address, int* port)
{
    int length = sizeof(struct sockaddr);
    memset(connectionSocket, 0, length);
    memset(address, '\0', INET_ADDRSTRLEN);

    // This returns -1 due to read message being larger than buffer of size 0
    recvfrom(server->socket, NULL, 0, MSG_PEEK, connectionSocket, &length);
    inet_ntop(AF_INET, &((struct sockaddr_in*)connectionSocket)->sin_addr, address, INET_ADDRSTRLEN);
    *port = ntohs(((struct sockaddr_in*)connectionSocket)->sin_port);
}

/**
 * Retrieve connection if exists
 *
 * @param server
 * @param address Address of client
 * @param port Port of client
 * @return DTLSConnection if exists, NULL otherwise
 */
DtlsConnection* get_connection(DtlsServer* server, const char* address, int port)
{
    node* current = hashtable_get(server->connections, hash_connection(address, port));

    DtlsConnection* connection = NULL;
    if (current != NULL) {
        while (current != NULL) {
            DtlsConnection* tmp = (DtlsConnection*)(current->data);
            if (tmp->port == port && (strcmp(tmp->address, address) == 0))
            {
                connection = tmp;
                break;
            }
            current = current->next;
        }
    }

    return connection;
}

/**
 * Initialize the server
 *
 * @param server Uninitialized server struct
 */
void server_init(DtlsServer* server, const char* ciphers, const char* rootChain, const char* serverChain, const char* privKey, int mode)
{
    if (wolfSSL_Init() != SSL_SUCCESS) {
        err("WolfSSL init error");
    }

    wolfSSL_Debugging_ON();

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());

    if (!rootChain || wolfSSL_CTX_load_verify_locations(ctx, rootChain, 0) != SSL_SUCCESS) {
        dprint("No or invalid root CA certificate chain");
        err("No or invalid root CA certificate chain");
    }

    if (!serverChain || wolfSSL_CTX_use_certificate_chain_file(ctx, serverChain) != SSL_SUCCESS) {
        dprint("No or invalid server certificate chain");
        err("No or invalid server certificate chain");
    }

    if (wolfSSL_CTX_use_PrivateKey_file(ctx, privKey, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        dprint("No or invalid private key");
        err("No or invalid private key");
    }

    if (!ciphers || wolfSSL_CTX_set_cipher_list(ctx, ciphers) != SSL_SUCCESS) {
        dprint("Missing or invalid ciphersuite list");
        err("Missing or invalid ciphersuite list");
    }

    if (mode) {
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
    }

    server->ctx = ctx;
}

/**
 * Setup server connection
 *
 * @param server
 */
void server_connection_setup(DtlsServer* server, int port, unsigned int connectionTableSize, void* free_func(void*))
{
    SockAddress serverAddr = {
        .s4.sin_family = AF_INET,
        .s4.sin_addr.s_addr = htonl(INADDR_ANY),
        .s4.sin_port = htons(port)
    };
    memcpy(&server->local, &serverAddr, sizeof(struct sockaddr_in));
    server->timeoutSeconds = 5;
    server->socket = new_socket((const struct sockaddr*)&serverAddr);

    hashtable* table = hashtable_new(connectionTableSize);
    table->free_func = free_func;
    server->connections = table;

    server->isRunning = 1;
}

/**
 * Main loop to handle new and existing connections
 *
 * @param server
 */
void server_connection_loop(DtlsServer* server)
{
    // Incoming connection handling
    struct sockaddr clientSocket = {0};
    char packetBuffer[MAX_PACKET_SIZE];
    char address[INET_ADDRSTRLEN];
    int port;

    // Select
    int selRet;
    fd_set readset;

    struct timeval timeout;
    while(server->isRunning)
    {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        FD_ZERO(&readset);
        FD_SET(server->socket, &readset);

        selRet = select(FD_SETSIZE, &readset, NULL, NULL, &timeout);
        if (selRet == 0) {
            continue;
        }
        else if (selRet < 0) {
            fprintf(stderr,"Select error...\n");
            break;
        }

        get_connection_info(server, &clientSocket, address, &port);
        DtlsConnection* connection = get_connection(server, address, port);

        if (connection != NULL)
        {
            int recvlen = dtls_recv(connection->ssl, packetBuffer, MAX_PACKET_SIZE);
            if (wolfSSL_get_shutdown(connection->ssl) == SSL_RECEIVED_SHUTDOWN || recvlen <= 0)
            {
                fprintf(stdout, "%s:%d> Disconnected (recvlen = %d)\n", address, port, recvlen);
                hashtable_remove(server->connections, hash_connection(address, port), connection);
                continue;
            }

//            printf("%s:%d> %.8s ... (%zu)\n", address, port, packetBuffer, strnlen(packetBuffer, MAX_PACKET_SIZE));
            dtls_send(connection->ssl, packetBuffer, strnlen(packetBuffer, MAX_PACKET_SIZE));
        }
        else {
            server_dtls_accept(server, &clientSocket);
        }
    }
}

int count = 0;

/**
 * Try and accept a new client
 *
 * @param server
 * @param client Client struct to initialize on connected
 * @return 1 on accepted, <= 0 otherwise
 */
int server_dtls_accept(DtlsServer* server, struct sockaddr* clientSockAddr)
{
    DtlsConnection* connection = calloc(1, sizeof(DtlsConnection));

    connection->ssl = wolfSSL_new(server->ctx);
    if (!connection->ssl) {
        int errCode = wolfSSL_get_error(connection->ssl, 0);
        dprint("Failed to allocate new client, error = %d, %s", errCode, wolfSSL_ERR_reason_error_string(errCode));
        server_connection_free(connection);
        return -1;
    }

    if (wolfSSL_dtls_set_peer(connection->ssl, clientSockAddr, sizeof(*clientSockAddr)) != SSL_SUCCESS) {
        dprint("Failed to set client peer");
        server_connection_free(connection);
        return -1;
    }

    if (wolfSSL_set_fd(connection->ssl, server->socket) != SSL_SUCCESS) {
        dprint("Failed to bind new connection to socket");
        server_connection_free(connection);
        return -1;
    }

    int accept = wolfSSL_accept(connection->ssl);
    if (!wolfSSL_dtls(connection->ssl) || accept != SSL_SUCCESS) {
        int errCode = wolfSSL_get_error(connection->ssl, accept);
        if (errCode != SSL_ERROR_WANT_READ) {
            dprint("Connection failed, error = %d, %s", errCode, wolfSSL_ERR_reason_error_string(errCode));
            server_connection_free(connection);
            return -1;
        }
    }

    inet_ntop(AF_INET, &((struct sockaddr_in*)clientSockAddr)->sin_addr, connection->address, INET_ADDRSTRLEN);
    connection->port = ntohs(((struct sockaddr_in*)clientSockAddr)->sin_port);

    printf("New connection from %s:%d with hash of (%zu)\n", connection->address, connection->port, hash_connection(connection->address, connection->port) % server->connections->size);
    info_print_connection_summary(connection->ssl);
    info_print_ssl_summary(connection->ssl);

    node* clientNode = calloc(1, sizeof(node));
    clientNode->data = (void*)connection;
    hashtable_add(server->connections, hash_connection(connection->address, connection->port), clientNode);

    count++;
    printf("count: %d\n", count);

    return 1;
}

void server_free(DtlsServer* server)
{
#if WIN32
    closesocket(server->socket);
#else
    close(server->socket);
#endif
    server->socket = -1;
    hashtable_free(server->connections);
    wolfSSL_CTX_free(server->ctx);
    server->ctx = NULL;
}

void server_connection_free(DtlsConnection* connection)
{
    if (wolfSSL_shutdown(connection->ssl) != SSL_SUCCESS) {
        wolfSSL_shutdown(connection->ssl);
    }
    wolfSSL_free(connection->ssl);
    connection->ssl = NULL;
    free(connection);
}