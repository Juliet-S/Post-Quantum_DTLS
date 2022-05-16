#include <openssl/ssl.h>
#include <openssl/err.h>

#if WIN32
 #include <winsock2.h>
 #include <WS2tcpip.h>
#else
 #include <unistd.h>
 #include <arpa/inet.h>
#endif

#include "server/server.h"
#include "server/sverify.h"
#include "info.h"

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
void server_init(DtlsServer* server, const char* cipher, const char* certChain, const char* certFile, const char* privKey, int mode)
{
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init(); /* initialize library */

    SSL_CTX* ctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_set_cipher_list(ctx, cipher);
    SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if (!certChain || !SSL_CTX_load_verify_locations(ctx, certChain, NULL) || !SSL_CTX_set_default_verify_paths(ctx)) {
        err("No or invalid certificate chain");
    }
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(certChain));

    if (!SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM)) {
        err("No certificate chain found");
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, privKey, SSL_FILETYPE_PEM)) {
        err("No or invalid private key");
    }

    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_verify(ctx, mode, NULL);
    SSL_CTX_set_cookie_generate_cb(ctx, sverify_generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &sverify_cookie);

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
    char packetBuffer[1500];
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
            memset(packetBuffer, 0, MAX_PACKET_SIZE);
            int recvlen = server_recv(connection, packetBuffer, MAX_PACKET_SIZE);
            if (recvlen <= 0)
            {
                fprintf(stderr, "%s:%d> Disconnected (recvlen = %d)\n", address, port, recvlen);
                hashtable_remove(server->connections, hash_connection(address, port), connection);
                continue;
            }

            printf("%s:%d> %s\n", address, port, packetBuffer);
            //remove_item(server->connections, hash_connection(address, port), client);
            //printf("== Disconnected client %s:%d ==\n", address, port);
        }
        else {
            server_dtls_accept(server);
        }
    }
}

/**
 * Try and accept a new client
 *
 * @param server
 * @param client Client struct to initialize on connected
 * @return 1 on accepted, <= 0 otherwise
 */
int server_dtls_accept(DtlsServer* server)
{
    DtlsConnection* connection = calloc(1, sizeof(DtlsConnection));

    BIO* clientBio = BIO_new_dgram(server->socket, BIO_NOCLOSE);

    struct timeval timeout = {
        .tv_sec = 1,
        .tv_usec = 0
    };
    BIO_ctrl(clientBio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    connection->ssl = SSL_new(server->ctx);
    SSL_set_bio(connection->ssl, clientBio, clientBio);
    SSL_set_options(connection->ssl, SSL_OP_COOKIE_EXCHANGE);

    SockAddress clientAddr = {0};
    if (DTLSv1_listen(connection->ssl, (BIO_ADDR*)&clientAddr) <= 0) {
        server_connection_free(connection);
        return -1;
    } // Wait for ClientHello + Reply + Cookie

    /* Finish handshake */
    int ret;
    do
    {
        ret = SSL_accept(connection->ssl);
    } while (ret == 0);

    if (ret < 0)
    {
        char buffer[256];
        ERR_error_string_n(ERR_get_error(), buffer, 256);
        fprintf(stderr, "%s\n", buffer);
        server_connection_free(connection);
        return -1;
    }

    inet_ntop(AF_INET, &((struct sockaddr_in*)&clientAddr)->sin_addr, connection->address, INET_ADDRSTRLEN);
    connection->port = ntohs(((struct sockaddr_in*)&clientAddr)->sin_port);

    printf("New connection from %s:%d with hash of (%zu)\n", connection->address, connection->port, hash_connection(connection->address, connection->port) % server->connections->size);
    info_print_ssl_summary(connection->ssl);

    node* clientNode = calloc(1, sizeof(node));
    clientNode->data = (void*)connection;
    hashtable_add(server->connections, hash_connection(connection->address, connection->port), clientNode);

    return 1;
}

int server_recv(DtlsConnection* connection, void* buffer, int size)
{
    int length = SSL_read(connection->ssl, buffer, size);
    return check_ssl_read(connection->ssl, buffer, length);
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
    SSL_CTX_free(server->ctx);
    server->ctx = NULL;
}

void server_connection_free(DtlsConnection* connection)
{
    SSL_shutdown(connection->ssl);
    SSL_free(connection->ssl);
    connection->ssl = NULL;
}