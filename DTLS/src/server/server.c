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
#include "server/verification.h"

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

    return fd;
}

/**
 * Get client info from a socket
 *
 * @param server DtlsServer struct                [in]
 * @param clientSocket Pointer to sockaddr struct [in]
 * @param address IPv4 formatted address string   [out]
 * @param port port number                        [out]
 */
void get_client_info(DtlsServer* server, struct sockaddr* clientSocket, char* address, int* port)
{
    int length = sizeof(struct sockaddr);
    memset(clientSocket, 0, length);
    memset(address, '\0', INET_ADDRSTRLEN);

    // This returns -1 due to read message being larger than buffer of size 0
    recvfrom(server->socket, NULL, 0, MSG_PEEK, clientSocket, &length);
    inet_ntop(AF_INET, &((struct sockaddr_in*)clientSocket)->sin_addr, address, INET_ADDRSTRLEN);
    *port = ntohs(((struct sockaddr_in*)clientSocket)->sin_port);
}

DtlsClient* get_client(DtlsServer* server, const char* address, int port)
{
    node* current = get_bucket(server->connections, hash_connection(address, port));

    DtlsClient* client = NULL;
    if (current != NULL) {
        while (current != NULL) {
            DtlsClient* tmp = (DtlsClient*)(current->data);
            if (tmp->port == port && (strcmp(tmp->address, address) == 0))
            {
                client = tmp;
                break;
            }
            current = current->next;
        }
    }

    return client;
}

/**
 * Initialize the server
 *
 * @param server Uninitialized server struct
 */
void init_server(DtlsServer* server, const char* cipher, const char* certChain, const char* certFile, const char* privKey)
{
    memset(server, 0, sizeof(DtlsServer));

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
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_cert);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

    server->ctx = ctx;
}

/**
 * Setup server connection
 *
 * @param server
 */
void connection_setup(DtlsServer* server, int port, unsigned int connectionTableSize, void* freeFunc(void*))
{
    sockAddress serverAddr;
    memset(&serverAddr, 0, sizeof(struct sockaddr_in));

    serverAddr.s4.sin_family = AF_INET;
    serverAddr.s4.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.s4.sin_port = htons(port);

    memcpy(&server->local, &serverAddr, sizeof(struct sockaddr_in));
    server->timeoutSeconds = 5;
    server->socket = new_socket((const struct sockaddr*)&serverAddr);

    hashtable* table = new_hashtable(connectionTableSize);
    table->free_func = freeFunc;
    server->connections = table;

    server->isRunning = 1;
}

/**
 * Main loop to handle new and existing connections
 *
 * @param server
 */
void connection_loop(DtlsServer* server)
{
    // Incoming connection handling
    struct sockaddr clientSocket;
    memset(&clientSocket, 0, sizeof(struct sockaddr));
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

        get_client_info(server, &clientSocket, address, &port);
        DtlsClient* client = get_client(server, address, port);

        if (client != NULL)
        {
            memset(packetBuffer, 0, MAX_PACKET_SIZE);
            printf("== New datagram from %s:%d ==\n", address, port);

            int recvlen = client_recv(client, packetBuffer, MAX_PACKET_SIZE);
            if (recvlen <= 0)
            {
                fprintf(stderr, "recvlen = %d", recvlen);
                remove_item(server->connections, hash_connection(address, port), client);
                break;
            }

            printf("%s\n", packetBuffer);
            //remove_item(server->connections, hash_connection(address, port), client);
            printf("== Disconnected client %s:%d ==\n", address, port);
        }
        else {
            dtls_server_accept(server);
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
int dtls_server_accept(DtlsServer* server)
{
    DtlsClient* client = malloc(sizeof(DtlsClient));
    memset(client, 0, sizeof(DtlsClient));

    BIO* clientBio = BIO_new_dgram(server->socket, BIO_NOCLOSE);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    BIO_ctrl(clientBio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    client->ssl = SSL_new(server->ctx);
    SSL_set_bio(client->ssl, clientBio, clientBio);
    SSL_set_options(client->ssl, SSL_OP_COOKIE_EXCHANGE);

    sockAddress clientAddr;
    if (DTLSv1_listen(client->ssl, (BIO_ADDR*)&clientAddr) <= 0) {
        free_client(client);
        return -1;
    } // Wait for ClientHello + Reply + Cookie

    /* Finish handshake */
    int ret;
    do
    {
        ret = SSL_accept(client->ssl);
    } while (ret == 0);

    if (ret < 0)
    {
        char buffer[256];
        ERR_error_string_n(ERR_get_error(), buffer, 256);
        fprintf(stderr, "%s", buffer);
        free_client(client);
        return -1;
    }

    inet_ntop(AF_INET, &((struct sockaddr_in*)&clientAddr)->sin_addr, client->address, INET_ADDRSTRLEN);
    client->port = ntohs(((struct sockaddr_in*)&clientAddr)->sin_port);

    printf("New connection from %s:%d with hash of (%zu)\n", client->address, client->port, hash_connection(client->address, client->port) % server->connections->size);
    print_ssl_summary(client->ssl);

    node* clientNode = malloc(sizeof(node));
    memset(clientNode, 0, sizeof(node));
    clientNode->data = (void*)client;
    add_item(server->connections, hash_connection(client->address, client->port), clientNode);

    return 1;
}