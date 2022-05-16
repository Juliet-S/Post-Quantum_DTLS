#include <stdio.h>

#if WIN32
 #include <WinSock2.h>
#else

#endif

#include "client/client.h"

int main(int argc, char** argv)
{
    DtlsClient client = {0};
    const char* address = "127.0.0.1";
    const int port = 8443;
    const char* certChain = "certs/bundle.pem";
    const char* clientCert = "certs/client.crt";
    const char* clientKey = "certs/client.key";

#if WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    client_init(&client, certChain, clientCert, clientKey, SSL_VERIFY_PEER);

    double startTime = (double)clock() / CLOCKS_PER_SEC;
    client_connection_setup(&client, address, port);
    double endTime = (double)clock() / CLOCKS_PER_SEC;
    printf("%lf\n", endTime - startTime);

    client_connection_loop(&client);
    client_free(&client);

#if WIN32
    WSACleanup();
#endif
}