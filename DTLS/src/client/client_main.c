#include <stdio.h>

#if WIN32
 #include <WinSock2.h>
#else

#endif

#include "client/client.h"

int main(int argc, char** argv)
{
#if WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    DtlsClient client;
    const char* address = "127.0.0.1";
    const int port = 8443;

    init_client(&client, NULL, NULL);
    connection_setup(&client, address, port);
    connection_loop(&client);
    free_client(&client);

#if WIN32
    WSACleanup();
#endif
}