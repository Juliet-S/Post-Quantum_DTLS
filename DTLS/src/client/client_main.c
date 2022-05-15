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

    DtlsClient client = {0};
    const char* address = "127.0.0.1";
    const int port = 8443;

    init_client(&client, NULL, NULL);

    double startTime = (double)clock() / CLOCKS_PER_SEC;
    connection_setup(&client, address, port);
    double endTime = (double)clock() / CLOCKS_PER_SEC;
    printf("%lf\n", endTime - startTime);

    connection_loop(&client);
    free_client(&client);

#if WIN32
    WSACleanup();
#endif
}