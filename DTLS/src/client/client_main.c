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

    time_t start;
    time_t end;

    DtlsClient client = {0};
    const char* address = "127.0.0.1";
    const int port = 8443;

    init_client(&client, NULL, NULL);

    time(&start);
    connection_setup(&client, address, port);
    time(&end);
    printf("%f\n", difftime(end, start));

    connection_loop(&client);
    free_client(&client);

#if WIN32
    WSACleanup();
#endif
}