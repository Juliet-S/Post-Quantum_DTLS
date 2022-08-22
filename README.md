# PQDTLS

Repository for a post-quantum implementation of the DTLS protocol. Main files inside
DTLS subfolder, with dependencies WolfSSL and LibOQS included as submodules.

DTLS subdirectory has both a server and a client, with the server able to handle 
an arbitrary amount of clients connected.

## Requirements

- Cmake
  - Make / Ninja (Linux)
  - Visual Studio (Windows)
- LibOQS
- WolfSSL (Compiled with OQS)
- WSL (Linux emulation windows / Cross platform compilation ARM64 & ARMHF) †

† Optional 

## Building

General steps:
1. Build and Install LibOQS
2. Build and Install WolfSSL
3. Build PQDTLS

### Linux x64

1. Building LibOQS

From root dir:
```
cd liboqs
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX="/usr/local/liboqs"
make -j
sudo make install
```

2. Building WolfSSL

From root dir:
```
cd wolfssl
make clean
./configure --disable-shared --enable-dtls13 --enable-dtls --enable-opensslextra --enable-sp=yes --with-liboqs=/usr/local/liboqs LDFLAGS=-static
make -j
sudo make install
```

3. Building

- Open in CLion
- Specify `WOLFSSL_LIBRARIES`, `WOLFSSL_INCLUDE_DIR` locations (if not on path)

OR

From root dir:
```
cd DTLS
mkdir build
cd build
cmake .. -DWOLFSSL_LIBRARIES="/usr/local/wolfssl/lib/wolfssl.a" \ 
          -DWOLFSSL_INCLUDE_DIR="/usr/local/wolfssl/include" \
          -DDEBUG=1
make -j
```

### Windows x64

1. Building LibOQS

From root dir:
```
cd liboqs
mkdir build && cd build
cmake .. -D "CMAKE_INSTALL_PREFIX:PATH=path/to/your/install"
```

Open in Visual Studio and run `ALL_BUILD` and `INSTALL` or Use commandline `msbuild`

2. Building WolfSSL

- Open `wolfssl64.sln` in Visual Studio, 
- Retarget for your `VC++` redistributible version e.g VC142
- Update `/IDE/win/user_settings.h` with contents from `DTLS/include/user_settings.h`
- Change configuration target to Debug/Release static library
- Rebuild `wolfssl` project
- Keep note of where `wolfssl.lib` is: e.g `wolfssl\Debug\x64\wolfssl.lib`

3. Building

- Open in CLion

OR

From root dir:
```
cd DTLS
mkdir build
cd build
cmake .. -DWOLFSSL_LIBRARIES="/path/to/wolfssl.lib" \ 
          -DWOLFSSL_INCLUDE_DIR="/path/to/wolfssl/include/headers" \
          -DDEBUG=1
```

Open in Visual Studio and run `ALL_BUILD` or Use commandline `msbuild`

## Linux ARM64 / ARMHF Partial Instructions

Compile for ARM64 Prerequisites:
1. Linux with `aarch64-linux-gnu-{gcc,g++}` installed (Windows just use WSL2)
2. Cross compile libs installed (dpkg --add-architecture <arch>) <arch> = arm64 in this case

Compile for ARMHF Preqrequisites:
1. Linux with `arm-linux-gnueabi-{gcc,g++}` installed (Windows just use WSL2)
2. Cross compile libs installed (dpkg --add-architecture <arch>) <arch> = armhf in this case

Example for ARM64:
1. Cross compile LibOQS for ARM64
2. Cross Compile WolfSSL for ARM64
```
cd wolfssl
make clean
./configure --host=aarch64-linux-gnu --prefix=/usr/local/wolfsslarm64 --disable-shared --enable-dtls13 --enable-dtls --enable-opensslextra --enable-sp=yes LDFLAGS=-static
make -j
sudo make install
```

## Build Configuration

Using CLion (and WSL) it is possible build and run for Windows, Linux, x86, ARM64 / ARMHF

Example Config for (Debug) Windows x64:
```
-G
"Visual Studio 16 2019"
-DWOLFSSL_LIBRARIES="path\to\wolfssl\Debug\x64\wolfssl.lib"
-DWOLFSSL_INCLUDE_DIR="path\to\wolfssl"
-DDEBUG=1
```

Example Config for (Debug) Linux x64:

```
-DWOLFSSL_LIBRARIES="/usr/local/wolfssl/lib/libwolfssl.a"
-DWOLFSSL_INCLUDE_DIR="/usr/local/wolfssl/include"
-DDEBUG=1
```

Example Config for (Release) Linux ARM64

```
-DWOLFSSL_LIBRARIES="/usr/local/wolfsslarm64/lib/libwolfssl.a"
-DWOLFSSL_INCLUDE_DIR="/usr/local/wolfsslarm64/include"
```

## Running

Once built, simply run `./dtls_server` or `./dtls_client` (Linux) or `dtls_server.exe` or `dtls_client.exe` on Windows.

See following sections for the parameters these programs take.

### Certificate Generation

The server (and optionally the client) require certificates in order to run properly. See the `WinTools` folder
for examples on how to generate certificate chains and server/client certificates. In the `WinTools/DTLS` folder
is a `generate_chain.bat` file (Windows) for generating a valid certificate chain for
both the server and client which is stored in a `certs` folder which can be deployed next to the programs.

### DTLS Server

- -cipher [string] (e.g `TLS_AES_256_GCM_SHA384`)
- -chain [file] (e.g `certs/ca.crt or certs/intermediate.pem`)
- -key [file] (e.g `certs/server.key`)
- -port [int] (e.g `8443`)
- -verify (optional, enable client verification)

e.g `dtls_server -cipher "TLS_AES_256_GCM_SHA384" -key certs/server.key -root certs/ca.crt -chain certs/s_bundle.pem -port 8443 -verify`

With cipher being the server's cipher, 
chain being the certificate chain to send to the client,
key being the server's private key,
and port being the port to host on.

Verify is an optional flag for client verification.

### DTLS Client

- <IP Address>:<Port> 
- -cert [file] 
- -key [file] 
- -chain [file]

e.g `192.168.1.238:8443 -chain certs/c_bundle.pem -key certs/client.key -root certs/intermediate.pem`

With chain being the certificate chain to send to the server,
key being the client's private key,
and cert being the client's certificate (signed by a root CA the server trusts.)