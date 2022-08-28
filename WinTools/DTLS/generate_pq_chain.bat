mkdir certs

@REM Set this to your install of open-quantum-safe OpenSSL
set OPENSSL_PROG=D:\Programming\openssl\pqopenssl\openssl\apps\openssl.exe

:: Generate Root CA
%OPENSSL_PROG% req -addext basicConstraints=critical,CA:TRUE -subj "/CN=RootCA" -new -newkey dilithium5_aes -nodes -out ca.csr -keyout ca.key
%OPENSSL_PROG% x509 -trustout -signkey ca.key -days 365 -req -in ca.csr -out ca.crt -extfile v3.ext

:: Generate CA A
%OPENSSL_PROG% genpkey -algorithm dilithium5_aes -outform pem -out CAA.key
%OPENSSL_PROG% req -addext basicConstraints=critical,CA:TRUE -subj "/CN=CAA" -new -key CAA.key -out CAA.csr
%OPENSSL_PROG% x509 -req -days 365 -in CAA.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out CAA.crt -extfile v3.ext

:: Generate CA B
%OPENSSL_PROG% genpkey -algorithm dilithium5_aes -outform pem -out CAB.key
%OPENSSL_PROG% req -addext basicConstraints=critical,CA:TRUE -subj "/CN=CAB" -new -key CAB.key -out CAB.csr
%OPENSSL_PROG% x509 -req -days 365 -in CAB.csr -CA CAA.crt -CAkey CAA.key -set_serial 02 -out CAB.crt -extfile v3.ext

:: Generate Server
%OPENSSL_PROG% genpkey -algorithm dilithium5_aes -outform pem -out server.key
%OPENSSL_PROG% req -subj "/CN=Server" -new -key server.key -out server.csr
%OPENSSL_PROG% x509 -req -days 365 -in server.csr -CA CAB.crt -CAkey CAB.key -set_serial 03 -out server.crt -extfile v3.ext

:: Generate Client
%OPENSSL_PROG% genpkey -algorithm dilithium5_aes -outform pem -out client.key
%OPENSSL_PROG% req -subj "/CN=Client" -new -key client.key -out client.csr
%OPENSSL_PROG% x509 -req -days 365 -in client.csr -CA CAB.crt -CAkey CAB.key -set_serial 04 -out client.crt -extfile v3.ext


:: Generate bundle
powershell -Command "(gc ca.crt) -replace 'TRUSTED ', '' | Out-File -encoding ASCII ca.crt"
copy server.crt+CAB.crt+CAA.crt+ca.crt s_bundle.pem
copy client.crt+CAB.crt+CAA.crt+ca.crt c_bundle.pem
copy ca.crt+CAA.crt+CAB.crt intermediate.pem

:: Cleanup
move *.key certs
move ca.crt certs
move *.pem certs

del *.csr
del *.crt
