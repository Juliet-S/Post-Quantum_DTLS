mkdir certs

:: Generate Root CA
openssl req -addext basicConstraints=critical,CA:TRUE -subj "/CN=RootCA" -new -newkey rsa:4096 -nodes -out ca.csr -keyout ca.key
openssl x509 -trustout -signkey ca.key -days 365 -req -in ca.csr -out ca.crt -extfile v3.ext

:: Generate CA A
openssl genrsa -out CAA.key 4096
openssl req -addext basicConstraints=critical,CA:TRUE -subj "/CN=CAA" -new -key CAA.key -out CAA.csr
openssl x509 -req -days 365 -in CAA.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out CAA.crt -extfile v3.ext

:: Generate CA B
openssl genrsa -out CAB.key 4096
openssl req -addext basicConstraints=critical,CA:TRUE -subj "/CN=CAB" -new -key CAB.key -out CAB.csr
openssl x509 -req -days 365 -in CAB.csr -CA CAA.crt -CAkey CAA.key -set_serial 02 -out CAB.crt -extfile v3.ext

:: Generate Server
openssl genrsa -out server.key 4096
openssl req -subj "/CN=Server" -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA CAB.crt -CAkey CAB.key -set_serial 03 -out server.crt -extfile v3.ext

:: Generate Client
openssl genrsa -out client.key 4096
openssl req -subj "/CN=Client" -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA CAB.crt -CAkey CAB.key -set_serial 04 -out client.crt -extfile v3.ext


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
