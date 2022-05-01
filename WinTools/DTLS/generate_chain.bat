mkdir certs

:: Generate CA
openssl req -addext basicConstraints=critical,CA:TRUE -subj "/CN=RootCA" -new -newkey rsa:8192 -nodes -out ca.csr -keyout ca.key
openssl x509 -trustout -signkey ca.key -days 365 -req -in ca.csr -out ca.crt -extfile v3.ext

:: Generate Client A
openssl genrsa -out clientA.key 8192
openssl req -subj "/CN=ClientA" -new -key clientA.key -out clientA.csr
openssl x509 -req -days 365 -in clientA.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out clientA.crt -extfile v3.ext

:: Generate Client B
openssl genrsa -out clientB.key 8192
openssl req -subj "/CN=ClientB" -new -key clientB.key -out clientB.csr
openssl x509 -req -days 365 -in clientB.csr -CA clientA.crt -CAkey clientA.key -set_serial 02 -out clientB.crt -extfile v3.ext

:: Generate Client C
openssl genrsa -out clientC.key 8192
openssl req -subj "/CN=ClientC" -new -key clientC.key -out clientC.csr
openssl x509 -req -days 365 -in clientC.csr -CA clientB.crt -CAkey clientB.key -set_serial 03 -out clientC.crt -extfile v3.ext


:: Generate bundle

copy ca.crt+clientA.crt+clientB.crt+clientC.crt bundle.pem

:: Cleanup

del *.csr

move *.key certs
move *.crt certs
move bundle.pem certs
