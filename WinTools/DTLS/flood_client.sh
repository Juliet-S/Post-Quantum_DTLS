#!/bin/bash

for i in {1..100}
do
  ./dtls_client 192.168.1.238:8443 -key certs/client.key -root certs/intermediate.pem -chain certs/c_bundle.pem -group SECP521R1 &
  sleep 0.1
done

read
pkill dtls_client