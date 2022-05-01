openssl s_server^
 -CAfile certs/bundle.pem^
 -cert certs/clientC.crt^
 -key certs/clientC.key^
 -accept 8443^
 -cipher "TLS_RSA_WITH_AES_128_GCM_SHA256"^
 -dtls1_2^
 -mtu 1500^
 -listen^