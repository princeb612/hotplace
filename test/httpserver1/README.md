#### test

```
# run (libssl)
./test-httpserver1 -r -k --trace &
# run (trial)
./test-httpserver1 -r -k --trace -T &

# chrome or edge
#   https://localhost:9000/
#   https://[::1]:9000/
# curl
#   curl https://localhost:9000/ -v -s -k
#   curl https://[::1]:9000/ -v -s -k

# stop
rm .run
```

- [x] tasks
  - [x] network_server
  - [x] HTTP/1.1
  - [x] integration
    - [x] libssl
    - [x] trial
  - [x] TLS 1.3
    - [x] chrome
    - [x] curl (8.15.0)
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves secp256r1
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves secp384r1
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves secp521r1
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves x25519
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves x448
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves ffdhe2048
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves ffdhe3072
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves ffdhe4096
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves ffdhe6144
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves ffdhe8192
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves brainpoolP256r1tls13
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves brainpoolP384r1tls13
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves brainpoolP512r1tls13
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves MLKEM512
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves MLKEM768
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves MLKEM1024
      - [ ] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves SecP256r1MLKEM768
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves X25519MLKEM768
      - [ ] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --curves SecP384r1MLKEM1024
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -k -v --http1.1
    - [x] openssl
      - [x] openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 --curves SecP256r1MLKEM768
      - [x] openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 --curves SecP384r1MLKEM1024
  - [x] TLS 1.2
    - [x] curl
      - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -k -v --tlsv1.2 --tls-max 1.2 --http1.1 --ciphers TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
