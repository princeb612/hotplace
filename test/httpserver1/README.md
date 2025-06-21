#### test

```
# run
./test-httpserver1 -v -d -r &

# chrome
# https://localhost:9000/

# stop
rm .run
```

- [x] tasks
  - [x] network_server
  - [x] HTTP/1.1
  - [x] libssl
  - [x] trial
  - [x] TLS 1.3
    - [x] chrome
    - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -k -v --http1.1
  - [x] TLS 1.2
    - [x] SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -k -v --tlsv1.2 --tls-max 1.2 --http1.1 --ciphers TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
