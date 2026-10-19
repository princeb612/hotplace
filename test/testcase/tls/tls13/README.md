#### TLS 1.3

> [!NOTE]
> MLKEM512, MLKEM768, MLKEM1024 - openssl 3.5 required

- [sslkeylog](sslkeylog)
- tls13_TLS_AES_256_GCM_SHA384.pcapng
  - [server](tls13_TLS_AES_256_GCM_SHA384-server.md)
  - [client](tls13_TLS_AES_256_GCM_SHA384-client.md)
- tls13_TLS_AES_128_GCM_SHA256.pcapng
  - [server](tls13_TLS_AES_128_GCM_SHA256-server.md)
  - [client](tls13_TLS_AES_128_GCM_SHA256-client.md)
- tls13_TLS_AES_128_CCM_SHA256.pcapng
  - [server](tls13_TLS_AES_128_CCM_SHA256-server.md)
  - [client](tls13_TLS_AES_128_CCM_SHA256-client.md)
- tls13_TLS_CHACHA20_POLY1305_SHA256.pcapng
  - [server](tls13_TLS_CHACHA20_POLY1305_SHA256-server.md)
  - [client](tls13_TLS_CHACHA20_POLY1305_SHA256-client.md)
- tls13_TLS_AES_128_CCM_SHA256_MLKEM512.pcapng
  - [server](tls13_TLS_AES_128_CCM_SHA256_MLKEM512-server.md)
  - [client](tls13_TLS_AES_128_CCM_SHA256_MLKEM512-client.md)
- tls13_TLS_AES_128_CCM_SHA256_MLKEM768.pcapng
  - [server](tls13_TLS_AES_128_CCM_SHA256_MLKEM768-server.md)
  - [client](tls13_TLS_AES_128_CCM_SHA256_MLKEM768-client.md)
- tls13_TLS_AES_128_CCM_SHA256_MLKEM1024.pcapng
  - [server](tls13_TLS_AES_128_CCM_SHA256_MLKEM1024-server.md)
  - [client](tls13_TLS_AES_128_CCM_SHA256_MLKEM1024-client.md)
- tls13_TLS_AES_128_CCM_SHA256_SecP256r1MLKEM768.pcapng
  - [server](tls13_TLS_AES_128_CCM_SHA256_SecP256r1MLKEM768-server.md)
  - [client](tls13_TLS_AES_128_CCM_SHA256_SecP256r1MLKEM768-client.md)
- tls13_TLS_AES_128_CCM_SHA256_X25519MLKEM768.pcapng
  - [server](tls13_TLS_AES_128_CCM_SHA256_X25519MLKEM768-server.md)
  - [client](tls13_TLS_AES_128_CCM_SHA256_X25519MLKEM768-client.md)
- tls13_TLS_AES_128_CCM_SHA256_SecP384r1MLKEM1024.pcapng
  - [server](tls13_TLS_AES_128_CCM_SHA256_SecP384r1MLKEM1024-server.md)
  - [client](tls13_TLS_AES_128_CCM_SHA256_SecP384r1MLKEM1024-client.md)
- tls13_TLS_AES_256_GCM_SHA384_SecP256r1MLKEM768.pcapng
  - [server](tls13_TLS_AES_256_GCM_SHA384_SecP256r1MLKEM768-server.md)
  - [client](tls13_TLS_AES_256_GCM_SHA384_SecP256r1MLKEM768-client.md)
- tls13_TLS_AES_256_GCM_SHA384_SecP384r1MLKEM1024.pcapng
  - [server](tls13_TLS_AES_256_GCM_SHA384_SecP384r1MLKEM1024-server.md)
  - [client](tls13_TLS_AES_256_GCM_SHA384_SecP384r1MLKEM1024-client.md)
- handshake_failure.pcapng
  - [server](handshake_failure-server.md)
  - [client](handshake_failure-client.md)


## Capture organization and backend requirements

The captures cover several TLS 1.3 AEAD suites and key-exchange variants, with a matching client/server note for each named scenario. The existing note states that ML-KEM 512/768/1024 cases require OpenSSL 3.5; availability is therefore dependent on the crypto backend version, not solely on hotplace's test source.

The `sslkeylog` file is intended for packet decryption in a controlled test. These captures document selected handshakes and negotiated suites, not every TLS 1.3 extension or a complete interoperability matrix.
