### test

1. test

| case     | server      | client    |
| --       | --          | --        |
| TCP      | tcpserver1  | netclient |
| TCP      | tcpserver2  | netclient |
| UDP      | udpserver1  | netclient |
| UDP      | udpserver2  | netclient |
| TLS      | tlsserver   | netclient |
| DTLS     | dtlsserver  | netclient |
| http/1.1 | httpserver1 | chrome    |
| h2       | httpserver2 | chrome    |

2. result

| status                    | MINGW | LINUX |
| --                        | --    | --    |
| tcp_client_socket         | PASS  | PASS  |
| udp_client_socket         | PASS  | PASS  |
| tls_client_socket         | PASS  | PASS  |
| dtls_client_socket        | PASS  | PASS  |
| async_tcp_client_socket   | PASS  | PASS  |
| async_udp_client_socket   | PASS  | PASS  |
| async_tls_client_socket   | PASS  | todo1 |
| async_dtls_client_socket  | -     | -     |

- todo1
  - sometimes EVP_CipherFinal while decryption
