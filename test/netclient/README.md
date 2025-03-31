### test

1. test

| case     | server      | client            |
| --       | --          | --                |
| TCP      | tcpserver1  | netclient         |
| TCP      | tcpserver2  | netclient         |
| UDP      | udpserver1  | netclient         |
| UDP      | udpserver2  | netclient         |
| TLS      | tlsserver   | netclient         |
| DTLS     | dtlsserver  | netclient         |
| http/1.1 | httpserver1 | chrome, netclient |
| h2       | httpserver2 | chrome            |

2. progress

| status                      | MINGW | LINUX | TLSv1.3 | TLSv1.2 |
| --                          | --    | --    | --      | --      |
| tcp_client_socket           | PASS  | PASS  | N/A     | N/A     |
| udp_client_socket           | PASS  | PASS  | N/A     | N/A     |
| async_tcp_client_socket     | PASS  | PASS  | N/A     | N/A     |
| async_udp_client_socket     | PASS  | PASS  | N/A     | N/A     |
| tls_client_socket (openssl) | PASS  | PASS  | PASS    | PASS    |
| dtls_client_socket(openssl) | PASS  | PASS  | N/A     | PASS    |
| async_tls_client_socket     | PASS  | study | PASS    | PASS    |
| async_dtls_client_socket    | study | study | -       | study   |
