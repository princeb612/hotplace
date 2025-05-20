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
| tcp_client_socket2          | PASS  | PASS  | N/A     | N/A     |
| udp_client_socket2          | PASS  | PASS  | N/A     | N/A     |
| tls_client_socket (openssl) | PASS  | PASS  | PASS    | PASS    |
| dtls_client_socket(openssl) | PASS  | PASS  | N/A     | PASS    |
| tls_client_socket2          | PASS  | PASS  | PASS    | PASS    |
| dtls_client_socket2         | PASS  | PASS  | -       | PASS    |

3. help

* TLS 1.2
  * ./test-netclient -v -d -P tls12 -i
* TLS 1.3
  * ./test-netclient -v -d -P tls13 -i
