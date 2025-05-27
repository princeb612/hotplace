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

| status                     | MINGW | LINUX | TLSv1.3 | TLSv1.2 |
| --                         | --    | --    | --      | --      |
| naive_tcp_client_socket    | PASS  | PASS  | N/A     | N/A     |
| naive_udp_client_socket    | PASS  | PASS  | N/A     | N/A     |
| trial_tcp_client_socket    | PASS  | PASS  | N/A     | N/A     |
| trial_udp_client_socket    | PASS  | PASS  | N/A     | N/A     |
| openssl_tls_client_socket  | PASS  | PASS  | PASS    | PASS    |
| openssl_dtls_client_socket | PASS  | PASS  | N/A     | PASS    |
| trial_tls_client_socket    | PASS  | PASS  | PASS    | PASS    |
| trial_dtls_client_socket   | PASS  | PASS  | -       | PASS    |

3. help

* TLS 1.2
  * ./test-netclient -v -d -P tls12 -i
* TLS 1.3
  * ./test-netclient -v -d -P tls13 -i
