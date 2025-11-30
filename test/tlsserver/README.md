#### test

* TLS 1.3 or TLS 1.2
  * ./test-tlsserver.exe -r -k --trace &

* TLS 1.3 only
  * ./test-tlsserver.exe -r -k --trace -tls13 &

* TLS 1.2 only
  * ./test-tlsserver.exe -r -k --trace -tls12 &

* stop server
  * rm .run

* [x] ML-KEM Post-Quantum Key Agreement for TLS 1.3
  * [x] [draft-ietf-tls-mlkem-05](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/)
  * [x] [draft-ietf-tls-ecdhe-mlkem-03](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
  * [x] test
    * [x] server
      * [x] ./test-tlsserver.exe -r -k -T --trace -tls13
        * -T TLS implementation
    * [x] client
      * [x] openssl s_client -connect localhost:9000 -state -msg -trace -debug -keylogfile sslkeylog -tls1_3 -groups MLKEM512:MLKEM768:MLKEM1024
      * [x] openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 --curves SecP256r1MLKEM768
