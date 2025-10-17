#### test

* TLS 1.3 or TLS 1.2
  * ./test-tlsserver.exe -r -k --trace &

* TLS 1.3 only
  * ./test-tlsserver.exe -r -k --trace -tls13 &

* TLS 1.2 only
  * ./test-tlsserver.exe -r -k --trace -tls12 &

* stop server
  * rm .run

* [x] MLKEM
  * [x] server
    * [x] ./test-tlsserver.exe -r -k -T --trace -tls13
  * [x] client
    * [x] openssl s_client -connect localhost:9000 -state -msg -trace -debug -keylogfile sslkeylog -tls1_3 -groups MLKEM512:MLKEM768:MLKEM1024

* hybrid MLKEM
  * TODO
