#### test

* TLS 1.3 or TLS 1.2
  * ./test-tlsserver.exe -r -k --trace &

* TLS 1.3 only
  * ./test-tlsserver.exe -r -k --trace -tls13 &

* TLS 1.2 only
  * ./test-tlsserver.exe -r -k --trace -tls12 &

* stop server
  * rm .run
