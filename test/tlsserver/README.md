#### test

* TLS 1.3 or TLS 1.2
  * ./test-tlsserver.exe -v -d -r &

* TLS 1.3 only
  * ./test-tlsserver.exe -v -d -r -tls13 &

* TLS 1.2 only
  * ./test-tlsserver.exe -v -d -r -tls12 &

* stop server
  * rm .run
