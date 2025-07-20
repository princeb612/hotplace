#### curl_http1_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.pcapng - client

````
$ SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v --tlsv1.2 --tls-max 1.2 --http1.1 --ciphers TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 -k
* Host localhost:9000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:9000...
* Cipher selection: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
* ALPN: curl offers http/1.1
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-CHACHA20-POLY1305 / x25519 / RSASSA-PSS
* ALPN: server accepted http/1.1
* Server certificate:
*  subject: C=KR; ST=GG; L=YI; O=Test; OU=Test; CN=Test
*  start date: Aug 29 06:27:17 2024 GMT
*  expire date: Aug 29 06:27:17 2025 GMT
*  issuer: C=KR; ST=GG; L=YI; O=Test; OU=Test; CN=Test Root
*  SSL certificate verify result: unable to get local issuer certificate (20), continuing anyway.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
* Connected to localhost (::1) port 9000
* using HTTP/1.x
> GET / HTTP/1.1
> Host: localhost:9000
> User-Agent: curl/8.11.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Content-Type: text/html
< Connection: Keep-Alive
< Content-Length: 291
<
<!DOCTYPE html>
<html>
<head>
  <title>test</title>
  <meta charset="UTF-8">
</head>
<body>
  <p>Hello world</p>
  <ul>
    <li><a href="/api/html">html response</a></li>
    <li><a href="/api/json">json response</a></li>
    <li><a href="/api/test">response</a></li>
  </ul>
</body>
</html>* Connection #0 to host localhost left intact
````

[TOC](README.md)
