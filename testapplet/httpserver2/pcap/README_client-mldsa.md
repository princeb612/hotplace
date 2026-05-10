#### client

$ SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v -k --verbose
````
* Host localhost:9000 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:9000...
* ALPN: curl offers h2,http/1.1
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* SSL Trust: peer verification disabled
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.3 (IN), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
* TLSv1.3 (IN), TLS handshake, Certificate (11):
* TLSv1.3 (IN), TLS handshake, CERT verify (15):
* TLSv1.3 (IN), TLS handshake, Finished (20):
* TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768 / id-ml-dsa-65
* ALPN: server accepted h2
* Server certificate:
*   subject: C=KR; ST=KN; L=GJ; O=Test; OU=Test; CN=Test
*   start date: Apr 21 14:48:13 2026 GMT
*   expire date: Apr 21 14:48:13 2027 GMT
*   issuer: C=KR; ST=KN; L=GJ; O=Test; OU=Test; CN=Test Root
*   Certificate level 0: Public key type ML-DSA-65 (15616/192 Bits/secBits), signed using ML-DSA-65
* OpenSSL verify result: 14
*  SSL certificate verification failed, continuing anyway!
* SSLKEYLOGFILE set, all TLS secrets are logged to 'sslkeylog'
* Established connection to localhost (::1 port 9000) from ::1 port 12351
* using HTTP/2
* [HTTP/2] [1] OPENED stream for https://localhost:9000/
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: https]
* [HTTP/2] [1] [:authority: localhost:9000]
* [HTTP/2] [1] [:path: /]
* [HTTP/2] [1] [user-agent: curl/8.20.0]
* [HTTP/2] [1] [accept: */*]
> GET / HTTP/2
> Host: localhost:9000
> User-Agent: curl/8.20.0
> Accept: */*
>
* Request completely sent off
< HTTP/2 200
< content-type: text/html
< content-length: 291
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
</html>* Connection #0 to host localhost:9000 left intact
````

[TOC](README.md)
