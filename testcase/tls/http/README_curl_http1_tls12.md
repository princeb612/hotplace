#### HTTP/1.1

````
$ SSLKEYLOGFILE=sslkeylog curl -s https://www.google.com/ -v -I --tlsv1.2 --tls-max 1.2 --http1.1 --ciphers TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* Host www.google.com:443 was resolved.
* IPv6: (none)
* IPv4: 142.250.76.132
*   Trying 142.250.76.132:443...
* Cipher selection: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
* ALPN: curl offers http/1.1
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
*  CAfile: C:/Home/msys64/mingw64/etc/ssl/certs/ca-bundle.crt
*  CApath: none
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / x25519 / RSASSA-PSS
* ALPN: server accepted http/1.1
* Server certificate:
*  subject: CN=www.google.com
*  start date: Jun  2 08:37:21 2025 GMT
*  expire date: Aug 25 08:37:20 2025 GMT
*  subjectAltName: host "www.google.com" matched cert's "www.google.com"
*  issuer: C=US; O=Google Trust Services; CN=WR2
*  SSL certificate verify ok.
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 1: Public key type RSA (2048/112 Bits/secBits), signed using sha256WithRSAEncryption
*   Certificate level 2: Public key type RSA (4096/152 Bits/secBits), signed using sha384WithRSAEncryption
* Connected to www.google.com (142.250.76.132) port 443
* using HTTP/1.x
> HEAD / HTTP/1.1
> Host: www.google.com
> User-Agent: curl/8.11.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Content-Type: text/html; charset=ISO-8859-1
Content-Type: text/html; charset=ISO-8859-1
< Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-YpYKVgfjjlMg4rW2POQc3A' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-YpYKVgfjjlMg4rW2POQc3A' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
< Accept-CH: Sec-CH-Prefers-Color-Scheme
Accept-CH: Sec-CH-Prefers-Color-Scheme
< P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
< Date: Fri, 20 Jun 2025 05:06:56 GMT
Date: Fri, 20 Jun 2025 05:06:56 GMT
< Server: gws
Server: gws
< X-XSS-Protection: 0
X-XSS-Protection: 0
< X-Frame-Options: SAMEORIGIN
X-Frame-Options: SAMEORIGIN
< Transfer-Encoding: chunked
Transfer-Encoding: chunked
< Expires: Fri, 20 Jun 2025 05:06:56 GMT
Expires: Fri, 20 Jun 2025 05:06:56 GMT
< Cache-Control: private
Cache-Control: private
< Set-Cookie: AEC=AVh_V2h8Qf0U85Lvc_XxltkvZ_eQZG4JugRIHWMQADwqrCF8-zeJq46DuA; expires=Wed, 17-Dec-2025 05:06:56 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
Set-Cookie: AEC=AVh_V2h8Qf0U85Lvc_XxltkvZ_eQZG4JugRIHWMQADwqrCF8-zeJq46DuA; expires=Wed, 17-Dec-2025 05:06:56 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
< Set-Cookie: NID=525=SjdqamTvr7xBbHeq69r8l4ydRgaTRXTX7_4BM5QBjBJcGIOe7CdEqBiCLA2W3SZRv3QkldsgdxoX0gX1DDXsZDl7G1PZHExFn1Uj0LjmyZpi1FBcb_S5k_VcEm48qD4f8n-0EN9sRsq8F3itNYianpA7ca6aE9IngCn0r0fWBQYAW7DL1OVuBhwspyuyQUgMgpqV2GDx_FyCqfU; expires=Sat, 20-Dec-2025 05:06:56 GMT; path=/; domain=.google.com; HttpOnly
Set-Cookie: NID=525=SjdqamTvr7xBbHeq69r8l4ydRgaTRXTX7_4BM5QBjBJcGIOe7CdEqBiCLA2W3SZRv3QkldsgdxoX0gX1DDXsZDl7G1PZHExFn1Uj0LjmyZpi1FBcb_S5k_VcEm48qD4f8n-0EN9sRsq8F3itNYianpA7ca6aE9IngCn0r0fWBQYAW7DL1OVuBhwspyuyQUgMgpqV2GDx_FyCqfU; expires=Sat, 20-Dec-2025 05:06:56 GMT; path=/; domain=.google.com; HttpOnly
< Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
<

* Connection #0 to host www.google.com left intact
````

[TOC](README.md)
