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
* ALPN: server accepted http/1.1
* Server certificate:
*   subject: C=KR; ST=KN; L=GJ; O=Test; OU=Test; CN=Test
*   start date: Apr 21 14:48:13 2026 GMT
*   expire date: Apr 21 14:48:13 2027 GMT
*   issuer: C=KR; ST=KN; L=GJ; O=Test; OU=Test; CN=Test Root
*   Certificate level 0: Public key type ML-DSA-65 (15616/192 Bits/secBits), signed using ML-DSA-65
* OpenSSL verify result: 14
*  SSL certificate verification failed, continuing anyway!
* Established connection to localhost (::1 port 9000) from ::1 port 1132
* using HTTP/1.x
> GET / HTTP/1.1
> Host: localhost:9000
> User-Agent: curl/8.19.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Content-Type: text/html
< Connection: Keep-Alive
< Content-Length: 3112
<
<!DOCTYPE html>
<html>
<head>
  <title>HTTP Authentication</title>
  <meta charset="UTF-8">
  <link href="style.css" rel="stylesheet" type="text/css" />
  <script>
    function resource_owner_password_credentials_grant_handler() {
      var req = new XMLHttpRequest();
      req.open("POST", "/auth/token");
      req.setRequestHeader("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
      req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      req.send("grant_type=password&username=user&password=password&client_id=s6BhdRkqt3");

      req.onload = () => {
        alert(req.responseText);
      }
    }
    function client_credentials_grant_handler() {
      var req = new XMLHttpRequest();
      req.open("POST", "/auth/token");
      req.setRequestHeader("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
      req.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
      req.send("grant_type=client_credentials&client_id=s6BhdRkqt3");

      req.onload = () => {
        alert(req.responseText);
      }
    }
  </script>
</head>
<body>
  <table>
    <tr>
      <th>testcase</th>
      <th>realm</th>
      <th>username</th>
      <th>password</th>
    </tr>
    <tr>
      <td><a href="/auth/basic">Basic Authentication (RFC 2617)</a></td>
      <td>Hello World</td>
      <td>user</td>
      <td>password</td>
    </tr>
    <tr>
      <td><a href="/auth/digest">Digest Authentication (RFC 2617))</a></td>
      <td>happiness</td>
      <td>user</td>
      <td>password</td>
    </tr>
    <tr>
      <td><a href="/auth/userhash">Digest Authentication userhash (RFC 7616)</a></td>
      <td>testrealm@host.com</td>
      <td>Mufasa</td>
      <td>Circle Of Life</td>
    </tr>
    <!--
    <tr>
      <td><a href="/auth/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Flocalhost:9000%2Fclient%2Fcb">Authorization Code Grant (RFC 6749 4.1.)</a></td>
      <td/>
      <td>user</td>
      <td>password</td>
    </tr>
    <tr>
      <td><a href="/auth/authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Flocalhost:9000%2Fclient%2Fcb">Implicit Grant (RFC 6749 4.2.)</a></td>
      <td/>
      <td/>
      <td/>
    </tr>
    <tr>
      <td><a href="javascript:void(0);" onclick="resource_owner_password_credentials_grant_handler();">Resource Owner Password Credentials Grant (RFC 6749 4.3.)</a></td>
      <td/>
      <td/>
      <td/>
    </tr>
    <tr>
      <td><a href="javascript:void(0);" onclick="client_credentials_grant_handler();">Client Credentials Grant (RFC 6749 4.4.)</a></td>
      <td/>
      <td/>
      <td/>
    </tr>
    -->
    <tr>
      <td><a href="https://[::1]:9000/">IPv6</a></td>
      <td/>
      <td/>
      <td/>
    </tr>
    <tr>
      <td><a href="http://localhost:8080/">HTTP</a></td>
      <td/>
      <td/>
      <td/>
    </tr>
  </table>
  <p>Hello world</p>
  <ul>
    <li><a href="/api/html">html response</a></li>
    <li><a href="/api/json">json response</a></li>
    <li><a href="/api/test">response</a></li>
  </ul>
</body>
</html>
* Connection #0 to host localhost:9000 left intact
````

[TOC](README.md)
