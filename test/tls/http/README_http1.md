#### HTTP/1.1

$ ./test-httpserver1.exe -r --debug &

````
[test case] http/1.1 powered by http_server
flag 00000001
min proto version 00000303
max proto version 00000304
socket 512 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 0000020c created
socket 568 created family 23(AF_INET6) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 0000023c created
socket 620 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 00000270 created
socket 660 created family 23(AF_INET6) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000002a0 created
- event_loop_new tid 000066bc
- event_loop_new tid 000077bc
- event_loop_new tid 000056ec
- event_loop_new tid 00006b68
- event_loop_new tid 00009040
- event_loop_new tid 00007338
- event_loop_new tid 000047a4
- event_loop_new tid 00003a20
- event_loop_new tid 00004034
- event_loop_new tid 00001ea8
- event_loop_new tid 000019b4
- event_loop_new tid 00004a68
- event_loop_new tid 00007920
- event_loop_new tid 000095fc
- event_loop_new tid 00009380
- event_loop_new tid 00006a78
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:(NONE)
SERVER_HANDSHAKE_TRAFFIC_SECRET c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 03baaf4ead28ab678c4c6643185eb1fe2699de129cd39e341579d82a7b7218b6
CLIENT_HANDSHAKE_TRAFFIC_SECRET c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 8096092572254ce5bc0d0f1609ff6e0b9f0de2a2789c0e327504db5b3d8c09e2
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write certificate:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write server certificate verify:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 3d371adf33f888bd3b88f1249c6009621881c29368107f2741b40a8b9d9c7767
SERVER_TRAFFIC_SECRET_0 c126cfafae8cb4f1ec61468e6f8b16db41bcb2bd16ff0c81610f8c40c5d028e4 014469a0a1e8ca364a554a7dde68ab18d7a4c611d0bc5adc71952dc78fb7018d
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00002002 SSL_accept:exit:TLSv1.3 early data
TLS 00000304 00004004 SSL_read:callback:fatal:certificate unknown
TLS 00000304 00002002 SSL_accept:exit:error
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:(NONE)
SERVER_HANDSHAKE_TRAFFIC_SECRET f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 cb49c716f80e75180c4e0337b88d305c15fd59459945124fa95fae1cc73522c0
CLIENT_HANDSHAKE_TRAFFIC_SECRET f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 3f376c10a23552fc894187c1dbe853a72ac737f68ae4778f353d4daaa37963ad
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write certificate:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write server certificate verify:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 d55fc9a65345c41ea52f76071340638216287b336a188e1c1c00d3012c371013
SERVER_TRAFFIC_SECRET_0 f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 1c6a88896c6103e4c5d2f64a98809ffb6671ec792e2953873644f65ef6945882
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
CLIENT_TRAFFIC_SECRET_0 f9cef6ee59e41f07f495a835982451150e5ad090ff6b33547b56a364f58e8b62 cd158cbf6313b8bffff5bc2236ae2caeba6f39b57f02c9aefdc076a67f23e7d6
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00000020 handshake done
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write session ticket:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write session ticket:TLS_AES_128_GCM_SHA256
TLS 00000304 00002002 SSL_accept:exit:SSL negotiation finished successfully
iocp handle 0000023c bind 984
[ns] read 984
  00000000 : 47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A | GET / HTTP/1.1..
  00000010 : 48 6F 73 74 3A 20 6C 6F 63 61 6C 68 6F 73 74 3A | Host: localhost:
  00000020 : 39 30 30 30 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E | 9000..Connection
  00000030 : 3A 20 6B 65 65 70 2D 61 6C 69 76 65 0D 0A 73 65 | : keep-alive..se
  00000040 : 63 2D 63 68 2D 75 61 3A 20 22 47 6F 6F 67 6C 65 | c-ch-ua: "Google
  00000050 : 20 43 68 72 6F 6D 65 22 3B 76 3D 22 31 33 37 22 |  Chrome";v="137"
  00000060 : 2C 20 22 43 68 72 6F 6D 69 75 6D 22 3B 76 3D 22 | , "Chromium";v="
  00000070 : 31 33 37 22 2C 20 22 4E 6F 74 2F 41 29 42 72 61 | 137", "Not/A)Bra
  00000080 : 6E 64 22 3B 76 3D 22 32 34 22 0D 0A 73 65 63 2D | nd";v="24"..sec-
  00000090 : 63 68 2D 75 61 2D 6D 6F 62 69 6C 65 3A 20 3F 30 | ch-ua-mobile: ?0
  000000A0 : 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 70 6C 61 74 | ..sec-ch-ua-plat
  000000B0 : 66 6F 72 6D 3A 20 22 57 69 6E 64 6F 77 73 22 0D | form: "Windows".
  000000C0 : 0A 55 70 67 72 61 64 65 2D 49 6E 73 65 63 75 72 | .Upgrade-Insecur
  000000D0 : 65 2D 52 65 71 75 65 73 74 73 3A 20 31 0D 0A 55 | e-Requests: 1..U
  000000E0 : 73 65 72 2D 41 67 65 6E 74 3A 20 4D 6F 7A 69 6C | ser-Agent: Mozil
  000000F0 : 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 | la/5.0 (Windows
  00000100 : 4E 54 20 31 30 2E 30 3B 20 57 69 6E 36 34 3B 20 | NT 10.0; Win64;
  00000110 : 78 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 | x64) AppleWebKit
  00000120 : 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 | /537.36 (KHTML,
  00000130 : 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F | like Gecko) Chro
  00000140 : 6D 65 2F 31 33 37 2E 30 2E 30 2E 30 20 53 61 66 | me/137.0.0.0 Saf
  00000150 : 61 72 69 2F 35 33 37 2E 33 36 0D 0A 41 63 63 65 | ari/537.36..Acce
  00000160 : 70 74 3A 20 74 65 78 74 2F 68 74 6D 6C 2C 61 70 | pt: text/html,ap
  00000170 : 70 6C 69 63 61 74 69 6F 6E 2F 78 68 74 6D 6C 2B | plication/xhtml+
  00000180 : 78 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F 6E 2F | xml,application/
  00000190 : 78 6D 6C 3B 71 3D 30 2E 39 2C 69 6D 61 67 65 2F | xml;q=0.9,image/
  000001A0 : 61 76 69 66 2C 69 6D 61 67 65 2F 77 65 62 70 2C | avif,image/webp,
  000001B0 : 69 6D 61 67 65 2F 61 70 6E 67 2C 2A 2F 2A 3B 71 | image/apng,*/*;q
  000001C0 : 3D 30 2E 38 2C 61 70 70 6C 69 63 61 74 69 6F 6E | =0.8,application
  000001D0 : 2F 73 69 67 6E 65 64 2D 65 78 63 68 61 6E 67 65 | /signed-exchange
  000001E0 : 3B 76 3D 62 33 3B 71 3D 30 2E 37 0D 0A 53 65 63 | ;v=b3;q=0.7..Sec
  000001F0 : 2D 46 65 74 63 68 2D 53 69 74 65 3A 20 6E 6F 6E | -Fetch-Site: non
  00000200 : 65 0D 0A 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 | e..Sec-Fetch-Mod
  00000210 : 65 3A 20 6E 61 76 69 67 61 74 65 0D 0A 53 65 63 | e: navigate..Sec
  00000220 : 2D 46 65 74 63 68 2D 55 73 65 72 3A 20 3F 31 0D | -Fetch-User: ?1.
  00000230 : 0A 53 65 63 2D 46 65 74 63 68 2D 44 65 73 74 3A | .Sec-Fetch-Dest:
  00000240 : 20 64 6F 63 75 6D 65 6E 74 0D 0A 41 63 63 65 70 |  document..Accep
  00000250 : 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 70 | t-Encoding: gzip
  00000260 : 2C 20 64 65 66 6C 61 74 65 2C 20 62 72 2C 20 7A | , deflate, br, z
  00000270 : 73 74 64 0D 0A 41 63 63 65 70 74 2D 4C 61 6E 67 | std..Accept-Lang
  00000280 : 75 61 67 65 3A 20 6B 6F 2D 4B 52 2C 6B 6F 3B 71 | uage: ko-KR,ko;q
  00000290 : 3D 30 2E 39 2C 65 6E 2D 55 53 3B 71 3D 30 2E 38 | =0.9,en-US;q=0.8
  000002A0 : 2C 65 6E 3B 71 3D 30 2E 37 0D 0A 0D 0A -- -- -- | ,en;q=0.7....
GET / HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 32 39 31 0D 0A 0D 0A 3C 21 44 4F 43 54 59 | : 291....<!DOCTY
  00000060 : 50 45 20 68 74 6D 6C 3E 0A 3C 68 74 6D 6C 3E 0A | PE html>.<html>.
  00000070 : 3C 68 65 61 64 3E 0A 20 20 3C 74 69 74 6C 65 3E | <head>.  <title>
  00000080 : 74 65 73 74 3C 2F 74 69 74 6C 65 3E 0A 20 20 3C | test</title>.  <
  00000090 : 6D 65 74 61 20 63 68 61 72 73 65 74 3D 22 55 54 | meta charset="UT
  000000A0 : 46 2D 38 22 3E 0A 3C 2F 68 65 61 64 3E 0A 3C 62 | F-8">.</head>.<b
  000000B0 : 6F 64 79 3E 0A 20 20 3C 70 3E 48 65 6C 6C 6F 20 | ody>.  <p>Hello
  000000C0 : 77 6F 72 6C 64 3C 2F 70 3E 0A 20 20 3C 75 6C 3E | world</p>.  <ul>
  000000D0 : 0A 20 20 20 20 3C 6C 69 3E 3C 61 20 68 72 65 66 | .    <li><a href
  000000E0 : 3D 22 2F 61 70 69 2F 68 74 6D 6C 22 3E 68 74 6D | ="/api/html">htm
  000000F0 : 6C 20 72 65 73 70 6F 6E 73 65 3C 2F 61 3E 3C 2F | l response</a></
  00000100 : 6C 69 3E 0A 20 20 20 20 3C 6C 69 3E 3C 61 20 68 | li>.    <li><a h
  00000110 : 72 65 66 3D 22 2F 61 70 69 2F 6A 73 6F 6E 22 3E | ref="/api/json">
  00000120 : 6A 73 6F 6E 20 72 65 73 70 6F 6E 73 65 3C 2F 61 | json response</a
  00000130 : 3E 3C 2F 6C 69 3E 0A 20 20 20 20 3C 6C 69 3E 3C | ></li>.    <li><
  00000140 : 61 20 68 72 65 66 3D 22 2F 61 70 69 2F 74 65 73 | a href="/api/tes
  00000150 : 74 22 3E 72 65 73 70 6F 6E 73 65 3C 2F 61 3E 3C | t">response</a><
  00000160 : 2F 6C 69 3E 0A 20 20 3C 2F 75 6C 3E 0A 3C 2F 62 | /li>.  </ul>.</b
  00000170 : 6F 64 79 3E 0A 3C 2F 68 74 6D 6C 3E -- -- -- -- | ody>.</html>
[ns] read 984
  00000000 : 47 45 54 20 2F 66 61 76 69 63 6F 6E 2E 69 63 6F | GET /favicon.ico
  00000010 : 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A |  HTTP/1.1..Host:
  00000020 : 20 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D |  localhost:9000.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 | .Connection: kee
  00000040 : 70 2D 61 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D | p-alive..sec-ch-
  00000050 : 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 69 | ua-platform: "Wi
  00000060 : 6E 64 6F 77 73 22 0D 0A 55 73 65 72 2D 41 67 65 | ndows"..User-Age
  00000070 : 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 | nt: Mozilla/5.0
  00000080 : 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 | (Windows NT 10.0
  00000090 : 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 | ; Win64; x64) Ap
  000000A0 : 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 | pleWebKit/537.36
  000000B0 : 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 |  (KHTML, like Ge
  000000C0 : 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E | cko) Chrome/137.
  000000D0 : 30 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 | 0.0.0 Safari/537
  000000E0 : 2E 33 36 0D 0A 73 65 63 2D 63 68 2D 75 61 3A 20 | .36..sec-ch-ua:
  000000F0 : 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 3B | "Google Chrome";
  00000100 : 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D 69 | v="137", "Chromi
  00000110 : 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E 6F | um";v="137", "No
  00000120 : 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 34 | t/A)Brand";v="24
  00000130 : 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F 62 | "..sec-ch-ua-mob
  00000140 : 69 6C 65 3A 20 3F 30 0D 0A 41 63 63 65 70 74 3A | ile: ?0..Accept:
  00000150 : 20 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 67 |  image/avif,imag
  00000160 : 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 6E | e/webp,image/apn
  00000170 : 67 2C 69 6D 61 67 65 2F 73 76 67 2B 78 6D 6C 2C | g,image/svg+xml,
  00000180 : 69 6D 61 67 65 2F 2A 2C 2A 2F 2A 3B 71 3D 30 2E | image/*,*/*;q=0.
  00000190 : 38 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 69 74 | 8..Sec-Fetch-Sit
  000001A0 : 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E 0D 0A | e: same-origin..
  000001B0 : 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 3A 20 | Sec-Fetch-Mode:
  000001C0 : 6E 6F 2D 63 6F 72 73 0D 0A 53 65 63 2D 46 65 74 | no-cors..Sec-Fet
  000001D0 : 63 68 2D 44 65 73 74 3A 20 69 6D 61 67 65 0D 0A | ch-Dest: image..
  000001E0 : 52 65 66 65 72 65 72 3A 20 68 74 74 70 73 3A 2F | Referer: https:/
  000001F0 : 2F 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 2F | /localhost:9000/
  00000200 : 0D 0A 41 63 63 65 70 74 2D 45 6E 63 6F 64 69 6E | ..Accept-Encodin
  00000210 : 67 3A 20 67 7A 69 70 2C 20 64 65 66 6C 61 74 65 | g: gzip, deflate
  00000220 : 2C 20 62 72 2C 20 7A 73 74 64 0D 0A 41 63 63 65 | , br, zstd..Acce
  00000230 : 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 6B 6F 2D | pt-Language: ko-
  00000240 : 4B 52 2C 6B 6F 3B 71 3D 30 2E 39 2C 65 6E 2D 55 | KR,ko;q=0.9,en-U
  00000250 : 53 3B 71 3D 30 2E 38 2C 65 6E 3B 71 3D 30 2E 37 | S;q=0.8,en;q=0.7
  00000260 : 0D 0A 0D 0A -- -- -- -- -- -- -- -- -- -- -- -- | ....
GET /favicon.ico HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://localhost:9000/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 36 32 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 62....<html><b
  00000060 : 6F 64 79 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E | ody>404 Not Foun
  00000070 : 64 3C 70 72 65 3E 2F 66 61 76 69 63 6F 6E 2E 69 | d<pre>/favicon.i
  00000080 : 63 6F 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | co</pre></body><
  00000090 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
[ns] read 984
  00000000 : 47 45 54 20 2F 61 70 69 2F 68 74 6D 6C 20 48 54 | GET /api/html HT
  00000010 : 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 6C 6F | TP/1.1..Host: lo
  00000020 : 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D 0A 43 6F | calhost:9000..Co
  00000030 : 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 70 2D 61 | nnection: keep-a
  00000040 : 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D 75 61 3A | live..sec-ch-ua:
  00000050 : 20 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 |  "Google Chrome"
  00000060 : 3B 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D | ;v="137", "Chrom
  00000070 : 69 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E | ium";v="137", "N
  00000080 : 6F 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 | ot/A)Brand";v="2
  00000090 : 34 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F | 4"..sec-ch-ua-mo
  000000A0 : 62 69 6C 65 3A 20 3F 30 0D 0A 73 65 63 2D 63 68 | bile: ?0..sec-ch
  000000B0 : 2D 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 | -ua-platform: "W
  000000C0 : 69 6E 64 6F 77 73 22 0D 0A 55 70 67 72 61 64 65 | indows"..Upgrade
  000000D0 : 2D 49 6E 73 65 63 75 72 65 2D 52 65 71 75 65 73 | -Insecure-Reques
  000000E0 : 74 73 3A 20 31 0D 0A 55 73 65 72 2D 41 67 65 6E | ts: 1..User-Agen
  000000F0 : 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 | t: Mozilla/5.0 (
  00000100 : 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B | Windows NT 10.0;
  00000110 : 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 |  Win64; x64) App
  00000120 : 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 | leWebKit/537.36
  00000130 : 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 | (KHTML, like Gec
  00000140 : 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E 30 | ko) Chrome/137.0
  00000150 : 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 2E | .0.0 Safari/537.
  00000160 : 33 36 0D 0A 41 63 63 65 70 74 3A 20 74 65 78 74 | 36..Accept: text
  00000170 : 2F 68 74 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F | /html,applicatio
  00000180 : 6E 2F 78 68 74 6D 6C 2B 78 6D 6C 2C 61 70 70 6C | n/xhtml+xml,appl
  00000190 : 69 63 61 74 69 6F 6E 2F 78 6D 6C 3B 71 3D 30 2E | ication/xml;q=0.
  000001A0 : 39 2C 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 | 9,image/avif,ima
  000001B0 : 67 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 | ge/webp,image/ap
  000001C0 : 6E 67 2C 2A 2F 2A 3B 71 3D 30 2E 38 2C 61 70 70 | ng,*/*;q=0.8,app
  000001D0 : 6C 69 63 61 74 69 6F 6E 2F 73 69 67 6E 65 64 2D | lication/signed-
  000001E0 : 65 78 63 68 61 6E 67 65 3B 76 3D 62 33 3B 71 3D | exchange;v=b3;q=
  000001F0 : 30 2E 37 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 | 0.7..Sec-Fetch-S
  00000200 : 69 74 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E | ite: same-origin
  00000210 : 0D 0A 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 | ..Sec-Fetch-Mode
  00000220 : 3A 20 6E 61 76 69 67 61 74 65 0D 0A 53 65 63 2D | : navigate..Sec-
  00000230 : 46 65 74 63 68 2D 55 73 65 72 3A 20 3F 31 0D 0A | Fetch-User: ?1..
  00000240 : 53 65 63 2D 46 65 74 63 68 2D 44 65 73 74 3A 20 | Sec-Fetch-Dest:
  00000250 : 64 6F 63 75 6D 65 6E 74 0D 0A 52 65 66 65 72 65 | document..Refere
  00000260 : 72 3A 20 68 74 74 70 73 3A 2F 2F 6C 6F 63 61 6C | r: https://local
  00000270 : 68 6F 73 74 3A 39 30 30 30 2F 0D 0A 41 63 63 65 | host:9000/..Acce
  00000280 : 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 | pt-Encoding: gzi
  00000290 : 70 2C 20 64 65 66 6C 61 74 65 2C 20 62 72 2C 20 | p, deflate, br,
  000002A0 : 7A 73 74 64 0D 0A 41 63 63 65 70 74 2D 4C 61 6E | zstd..Accept-Lan
  000002B0 : 67 75 61 67 65 3A 20 6B 6F 2D 4B 52 2C 6B 6F 3B | guage: ko-KR,ko;
  000002C0 : 71 3D 30 2E 39 2C 65 6E 2D 55 53 3B 71 3D 30 2E | q=0.9,en-US;q=0.
  000002D0 : 38 2C 65 6E 3B 71 3D 30 2E 37 0D 0A 0D 0A -- -- | 8,en;q=0.7....
GET /api/html HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://localhost:9000/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 33 34 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 34....<html><b
  00000060 : 6F 64 79 3E 70 61 67 65 20 2D 20 6F 6B 3C 62 6F | ody>page - ok<bo
  00000070 : 64 79 3E 3C 2F 68 74 6D 6C 3E -- -- -- -- -- -- | dy></html>
[ns] read 984
  00000000 : 47 45 54 20 2F 66 61 76 69 63 6F 6E 2E 69 63 6F | GET /favicon.ico
  00000010 : 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A |  HTTP/1.1..Host:
  00000020 : 20 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D |  localhost:9000.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 | .Connection: kee
  00000040 : 70 2D 61 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D | p-alive..sec-ch-
  00000050 : 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 69 | ua-platform: "Wi
  00000060 : 6E 64 6F 77 73 22 0D 0A 55 73 65 72 2D 41 67 65 | ndows"..User-Age
  00000070 : 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 | nt: Mozilla/5.0
  00000080 : 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 | (Windows NT 10.0
  00000090 : 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 | ; Win64; x64) Ap
  000000A0 : 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 | pleWebKit/537.36
  000000B0 : 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 |  (KHTML, like Ge
  000000C0 : 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E | cko) Chrome/137.
  000000D0 : 30 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 | 0.0.0 Safari/537
  000000E0 : 2E 33 36 0D 0A 73 65 63 2D 63 68 2D 75 61 3A 20 | .36..sec-ch-ua:
  000000F0 : 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 3B | "Google Chrome";
  00000100 : 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D 69 | v="137", "Chromi
  00000110 : 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E 6F | um";v="137", "No
  00000120 : 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 34 | t/A)Brand";v="24
  00000130 : 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F 62 | "..sec-ch-ua-mob
  00000140 : 69 6C 65 3A 20 3F 30 0D 0A 41 63 63 65 70 74 3A | ile: ?0..Accept:
  00000150 : 20 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 67 |  image/avif,imag
  00000160 : 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 6E | e/webp,image/apn
  00000170 : 67 2C 69 6D 61 67 65 2F 73 76 67 2B 78 6D 6C 2C | g,image/svg+xml,
  00000180 : 69 6D 61 67 65 2F 2A 2C 2A 2F 2A 3B 71 3D 30 2E | image/*,*/*;q=0.
  00000190 : 38 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 69 74 | 8..Sec-Fetch-Sit
  000001A0 : 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E 0D 0A | e: same-origin..
  000001B0 : 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 3A 20 | Sec-Fetch-Mode:
  000001C0 : 6E 6F 2D 63 6F 72 73 0D 0A 53 65 63 2D 46 65 74 | no-cors..Sec-Fet
  000001D0 : 63 68 2D 44 65 73 74 3A 20 69 6D 61 67 65 0D 0A | ch-Dest: image..
  000001E0 : 52 65 66 65 72 65 72 3A 20 68 74 74 70 73 3A 2F | Referer: https:/
  000001F0 : 2F 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 2F | /localhost:9000/
  00000200 : 61 70 69 2F 68 74 6D 6C 0D 0A 41 63 63 65 70 74 | api/html..Accept
  00000210 : 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 70 2C | -Encoding: gzip,
  00000220 : 20 64 65 66 6C 61 74 65 2C 20 62 72 2C 20 7A 73 |  deflate, br, zs
  00000230 : 74 64 0D 0A 41 63 63 65 70 74 2D 4C 61 6E 67 75 | td..Accept-Langu
  00000240 : 61 67 65 3A 20 6B 6F 2D 4B 52 2C 6B 6F 3B 71 3D | age: ko-KR,ko;q=
  00000250 : 30 2E 39 2C 65 6E 2D 55 53 3B 71 3D 30 2E 38 2C | 0.9,en-US;q=0.8,
  00000260 : 65 6E 3B 71 3D 30 2E 37 0D 0A 0D 0A -- -- -- -- | en;q=0.7....
GET /favicon.ico HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://localhost:9000/api/html
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 36 32 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 62....<html><b
  00000060 : 6F 64 79 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E | ody>404 Not Foun
  00000070 : 64 3C 70 72 65 3E 2F 66 61 76 69 63 6F 6E 2E 69 | d<pre>/favicon.i
  00000080 : 63 6F 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | co</pre></body><
  00000090 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
[ns] read 984
  00000000 : 47 45 54 20 2F 66 61 76 69 63 6F 6E 2E 69 63 6F | GET /favicon.ico
  00000010 : 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A |  HTTP/1.1..Host:
  00000020 : 20 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D |  localhost:9000.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 | .Connection: kee
  00000040 : 70 2D 61 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D | p-alive..sec-ch-
  00000050 : 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 69 | ua-platform: "Wi
  00000060 : 6E 64 6F 77 73 22 0D 0A 55 73 65 72 2D 41 67 65 | ndows"..User-Age
  00000070 : 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 | nt: Mozilla/5.0
  00000080 : 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 | (Windows NT 10.0
  00000090 : 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 | ; Win64; x64) Ap
  000000A0 : 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 | pleWebKit/537.36
  000000B0 : 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 |  (KHTML, like Ge
  000000C0 : 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E | cko) Chrome/137.
  000000D0 : 30 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 | 0.0.0 Safari/537
  000000E0 : 2E 33 36 0D 0A 73 65 63 2D 63 68 2D 75 61 3A 20 | .36..sec-ch-ua:
  000000F0 : 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 3B | "Google Chrome";
  00000100 : 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D 69 | v="137", "Chromi
  00000110 : 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E 6F | um";v="137", "No
  00000120 : 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 34 | t/A)Brand";v="24
  00000130 : 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F 62 | "..sec-ch-ua-mob
  00000140 : 69 6C 65 3A 20 3F 30 0D 0A 41 63 63 65 70 74 3A | ile: ?0..Accept:
  00000150 : 20 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 67 |  image/avif,imag
  00000160 : 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 6E | e/webp,image/apn
  00000170 : 67 2C 69 6D 61 67 65 2F 73 76 67 2B 78 6D 6C 2C | g,image/svg+xml,
  00000180 : 69 6D 61 67 65 2F 2A 2C 2A 2F 2A 3B 71 3D 30 2E | image/*,*/*;q=0.
  00000190 : 38 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 69 74 | 8..Sec-Fetch-Sit
  000001A0 : 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E 0D 0A | e: same-origin..
  000001B0 : 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 3A 20 | Sec-Fetch-Mode:
  000001C0 : 6E 6F 2D 63 6F 72 73 0D 0A 53 65 63 2D 46 65 74 | no-cors..Sec-Fet
  000001D0 : 63 68 2D 44 65 73 74 3A 20 69 6D 61 67 65 0D 0A | ch-Dest: image..
  000001E0 : 52 65 66 65 72 65 72 3A 20 68 74 74 70 73 3A 2F | Referer: https:/
  000001F0 : 2F 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 2F | /localhost:9000/
  00000200 : 0D 0A 41 63 63 65 70 74 2D 45 6E 63 6F 64 69 6E | ..Accept-Encodin
  00000210 : 67 3A 20 67 7A 69 70 2C 20 64 65 66 6C 61 74 65 | g: gzip, deflate
  00000220 : 2C 20 62 72 2C 20 7A 73 74 64 0D 0A 41 63 63 65 | , br, zstd..Acce
  00000230 : 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 6B 6F 2D | pt-Language: ko-
  00000240 : 4B 52 2C 6B 6F 3B 71 3D 30 2E 39 2C 65 6E 2D 55 | KR,ko;q=0.9,en-U
  00000250 : 53 3B 71 3D 30 2E 38 2C 65 6E 3B 71 3D 30 2E 37 | S;q=0.8,en;q=0.7
  00000260 : 0D 0A 0D 0A -- -- -- -- -- -- -- -- -- -- -- -- | ....
GET /favicon.ico HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://localhost:9000/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 36 32 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 62....<html><b
  00000060 : 6F 64 79 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E | ody>404 Not Foun
  00000070 : 64 3C 70 72 65 3E 2F 66 61 76 69 63 6F 6E 2E 69 | d<pre>/favicon.i
  00000080 : 63 6F 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | co</pre></body><
  00000090 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
[ns] read 984
  00000000 : 47 45 54 20 2F 61 70 69 2F 6A 73 6F 6E 20 48 54 | GET /api/json HT
  00000010 : 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 6C 6F | TP/1.1..Host: lo
  00000020 : 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D 0A 43 6F | calhost:9000..Co
  00000030 : 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 70 2D 61 | nnection: keep-a
  00000040 : 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D 75 61 3A | live..sec-ch-ua:
  00000050 : 20 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 |  "Google Chrome"
  00000060 : 3B 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D | ;v="137", "Chrom
  00000070 : 69 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E | ium";v="137", "N
  00000080 : 6F 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 | ot/A)Brand";v="2
  00000090 : 34 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F | 4"..sec-ch-ua-mo
  000000A0 : 62 69 6C 65 3A 20 3F 30 0D 0A 73 65 63 2D 63 68 | bile: ?0..sec-ch
  000000B0 : 2D 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 | -ua-platform: "W
  000000C0 : 69 6E 64 6F 77 73 22 0D 0A 55 70 67 72 61 64 65 | indows"..Upgrade
  000000D0 : 2D 49 6E 73 65 63 75 72 65 2D 52 65 71 75 65 73 | -Insecure-Reques
  000000E0 : 74 73 3A 20 31 0D 0A 55 73 65 72 2D 41 67 65 6E | ts: 1..User-Agen
  000000F0 : 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 | t: Mozilla/5.0 (
  00000100 : 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B | Windows NT 10.0;
  00000110 : 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 |  Win64; x64) App
  00000120 : 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 | leWebKit/537.36
  00000130 : 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 | (KHTML, like Gec
  00000140 : 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E 30 | ko) Chrome/137.0
  00000150 : 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 2E | .0.0 Safari/537.
  00000160 : 33 36 0D 0A 41 63 63 65 70 74 3A 20 74 65 78 74 | 36..Accept: text
  00000170 : 2F 68 74 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F | /html,applicatio
  00000180 : 6E 2F 78 68 74 6D 6C 2B 78 6D 6C 2C 61 70 70 6C | n/xhtml+xml,appl
  00000190 : 69 63 61 74 69 6F 6E 2F 78 6D 6C 3B 71 3D 30 2E | ication/xml;q=0.
  000001A0 : 39 2C 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 | 9,image/avif,ima
  000001B0 : 67 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 | ge/webp,image/ap
  000001C0 : 6E 67 2C 2A 2F 2A 3B 71 3D 30 2E 38 2C 61 70 70 | ng,*/*;q=0.8,app
  000001D0 : 6C 69 63 61 74 69 6F 6E 2F 73 69 67 6E 65 64 2D | lication/signed-
  000001E0 : 65 78 63 68 61 6E 67 65 3B 76 3D 62 33 3B 71 3D | exchange;v=b3;q=
  000001F0 : 30 2E 37 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 | 0.7..Sec-Fetch-S
  00000200 : 69 74 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E | ite: same-origin
  00000210 : 0D 0A 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 | ..Sec-Fetch-Mode
  00000220 : 3A 20 6E 61 76 69 67 61 74 65 0D 0A 53 65 63 2D | : navigate..Sec-
  00000230 : 46 65 74 63 68 2D 55 73 65 72 3A 20 3F 31 0D 0A | Fetch-User: ?1..
  00000240 : 53 65 63 2D 46 65 74 63 68 2D 44 65 73 74 3A 20 | Sec-Fetch-Dest:
  00000250 : 64 6F 63 75 6D 65 6E 74 0D 0A 52 65 66 65 72 65 | document..Refere
  00000260 : 72 3A 20 68 74 74 70 73 3A 2F 2F 6C 6F 63 61 6C | r: https://local
  00000270 : 68 6F 73 74 3A 39 30 30 30 2F 0D 0A 41 63 63 65 | host:9000/..Acce
  00000280 : 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 | pt-Encoding: gzi
  00000290 : 70 2C 20 64 65 66 6C 61 74 65 2C 20 62 72 2C 20 | p, deflate, br,
  000002A0 : 7A 73 74 64 0D 0A 41 63 63 65 70 74 2D 4C 61 6E | zstd..Accept-Lan
  000002B0 : 67 75 61 67 65 3A 20 6B 6F 2D 4B 52 2C 6B 6F 3B | guage: ko-KR,ko;
  000002C0 : 71 3D 30 2E 39 2C 65 6E 2D 55 53 3B 71 3D 30 2E | q=0.9,en-US;q=0.
  000002D0 : 38 2C 65 6E 3B 71 3D 30 2E 37 0D 0A 0D 0A -- -- | 8,en;q=0.7....
GET /api/json HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://localhost:9000/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 | .Content-Type: a
  00000020 : 70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E 0D | pplication/json.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 4B 65 65 | .Connection: Kee
  00000040 : 70 2D 41 6C 69 76 65 0D 0A 43 6F 6E 74 65 6E 74 | p-Alive..Content
  00000050 : 2D 4C 65 6E 67 74 68 3A 20 31 35 0D 0A 0D 0A 7B | -Length: 15....{
  00000060 : 22 72 65 73 75 6C 74 22 3A 22 6F 6B 22 7D -- -- | "result":"ok"}
[ns] read 984
  00000000 : 47 45 54 20 2F 66 61 76 69 63 6F 6E 2E 69 63 6F | GET /favicon.ico
  00000010 : 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A |  HTTP/1.1..Host:
  00000020 : 20 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D |  localhost:9000.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 | .Connection: kee
  00000040 : 70 2D 61 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D | p-alive..sec-ch-
  00000050 : 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 69 | ua-platform: "Wi
  00000060 : 6E 64 6F 77 73 22 0D 0A 55 73 65 72 2D 41 67 65 | ndows"..User-Age
  00000070 : 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 | nt: Mozilla/5.0
  00000080 : 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 | (Windows NT 10.0
  00000090 : 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 | ; Win64; x64) Ap
  000000A0 : 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 | pleWebKit/537.36
  000000B0 : 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 |  (KHTML, like Ge
  000000C0 : 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E | cko) Chrome/137.
  000000D0 : 30 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 | 0.0.0 Safari/537
  000000E0 : 2E 33 36 0D 0A 73 65 63 2D 63 68 2D 75 61 3A 20 | .36..sec-ch-ua:
  000000F0 : 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 3B | "Google Chrome";
  00000100 : 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D 69 | v="137", "Chromi
  00000110 : 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E 6F | um";v="137", "No
  00000120 : 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 34 | t/A)Brand";v="24
  00000130 : 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F 62 | "..sec-ch-ua-mob
  00000140 : 69 6C 65 3A 20 3F 30 0D 0A 41 63 63 65 70 74 3A | ile: ?0..Accept:
  00000150 : 20 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 67 |  image/avif,imag
  00000160 : 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 6E | e/webp,image/apn
  00000170 : 67 2C 69 6D 61 67 65 2F 73 76 67 2B 78 6D 6C 2C | g,image/svg+xml,
  00000180 : 69 6D 61 67 65 2F 2A 2C 2A 2F 2A 3B 71 3D 30 2E | image/*,*/*;q=0.
  00000190 : 38 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 69 74 | 8..Sec-Fetch-Sit
  000001A0 : 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E 0D 0A | e: same-origin..
  000001B0 : 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 3A 20 | Sec-Fetch-Mode:
  000001C0 : 6E 6F 2D 63 6F 72 73 0D 0A 53 65 63 2D 46 65 74 | no-cors..Sec-Fet
  000001D0 : 63 68 2D 44 65 73 74 3A 20 69 6D 61 67 65 0D 0A | ch-Dest: image..
  000001E0 : 52 65 66 65 72 65 72 3A 20 68 74 74 70 73 3A 2F | Referer: https:/
  000001F0 : 2F 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 2F | /localhost:9000/
  00000200 : 61 70 69 2F 6A 73 6F 6E 0D 0A 41 63 63 65 70 74 | api/json..Accept
  00000210 : 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 70 2C | -Encoding: gzip,
  00000220 : 20 64 65 66 6C 61 74 65 2C 20 62 72 2C 20 7A 73 |  deflate, br, zs
  00000230 : 74 64 0D 0A 41 63 63 65 70 74 2D 4C 61 6E 67 75 | td..Accept-Langu
  00000240 : 61 67 65 3A 20 6B 6F 2D 4B 52 2C 6B 6F 3B 71 3D | age: ko-KR,ko;q=
  00000250 : 30 2E 39 2C 65 6E 2D 55 53 3B 71 3D 30 2E 38 2C | 0.9,en-US;q=0.8,
  00000260 : 65 6E 3B 71 3D 30 2E 37 0D 0A 0D 0A -- -- -- -- | en;q=0.7....
GET /favicon.ico HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://localhost:9000/api/json
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 36 32 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 62....<html><b
  00000060 : 6F 64 79 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E | ody>404 Not Foun
  00000070 : 64 3C 70 72 65 3E 2F 66 61 76 69 63 6F 6E 2E 69 | d<pre>/favicon.i
  00000080 : 63 6F 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | co</pre></body><
  00000090 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
[ns] read 984
  00000000 : 47 45 54 20 2F 66 61 76 69 63 6F 6E 2E 69 63 6F | GET /favicon.ico
  00000010 : 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A |  HTTP/1.1..Host:
  00000020 : 20 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D |  localhost:9000.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 | .Connection: kee
  00000040 : 70 2D 61 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D | p-alive..sec-ch-
  00000050 : 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 69 | ua-platform: "Wi
  00000060 : 6E 64 6F 77 73 22 0D 0A 55 73 65 72 2D 41 67 65 | ndows"..User-Age
  00000070 : 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 | nt: Mozilla/5.0
  00000080 : 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 | (Windows NT 10.0
  00000090 : 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 | ; Win64; x64) Ap
  000000A0 : 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 | pleWebKit/537.36
  000000B0 : 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 |  (KHTML, like Ge
  000000C0 : 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E | cko) Chrome/137.
  000000D0 : 30 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 | 0.0.0 Safari/537
  000000E0 : 2E 33 36 0D 0A 73 65 63 2D 63 68 2D 75 61 3A 20 | .36..sec-ch-ua:
  000000F0 : 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 3B | "Google Chrome";
  00000100 : 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D 69 | v="137", "Chromi
  00000110 : 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E 6F | um";v="137", "No
  00000120 : 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 34 | t/A)Brand";v="24
  00000130 : 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F 62 | "..sec-ch-ua-mob
  00000140 : 69 6C 65 3A 20 3F 30 0D 0A 41 63 63 65 70 74 3A | ile: ?0..Accept:
  00000150 : 20 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 67 |  image/avif,imag
  00000160 : 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 6E | e/webp,image/apn
  00000170 : 67 2C 69 6D 61 67 65 2F 73 76 67 2B 78 6D 6C 2C | g,image/svg+xml,
  00000180 : 69 6D 61 67 65 2F 2A 2C 2A 2F 2A 3B 71 3D 30 2E | image/*,*/*;q=0.
  00000190 : 38 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 69 74 | 8..Sec-Fetch-Sit
  000001A0 : 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E 0D 0A | e: same-origin..
  000001B0 : 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 3A 20 | Sec-Fetch-Mode:
  000001C0 : 6E 6F 2D 63 6F 72 73 0D 0A 53 65 63 2D 46 65 74 | no-cors..Sec-Fet
  000001D0 : 63 68 2D 44 65 73 74 3A 20 69 6D 61 67 65 0D 0A | ch-Dest: image..
  000001E0 : 52 65 66 65 72 65 72 3A 20 68 74 74 70 73 3A 2F | Referer: https:/
  000001F0 : 2F 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 2F | /localhost:9000/
  00000200 : 0D 0A 41 63 63 65 70 74 2D 45 6E 63 6F 64 69 6E | ..Accept-Encodin
  00000210 : 67 3A 20 67 7A 69 70 2C 20 64 65 66 6C 61 74 65 | g: gzip, deflate
  00000220 : 2C 20 62 72 2C 20 7A 73 74 64 0D 0A 41 63 63 65 | , br, zstd..Acce
  00000230 : 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 6B 6F 2D | pt-Language: ko-
  00000240 : 4B 52 2C 6B 6F 3B 71 3D 30 2E 39 2C 65 6E 2D 55 | KR,ko;q=0.9,en-U
  00000250 : 53 3B 71 3D 30 2E 38 2C 65 6E 3B 71 3D 30 2E 37 | S;q=0.8,en;q=0.7
  00000260 : 0D 0A 0D 0A -- -- -- -- -- -- -- -- -- -- -- -- | ....
GET /favicon.ico HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://localhost:9000/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 36 32 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 62....<html><b
  00000060 : 6F 64 79 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E | ody>404 Not Foun
  00000070 : 64 3C 70 72 65 3E 2F 66 61 76 69 63 6F 6E 2E 69 | d<pre>/favicon.i
  00000080 : 63 6F 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | co</pre></body><
  00000090 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
[ns] read 984
  00000000 : 47 45 54 20 2F 61 70 69 2F 74 65 73 74 20 48 54 | GET /api/test HT
  00000010 : 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 6C 6F | TP/1.1..Host: lo
  00000020 : 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D 0A 43 6F | calhost:9000..Co
  00000030 : 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 70 2D 61 | nnection: keep-a
  00000040 : 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D 75 61 3A | live..sec-ch-ua:
  00000050 : 20 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 |  "Google Chrome"
  00000060 : 3B 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D | ;v="137", "Chrom
  00000070 : 69 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E | ium";v="137", "N
  00000080 : 6F 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 | ot/A)Brand";v="2
  00000090 : 34 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F | 4"..sec-ch-ua-mo
  000000A0 : 62 69 6C 65 3A 20 3F 30 0D 0A 73 65 63 2D 63 68 | bile: ?0..sec-ch
  000000B0 : 2D 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 | -ua-platform: "W
  000000C0 : 69 6E 64 6F 77 73 22 0D 0A 55 70 67 72 61 64 65 | indows"..Upgrade
  000000D0 : 2D 49 6E 73 65 63 75 72 65 2D 52 65 71 75 65 73 | -Insecure-Reques
  000000E0 : 74 73 3A 20 31 0D 0A 55 73 65 72 2D 41 67 65 6E | ts: 1..User-Agen
  000000F0 : 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 | t: Mozilla/5.0 (
  00000100 : 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B | Windows NT 10.0;
  00000110 : 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 |  Win64; x64) App
  00000120 : 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 | leWebKit/537.36
  00000130 : 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 | (KHTML, like Gec
  00000140 : 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E 30 | ko) Chrome/137.0
  00000150 : 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 2E | .0.0 Safari/537.
  00000160 : 33 36 0D 0A 41 63 63 65 70 74 3A 20 74 65 78 74 | 36..Accept: text
  00000170 : 2F 68 74 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F | /html,applicatio
  00000180 : 6E 2F 78 68 74 6D 6C 2B 78 6D 6C 2C 61 70 70 6C | n/xhtml+xml,appl
  00000190 : 69 63 61 74 69 6F 6E 2F 78 6D 6C 3B 71 3D 30 2E | ication/xml;q=0.
  000001A0 : 39 2C 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 | 9,image/avif,ima
  000001B0 : 67 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 | ge/webp,image/ap
  000001C0 : 6E 67 2C 2A 2F 2A 3B 71 3D 30 2E 38 2C 61 70 70 | ng,*/*;q=0.8,app
  000001D0 : 6C 69 63 61 74 69 6F 6E 2F 73 69 67 6E 65 64 2D | lication/signed-
  000001E0 : 65 78 63 68 61 6E 67 65 3B 76 3D 62 33 3B 71 3D | exchange;v=b3;q=
  000001F0 : 30 2E 37 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 | 0.7..Sec-Fetch-S
  00000200 : 69 74 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E | ite: same-origin
  00000210 : 0D 0A 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 | ..Sec-Fetch-Mode
  00000220 : 3A 20 6E 61 76 69 67 61 74 65 0D 0A 53 65 63 2D | : navigate..Sec-
  00000230 : 46 65 74 63 68 2D 55 73 65 72 3A 20 3F 31 0D 0A | Fetch-User: ?1..
  00000240 : 53 65 63 2D 46 65 74 63 68 2D 44 65 73 74 3A 20 | Sec-Fetch-Dest:
  00000250 : 64 6F 63 75 6D 65 6E 74 0D 0A 52 65 66 65 72 65 | document..Refere
  00000260 : 72 3A 20 68 74 74 70 73 3A 2F 2F 6C 6F 63 61 6C | r: https://local
  00000270 : 68 6F 73 74 3A 39 30 30 30 2F 0D 0A 41 63 63 65 | host:9000/..Acce
  00000280 : 70 74 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 | pt-Encoding: gzi
  00000290 : 70 2C 20 64 65 66 6C 61 74 65 2C 20 62 72 2C 20 | p, deflate, br,
  000002A0 : 7A 73 74 64 0D 0A 41 63 63 65 70 74 2D 4C 61 6E | zstd..Accept-Lan
  000002B0 : 67 75 61 67 65 3A 20 6B 6F 2D 4B 52 2C 6B 6F 3B | guage: ko-KR,ko;
  000002C0 : 71 3D 30 2E 39 2C 65 6E 2D 55 53 3B 71 3D 30 2E | q=0.9,en-US;q=0.
  000002D0 : 38 2C 65 6E 3B 71 3D 30 2E 37 0D 0A 0D 0A -- -- | 8,en;q=0.7....
GET /api/test HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://localhost:9000/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 34 36 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 46....<html><b
  00000060 : 6F 64 79 3E 3C 70 72 65 3E 2F 61 70 69 2F 74 65 | ody><pre>/api/te
  00000070 : 73 74 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | st</pre></body><
  00000080 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
[ns] read 984
  00000000 : 47 45 54 20 2F 66 61 76 69 63 6F 6E 2E 69 63 6F | GET /favicon.ico
  00000010 : 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A |  HTTP/1.1..Host:
  00000020 : 20 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D |  localhost:9000.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 | .Connection: kee
  00000040 : 70 2D 61 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D | p-alive..sec-ch-
  00000050 : 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 69 | ua-platform: "Wi
  00000060 : 6E 64 6F 77 73 22 0D 0A 55 73 65 72 2D 41 67 65 | ndows"..User-Age
  00000070 : 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 | nt: Mozilla/5.0
  00000080 : 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 | (Windows NT 10.0
  00000090 : 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 | ; Win64; x64) Ap
  000000A0 : 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 | pleWebKit/537.36
  000000B0 : 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 |  (KHTML, like Ge
  000000C0 : 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E | cko) Chrome/137.
  000000D0 : 30 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 | 0.0.0 Safari/537
  000000E0 : 2E 33 36 0D 0A 73 65 63 2D 63 68 2D 75 61 3A 20 | .36..sec-ch-ua:
  000000F0 : 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 3B | "Google Chrome";
  00000100 : 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D 69 | v="137", "Chromi
  00000110 : 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E 6F | um";v="137", "No
  00000120 : 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 34 | t/A)Brand";v="24
  00000130 : 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F 62 | "..sec-ch-ua-mob
  00000140 : 69 6C 65 3A 20 3F 30 0D 0A 41 63 63 65 70 74 3A | ile: ?0..Accept:
  00000150 : 20 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 67 |  image/avif,imag
  00000160 : 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 6E | e/webp,image/apn
  00000170 : 67 2C 69 6D 61 67 65 2F 73 76 67 2B 78 6D 6C 2C | g,image/svg+xml,
  00000180 : 69 6D 61 67 65 2F 2A 2C 2A 2F 2A 3B 71 3D 30 2E | image/*,*/*;q=0.
  00000190 : 38 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 69 74 | 8..Sec-Fetch-Sit
  000001A0 : 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E 0D 0A | e: same-origin..
  000001B0 : 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 3A 20 | Sec-Fetch-Mode:
  000001C0 : 6E 6F 2D 63 6F 72 73 0D 0A 53 65 63 2D 46 65 74 | no-cors..Sec-Fet
  000001D0 : 63 68 2D 44 65 73 74 3A 20 69 6D 61 67 65 0D 0A | ch-Dest: image..
  000001E0 : 52 65 66 65 72 65 72 3A 20 68 74 74 70 73 3A 2F | Referer: https:/
  000001F0 : 2F 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 2F | /localhost:9000/
  00000200 : 61 70 69 2F 74 65 73 74 0D 0A 41 63 63 65 70 74 | api/test..Accept
  00000210 : 2D 45 6E 63 6F 64 69 6E 67 3A 20 67 7A 69 70 2C | -Encoding: gzip,
  00000220 : 20 64 65 66 6C 61 74 65 2C 20 62 72 2C 20 7A 73 |  deflate, br, zs
  00000230 : 74 64 0D 0A 41 63 63 65 70 74 2D 4C 61 6E 67 75 | td..Accept-Langu
  00000240 : 61 67 65 3A 20 6B 6F 2D 4B 52 2C 6B 6F 3B 71 3D | age: ko-KR,ko;q=
  00000250 : 30 2E 39 2C 65 6E 2D 55 53 3B 71 3D 30 2E 38 2C | 0.9,en-US;q=0.8,
  00000260 : 65 6E 3B 71 3D 30 2E 37 0D 0A 0D 0A -- -- -- -- | en;q=0.7....
GET /favicon.ico HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://localhost:9000/api/test
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 36 32 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 62....<html><b
  00000060 : 6F 64 79 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E | ody>404 Not Foun
  00000070 : 64 3C 70 72 65 3E 2F 66 61 76 69 63 6F 6E 2E 69 | d<pre>/favicon.i
  00000080 : 63 6F 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | co</pre></body><
  00000090 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
[ns] read 984
  00000000 : 47 45 54 20 2F 66 61 76 69 63 6F 6E 2E 69 63 6F | GET /favicon.ico
  00000010 : 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A |  HTTP/1.1..Host:
  00000020 : 20 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 0D |  localhost:9000.
  00000030 : 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 | .Connection: kee
  00000040 : 70 2D 61 6C 69 76 65 0D 0A 73 65 63 2D 63 68 2D | p-alive..sec-ch-
  00000050 : 75 61 2D 70 6C 61 74 66 6F 72 6D 3A 20 22 57 69 | ua-platform: "Wi
  00000060 : 6E 64 6F 77 73 22 0D 0A 55 73 65 72 2D 41 67 65 | ndows"..User-Age
  00000070 : 6E 74 3A 20 4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 | nt: Mozilla/5.0
  00000080 : 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 | (Windows NT 10.0
  00000090 : 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 | ; Win64; x64) Ap
  000000A0 : 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 | pleWebKit/537.36
  000000B0 : 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 |  (KHTML, like Ge
  000000C0 : 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 31 33 37 2E | cko) Chrome/137.
  000000D0 : 30 2E 30 2E 30 20 53 61 66 61 72 69 2F 35 33 37 | 0.0.0 Safari/537
  000000E0 : 2E 33 36 0D 0A 73 65 63 2D 63 68 2D 75 61 3A 20 | .36..sec-ch-ua:
  000000F0 : 22 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 22 3B | "Google Chrome";
  00000100 : 76 3D 22 31 33 37 22 2C 20 22 43 68 72 6F 6D 69 | v="137", "Chromi
  00000110 : 75 6D 22 3B 76 3D 22 31 33 37 22 2C 20 22 4E 6F | um";v="137", "No
  00000120 : 74 2F 41 29 42 72 61 6E 64 22 3B 76 3D 22 32 34 | t/A)Brand";v="24
  00000130 : 22 0D 0A 73 65 63 2D 63 68 2D 75 61 2D 6D 6F 62 | "..sec-ch-ua-mob
  00000140 : 69 6C 65 3A 20 3F 30 0D 0A 41 63 63 65 70 74 3A | ile: ?0..Accept:
  00000150 : 20 69 6D 61 67 65 2F 61 76 69 66 2C 69 6D 61 67 |  image/avif,imag
  00000160 : 65 2F 77 65 62 70 2C 69 6D 61 67 65 2F 61 70 6E | e/webp,image/apn
  00000170 : 67 2C 69 6D 61 67 65 2F 73 76 67 2B 78 6D 6C 2C | g,image/svg+xml,
  00000180 : 69 6D 61 67 65 2F 2A 2C 2A 2F 2A 3B 71 3D 30 2E | image/*,*/*;q=0.
  00000190 : 38 0D 0A 53 65 63 2D 46 65 74 63 68 2D 53 69 74 | 8..Sec-Fetch-Sit
  000001A0 : 65 3A 20 73 61 6D 65 2D 6F 72 69 67 69 6E 0D 0A | e: same-origin..
  000001B0 : 53 65 63 2D 46 65 74 63 68 2D 4D 6F 64 65 3A 20 | Sec-Fetch-Mode:
  000001C0 : 6E 6F 2D 63 6F 72 73 0D 0A 53 65 63 2D 46 65 74 | no-cors..Sec-Fet
  000001D0 : 63 68 2D 44 65 73 74 3A 20 69 6D 61 67 65 0D 0A | ch-Dest: image..
  000001E0 : 52 65 66 65 72 65 72 3A 20 68 74 74 70 73 3A 2F | Referer: https:/
  000001F0 : 2F 6C 6F 63 61 6C 68 6F 73 74 3A 39 30 30 30 2F | /localhost:9000/
  00000200 : 0D 0A 41 63 63 65 70 74 2D 45 6E 63 6F 64 69 6E | ..Accept-Encodin
  00000210 : 67 3A 20 67 7A 69 70 2C 20 64 65 66 6C 61 74 65 | g: gzip, deflate
  00000220 : 2C 20 62 72 2C 20 7A 73 74 64 0D 0A 41 63 63 65 | , br, zstd..Acce
  00000230 : 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 6B 6F 2D | pt-Language: ko-
  00000240 : 4B 52 2C 6B 6F 3B 71 3D 30 2E 39 2C 65 6E 2D 55 | KR,ko;q=0.9,en-U
  00000250 : 53 3B 71 3D 30 2E 38 2C 65 6E 3B 71 3D 30 2E 37 | S;q=0.8,en;q=0.7
  00000260 : 0D 0A 0D 0A -- -- -- -- -- -- -- -- -- -- -- -- | ....
GET /favicon.ico HTTP/1.1
Host: localhost:9000
Connection: keep-alive
sec-ch-ua-platform: "Windows"
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
sec-ch-ua-mobile: ?0
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: no-cors
Sec-Fetch-Dest: image
Referer: https://localhost:9000/
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7


  00000000 : 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D | HTTP/1.1 200 OK.
  00000010 : 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 74 | .Content-Type: t
  00000020 : 65 78 74 2F 68 74 6D 6C 0D 0A 43 6F 6E 6E 65 63 | ext/html..Connec
  00000030 : 74 69 6F 6E 3A 20 4B 65 65 70 2D 41 6C 69 76 65 | tion: Keep-Alive
  00000040 : 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 | ..Content-Length
  00000050 : 3A 20 36 32 0D 0A 0D 0A 3C 68 74 6D 6C 3E 3C 62 | : 62....<html><b
  00000060 : 6F 64 79 3E 34 30 34 20 4E 6F 74 20 46 6F 75 6E | ody>404 Not Foun
  00000070 : 64 3C 70 72 65 3E 2F 66 61 76 69 63 6F 6E 2E 69 | d<pre>/favicon.i
  00000080 : 63 6F 3C 2F 70 72 65 3E 3C 2F 62 6F 64 79 3E 3C | co</pre></body><
  00000090 : 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- -- | /html>
TLS 00000304 00004008 SSL_write:callback:warning:close notify
````

[TOC](README.md)
