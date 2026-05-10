#### server

$ ./test-httpserver2.exe -r -T -d
````
 _   _           _             _
| | | |   ___   | |_   _ __   | |   __ _    ___    ___
| |_| |  / _ \  | __| | '_ \  | |  / _` |  / __|  / _ \
|  _  | | (_) | | |_  | |_) | | | | (_| | | (__  |  __/
|_| |_|  \___/   \__| | .__/  |_|  \__,_|  \___|  \___|
                      |_|

[test case] HTTP/2 powered by http_server
# set ciphersuite(s)
 > 0xc030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 > 0xc02f TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 > 0xc02c TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 > 0xc02b TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 > 0x1303 TLS_CHACHA20_POLY1305_SHA256
 > 0x1302 TLS_AES_256_GCM_SHA384
 > 0x1301 TLS_AES_128_GCM_SHA256
openssl version 40000000
socket 436 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001bc created
socket 476 created family 23(AF_INET6) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001e0 created
- event_loop_new tid 00000a88
- event_loop_new tid 0000a958
- event_loop_new tid 00004048
- event_loop_new tid 000062e0
- event_loop_new tid 00006c78
- event_loop_new tid 00006928
- event_loop_new tid 00000934
- event_loop_new tid 0000b3e4
iocp handle 000001e0 bind 668
# record (client) [size 0x5ac(1452) pos 0x0]
> record content type 0x16(22) (handshake)
 > record version 0x0301 (TLS v1.0)
 > len 0x05a7(1447)
# read handshake type 0x01(1) (client_hello)
 > handshake type 0x01(1) (client_hello)
  > length 0x0005a3(1443)
  > version 0x0303 (TLS v1.2)
  > random
    bbf33c1aa2db1ae6fc8433dc003169353c127e96faa0df36bdf2e9e5be89c3b0
  > session id 0x20(32)
    9561414b9c3cce72e8bca29ab8534d4147a7346f9ba399c18a1a460e9a5a7e63
  > cookie
  > cipher suite len 0x0002(1 ent.)
    [0] 0x1304 TLS_AES_128_CCM_SHA256
  > compression method len 1
    [0] 0x00 null
  > extension len 0x0558(1368)
  > extension - 000b ec_point_formats
   > extension len 0x0002(2)
   > formats (1 ent.)
     [0] 0x00(0) uncompressed
  > extension - 000a supported_groups
   > extension len 0x0012(18)
   > curves (8 ent.)
     [0] 0x11ec(4588) X25519MLKEM768
     [1] 0x001d(29) x25519
     [2] 0x0017(23) secp256r1
     [3] 0x001e(30) x448
     [4] 0x0018(24) secp384r1
     [5] 0x0019(25) secp521r1
     [6] 0x0100(256) ffdhe2048
     [7] 0x0101(257) ffdhe3072
  > extension - 0023 session_ticket
   > extension len 0x0000(0)
  > extension - 0016 encrypt_then_mac
   > extension len 0x0000(0)
  > extension - 0017 extended_master_secret
   > extension len 0x0000(0)
  > extension - 000d signature_algorithms
   > extension len 0x002a(42)
   > algorithms (20 ent.)
     [00] 0x0905 mldsa65
     [01] 0x0906 mldsa87
     [02] 0x0904 mldsa44
     [03] 0x0403 ecdsa_secp256r1_sha256
     [04] 0x0503 ecdsa_secp384r1_sha384
     [05] 0x0603 ecdsa_secp521r1_sha512
     [06] 0x0807 ed25519
     [07] 0x0808 ed448
     [08] 0x081a ecdsa_brainpoolP256r1tls13_sha256
     [09] 0x081b ecdsa_brainpoolP384r1tls13_sha384
     [10] 0x081c ecdsa_brainpoolP512r1tls13_sha512
     [11] 0x0809 rsa_pss_pss_sha256
     [12] 0x080a rsa_pss_pss_sha384
     [13] 0x080b rsa_pss_pss_sha512
     [14] 0x0804 rsa_pss_rsae_sha256
     [15] 0x0805 rsa_pss_rsae_sha384
     [16] 0x0806 rsa_pss_rsae_sha512
     [17] 0x0401 rsa_pkcs1_sha256
     [18] 0x0501 rsa_pkcs1_sha384
     [19] 0x0601 rsa_pkcs1_sha512
  > extension - 002b supported_versions
   > extension len 0x0003(3)
    > supported versions (1 ent.)
      [0] 0x0304 TLS v1.3
  > extension - 002d psk_key_exchange_modes
   > extension len 0x0002(2)
   > modes
     [0] 1 psk_dhe_ke
  > extension - 0033 key_share
   > extension len 0x04ea(1258)
   > len 1256(0x04e8)
+ add pub key CH.pub (group X25519MLKEM768)
    > key share entry
     > group 0x11ec (X25519MLKEM768)
     > public key len 04c0(1216)
       13eb8867e9c8cf43b7933232c021ae81bbb0e1c405b6d41cff35a5e681724e19ac91217e67f409ca205f5c7284735a96eee25fab2cc16134151ab1a369e7cb6343b626a4502b4935d78372b1b50a16c2c650f803d848c915322b4e0ccba93b14723bb9fb42a2aff9199e545770408d1fd7cd8751bde50b2b8685846ef196e172053d731379f85b033835db22993476722dba83c2c04663e50c6b19405b168cbda3c6fc4b526b291233c2642d24a9de4c8f338b8091833e781b83930860ece213547c88ea06ccaaf2641889b500c30b97bb88b8e718a1c1a42688683c7b985f6c13e18c0cfbc464c60b4840738fd6c50076806665811c2b0a0b6ba42ddc2519553cc8f179a2db1ca9fe9a47f180bdf6d04fb2e7951381337b69459dd1b53a134f2dd355b2ac7338f02abf5b3ac2db2acca1b6d1fc7f2f42ae104a15b6402f00727d4723430d639e997a4095e6c519d114ea5a2ada402553b44cf4b16f4111b96f5555cae52a31e4c9b1153f6e8213bcb25e5d35a9ff335b40d12d52222b861a11a9451ce1257146a195540358f075192c293e1f5b13b54a030c6a343acc3aedc45d643893d407b47f14c8e196bd5ee6b8da286c815883b8c7011d30bcab9c48a4414156580db4b62cdd8498a733cfc58943b87b08bcd99ac35b61cf151515c03e57fa1dd184b7973234d4fc6bbb7257103750a0497208798f4c03515aa4432624c30dd824dda24459c407f48825ff30b0cfe559f8ab3adfc1c138ab3cfcf7196736ad1987354da31b0cb36bbe429eb12b913104aa795cc8c94752d70207cca3bac89b18e6fcb6fdc9b4c35496feb69383191365a187b0210f0182b6cab3a03de7a64af3422548526eb77260fc4afa10620229464e8c6d5494a2d4060fa641b621a31ed3c70e69f3331da020d5e117c50a122bac35f3462d4b549049c518324b5adb388beb4914d55305c6417fc576592781c62446bcff9acd9c70189fab2ff430cc969b647bec2404b91aa51a0f75710fecb02dd226cf7f7534a0855c5c4b45f08bc850369c0d727bc7bb9b03928685c17bcf41794bb9958c902d48a70bca2970baaaab56157ca083c70e501f58321b686ca4f6469c5383129090ac68b2361734928caa43b4e84809d126ae1a2fa7139387a5ad60537a34c8cdf760726828c24b1ccb2053bee6398ddf8b53cfe4535b677b23fb9be9e96ff8d1144fa86cbb81c0c584c4a9c7659591c432e87b3c7c2055853640f254cfb129d301a19948ac5bb4a70849cd08c7977e046e38262602b58ef89356b8349e37e44a82980f87c8889325c1268097607a4e2345475f89385666160a28c956f410382027bff000b6529ded57247bb908ab656125e70d561bbb12e647d49170a89ab55d114e0c861cd700722bc5cda7b205203b7216858bdf0702962610881c6463b90b478a6aefe75a9d57a3b71176afb2205aacc966e06922a435d6f4ac2c233fe05a30b85b71cbd8aa87e069f3f8ad77521b97f50960523500ebc00de5b942827d98b3b652a039ee0c7b1aba5e96b1c2538b3c1aa459a447a1c696c776388fa1eca271454c2d21c5d3932d097c7b08c68c1b828071e82ac3804cc665c5ffa22417c10bf7622895eb0329c4d7e2d1e8adaa23589bb7b0c489ab117e29573900855400ba793895870d1d5214e3d5fe5d52d8773000f2066b5b136ca2a945e7c263d516308f5549566644
+ add pub key CH.pub (group x25519)
    > key share entry
     > group 0x001d (x25519)
     > public key len 0020(32)
       22031f16d8835b5103f7ed27d0be7285895f5cb5a3baf6d4b51ecdae0278c163
  > extension - 001b compress_certificate
   > extension len 0x0003(3)
   > algorithm len 2 (1 ent.)
     [0] 0x0001 zlib
hook client_hello (server)
alert level:fatal desc:handshake_failure
# write record content type 0x15(21) (alert)
# record (server)
> record content type 0x15(21) (alert)
 > record version 0x0303 (TLS v1.2)
 > len 0x0002(2)
rm .run

hush@HUSH2021 MINGW64 /c/Home/git/hotplace/build/testapplet/httpserver2
# - event_loop_break_concurrent : break 1/4
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/3
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/2
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/1
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/4
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/3
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/2
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/1
- event_loop_test_broken : broken detected
================================================================================
report
# pass 0
--------------------------------------------------------------------------------
brief
pass fail skip triv case
--------------------------------------------------------------------------------
 ____
|  _ \    __ _   ___   ___
| |_) |  / _` | / __| / __|
|  __/  | (_| | \__ \ \__ \
|_|      \__,_| |___/ |___/
- hotplace test_case prooved
help
-v             verbose
-d             debug/trace
-D arg         trace level 0|2
--trace        trace level [trace]
--debug        trace level [debug]
-l             log
-t             log time
-r             run server
-h arg         http  port (default 8080)
-s arg         https port (default 9000)
-e             allow Content-Encoding
-T             use trial
-k             keylog
-cs arg        ciphersuite
-cert arg      rsa|ecdsa|mldsa
````

[TOC](README.md)
