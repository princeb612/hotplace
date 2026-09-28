#### server

$ ./test-httpserver2.exe -r -d -T -cert mldsa &
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
socket 440 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 00000190 created
socket 464 created family 23(AF_INET6) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001dc created
- event_loop_new tid 000035fc
- event_loop_new tid 0000b290
- event_loop_new tid 000076c0
- event_loop_new tid 00004da8
- event_loop_new tid 00005aec
- event_loop_new tid 00006b84
- event_loop_new tid 00002a74
- event_loop_new tid 0000a034
iocp handle 000001dc bind 228
# record (client) [size 0x61d(1565) pos 0x0]
> record content type 0x16(22) (handshake)
 > record version 0x0301 (TLS v1.0)
 > len 0x0618(1560)
# read handshake type 0x01(1) (client_hello)
 > handshake type 0x01(1) (client_hello)
  > length 0x000614(1556)
  > version 0x0303 (TLS v1.2)
  > random
    873d5d472e1e3c969d12158946e4f513f51730bcefb8b80ec88e492afe41debb
  > session id 0x20(32)
    3bd59af67f73291a256171924a7872e2ae870b31859cdece483969a3848e4e60
  > cookie
  > cipher suite len 0x003c(30 ent.)
    [0] 0x1302 TLS_AES_256_GCM_SHA384
    [1] 0x1303 TLS_CHACHA20_POLY1305_SHA256
    [2] 0x1301 TLS_AES_128_GCM_SHA256
    [3] 0xc02c TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    [4] 0xc030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    [5] 0x009f TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    [6] 0xcca9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    [7] 0xcca8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    [8] 0xccaa TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    [9] 0xc02b TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    [10] 0xc02f TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    [11] 0x009e TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    [12] 0xc024 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    [13] 0xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    [14] 0x006b TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    [15] 0xc023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    [16] 0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    [17] 0x0067 TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    [18] 0xc00a TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    [19] 0xc014 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    [20] 0x0039 TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    [21] 0xc009 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    [22] 0xc013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    [23] 0x0033 TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    [24] 0x009d TLS_RSA_WITH_AES_256_GCM_SHA384
    [25] 0x009c TLS_RSA_WITH_AES_128_GCM_SHA256
    [26] 0x003d TLS_RSA_WITH_AES_256_CBC_SHA256
    [27] 0x003c TLS_RSA_WITH_AES_128_CBC_SHA256
    [28] 0x0035 TLS_RSA_WITH_AES_256_CBC_SHA
    [29] 0x002f TLS_RSA_WITH_AES_128_CBC_SHA
  > compression method len 1
    [0] 0x00 null
  > extension len 0x058f(1423)
  > extension - ff01 renegotiation_info
   > extension len 0x0001(1)
   > renegotiation_info len 0
  > extension - 0000 server_name
   > extension len 0x000e(14)
   > name type 0 (hostname)
   > hostname localhost
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
  > extension - 0010 application_layer_protocol_negotiation
   > extension len 0x000e(14)
   > alpn len 12
     00000000 : 02 68 32 08 68 74 74 70 2F 31 2E 31 -- -- -- -- | .h2.http/1.1
  > extension - 0016 encrypt_then_mac
   > extension len 0x0000(0)
  > extension - 0017 extended_master_secret
   > extension len 0x0000(0)
  > extension - 0031 post_handshake_auth
   > extension len 0x0000(0)
  > extension - 000d signature_algorithms
   > extension len 0x0036(54)
   > algorithms (26 ent.)
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
     [20] 0x0303 SHA224 ECDSA
     [21] 0x0301 SHA224 RSA
     [22] 0x0302 SHA224 DSA
     [23] 0x0402 dsa_sha256_RESERVED
     [24] 0x0502 dsa_sha384_RESERVED
     [25] 0x0602 dsa_sha512_RESERVED
  > extension - 002b supported_versions
   > extension len 0x0005(5)
    > supported versions (2 ent.)
      [0] 0x0304 TLS v1.3
      [1] 0x0303 TLS v1.2
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
       d804accae328a4b7bd4512ca2f81659a0735c5d652f2abafe5e83727e201f46c2906c4619404d095d2c6004b25db91ca27d979ebe558aa5810a8ba2ad563820a981e7de8737f0465557bc9fe952e9b5313fd9732a09c9fc78802490b4292c88d48f3cb4fbc932b95a9f8d46ec290380c571fce788a25e808b3e6823cc32329eb54a9d403aa0b6e58e8ba4321489a2a19f5d8beeff51ab255ae15ecc177d97271cc2a32100b0706561cc152c40a3576ac21d4b52fcef827c3b27bff28cdc48bb39c13630ab198ccf25080b0591f6b28d8607f636b5022d167b6623035854f1f6381acb65b621a0c728887f1a3908c147b8ddb2e3a03ae6b9a72dae699a4868b861b293360765a85425ca3238253689a682484a7a5722b7457f6474bd2bbedd6831984b5d7eb70b9fbb169e61aa6696058b21d649a28d9a4942ce5ab0b3306c2c993606520059a5b49e33ceabc2d6ab2494c17ccffb81c1c625fe1424d6b279f610ca45d3a9cb23166b80c761fba0742240da86295173b76164883ea874e38a25d15ab8a5800cc5df28ca9b89c56bb50d3121fefa68c83757547fcbe3d97b5721331abb0c92a2629f18c310ce4a036d06f9802a91fd02f3f5356d898b99da89778a7bc4d718f92b8a35ae5397f614a8a965df3a1694ab3cea68cbd3b5a08962751f3f55042bb166f2ca94934b6f2a570c9b96957f807a880ada5bab6ec6a4e92363ff6727c694c702fd85241aa4d1070041a592abbe67cd0ba2e9753006092b1415241b0d659a20269d831323bf281815a9d4e61236ebb1a4789c592791d58835afa4b262e6068081147c0bbb55ea68a7a520f0f7395ae73bbf856a23d888d56b83764d165adac81e9f4b6c75538bd5700c4516230863902ec589a391480c049056a6c048431e1297511f927b4194127d12d7a75910284c117acbbb9e4bd0d389a92389b3136c7877c5d278c14d055c536fca128ac173cabcc651031bd2ca57c94641e3177e7428feb19c5adb3119035cbd874389cf25a40a7a72b533cc3f05ea3d3b571301afdf3a6515737693c83460605635a2b51e43445e7ccf68a1e6c819e33c7a6273207e4a571704cc459a825430208f919966ae73371381b8e6370673b3662d0c6c33a3e0dd221fb8223653b80c6f0abd5876dc1ba27a2784475d690af0ab00a788063f76179f86842794dfa2188e5b451c52c2224617f0cdb303dc9b6c8f65afe4a1c87f88680ec66a06080a9db2bc55635d95a598d268c06f053933c269cd617c64495f6b1b6b1f6635a44b87b15a60bf3cd4a0134ef01a199c865954290e91ca174a029ec7387eaf851ab715b2685b871c046bd3a2816da933e847b87f20272aa3483a93aa1ca11fea62d01b706fc8932fdf6cbd97a366033700d239c696bc441d145c6d27a2ef580e62282fe6406ea108e894b975c62aa25c23efe980e08d526659b71c6998011d17aa713c194c07500019ff9d7a69f0c9660e34d2217433b114a130c0971f24da4b77d5c8662de888803c934dce60c176a5848030832aa39b0783550065d9df147cd2b8cb987206d508614d384be83853284ce33eb6683519d8d58b67c50c814f4c4cd657198b36be082a9195a2b05522253790372e321f9dd37a9da8017bdff3f7ce02507b81c9765a654a2e77be858f12bd29967636af7c4d1181f7c71ada38cb23d43736d2d7574c8f3234fe40890be0a0744
+ add pub key CH.pub (group x25519)
    > key share entry
     > group 0x001d (x25519)
     > public key len 0020(32)
       eb2cb7ed821aec9a2bd0cae4fe1e519f9eeee8a2ae51efbe3d29382d787d6379
  > extension - 001b compress_certificate
   > extension len 0x0003(3)
   > algorithm len 2 (1 ent.)
     [0] 0x0001 zlib
hook client_hello (server)
 ? # 0x1302 TLS_AES_256_GCM_SHA384
 ? # 0x1303 TLS_CHACHA20_POLY1305_SHA256
 ? # 0x1301 TLS_AES_128_GCM_SHA256
 ! # 0x1302 TLS_AES_256_GCM_SHA384
 - # 0x001d x25519
 - # 0x11ec X25519MLKEM768
+ add keypair SH.priv (group X25519MLKEM768)
# write record content type 0x16(22) (handshake)
# write 0x20349748100 handshake type 0x02(2) (server_hello)
   > encaps
   > group X25519MLKEM768 2296386c1d8d93d79331eeecdea3b2cf4b21a9e21cd2a849cf434a0adabfdb74b043ea47603c86b92709d7f7a8a54bf7e3dca74543dc6cac5095e8d6bc53c69edd4c31b1db25a4c239efb5838092112fdfa3dbd670bb7b262e51b4ed557447b466fef37dce100a1f901324d016c4368457d5b06b23d3049784c54034c97f296472462194e181595ff2c7de944bde86c8f18787384f22813d384c35fa7022d4c49716820d5b645b72baf41ea49567100fbfca13e59bc997b76a4eb7d5ae0e207eb4399c49141433c39dc093d84e13b19638b938ece2e86e0855d8b3583d2f53ab009ae1381d2b6151e6a58c4aa50a9eec97a398af7f02601e23b6cb4adf99171e09edb8a38c92e8ca1ca3f929ebb57ee118c8cace9ef544469b351728fd8b9a03f150d7e8880b64e6baa1dc10a29a134b4d94c9152bbbc34133c7d4690701f837a476e5bc8b92afcc1a8716a1be2efb96d88a8496e28b3ff26e7ff2228380453922eb486ce3d84cc32616da4ede4e3f2e2ccefa6725e3c189f6856f43379f1bc0610c5816d1d17c4f9a7d568f8b41272fee0fd66619d9c821f400936c26e98b4bf84e5f9f6cca20667edff583846007f4d965f2cec03f3d33cd378dafa661044f8259eab19d5d6832993555f1c04d435ca8a34d6a24a2cfbbec9a9455ddc506c8165cfa69339efd362bf375ab3f83f4b8f41bf50040dc440ec2dc0293292433148c763492adaa80ebd5c96672265101a5706ac8ddb4e90c71ceba52a50210a30cad942b060fbc9ec7939649a1ca9d8fca46b246652b0f2e527d9b1d09b1ff7fd9c7f0c4c48f906dd278a3a76877545c8e267ad9b06ee529ddfdf7d675227812b4e2b21a7844408cd6d7259b30a2732e2e227bf474eb595e9b2049810bd7ba216919d82180f19b8249f5b8880336a6aca8f3cf24fafb90c97c73990ce04c3e88c1afd858411eafe5b513a7e95868f75e32f35ec491c75ad3cfab1e722fb7c4cd78245231b823e5be16344aaf738bae8dec4c71b7887f4d98d0669fa7be9a3999bdab900973f79519968ffc8cdffe30a4095e856aa036caf1ce82b27610a43f729fa6d9adc0b3ed9195b223ff8d87ff7fc86f59774c8918ce6931cf7e3e38f4d4912019f59a7bccf64f490fc2676014b437a8db2f1c4dae45e76cd840df5198ac033267642fe3f85789a96d5234486ee238f1d9e392699ff21363ea6cbe016ab74d9f4b34a0ca4f1d558d3c7d783c0ce64c717aa59534771d8e9ba47f213364ddd140ff63ca8e0bc5fa775909e0611811d2a12d6716e36662d6fe5d518dcc62e1cafd6d306edb0f75243df0879263b7109561438e1dea37d330ab4600af5e3c1b5c0fc87ad48e9cb31451507a16ca364430514b12bd3b5d9a93ec4e90d50aed1e4dc4c359c50c9f8e8d4a5788d38bbf909fee63031a15bd7c4f52cfa2a913c36a29938f81c6a77912ec50f2b2de8fba2e9125b25dde284cce5b2c6a95414196a96c484d028a6c48ddbb3898197348ab1c94192b42e0b8c2b5e19fb4c401c13c469bccc7f4594ad20da19c2a773d1a88531f259b18ec5fbe4fcd7760d8ef5ef3990a
> cipher suite {1:04x}
> extension {3:x}({3})
> encrypt_then_mac {3}
> extended master secret {4}
 # handshake
 > handshake type 0x02(2) (server_hello)
  > length 0x0004b6(1206)
# starting transcript_hash
 > cipher suite 0x1302 TLS_AES_256_GCM_SHA384
 > sha384
hook server_hello (server)
# record (server)
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x04ba(1210)
# write record content type 0x14(20) (change_cipher_spec)
# record (server)
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
> change_cipher_spec server
# write record content type 0x17(23) (application_data)
# write 0x20349748100 handshake type 0x08(8) (encrypted_extensions)
 # handshake
 > handshake type 0x08(8) (encrypted_extensions)
  > length 0x00000b(11)
hook  (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0020(32)
# write record content type 0x17(23) (application_data)
# write 0x20349748100 handshake type 0x0b(11) (certificate)
 > certificate
 # handshake
 > handshake type 0x0b(11) (certificate)
  > length 0x001618(5656)
hook server_certificate (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x162d(5677)
# write record content type 0x17(23) (application_data)
# write 0x20349748100 handshake type 0x0f(15) (certificate_verify)
 # handshake
 > handshake type 0x0f(15) (certificate_verify)
  > length 0x000cf1(3313)
hook server_certificate_verified (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0d06(3334)
# write record content type 0x17(23) (application_data)
# write 0x20349748100 handshake type 0x14(20) (finished)
> finished
  key   aa67494fb00a6e5931cff474813d482eed9b58e998ab0e31629b2b26f8e3f3d956c1f206a8f53a5675391147dc6f1259
  hash  1ae9f7ace3f06d1763169a571ac9f6dde385fc581e96c5e2263221c2345c016675be35e7f33b288ca2cbd21affde7ebf
  maced 55e6bd90444b4f4249392a192baabd8141b820f98eba72f3dac24101d7a09bf70b4bfe0cd820912f0cbdf8e149ea463b
> verify data
  > secret [0x0000020a] 0168b254ce4d3e6e0a76bdc1a623c82684019c85b54071ce3bf88d79009655a91160f54dd85f752a2279764705d19be5 (secret_s_hs_traffic)
  > algorithm sha384 size 48
  > verify data 55e6bd90444b4f4249392a192baabd8141b820f98eba72f3dac24101d7a09bf70b4bfe0cd820912f0cbdf8e149ea463b
 # handshake
 > handshake type 0x14(20) (finished)
  > length 0x000030(48)
hook server_finished (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0045(69)
# record (client) [size 0x50(80) pos 0x0]
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
> change_cipher_spec client
# record (client) [size 0x50(80) pos 0x6]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0045(69)
# read handshake type 0x14(20) (finished)
 > handshake type 0x14(20) (finished)
  > length 0x000030(48)
> finished
  key   d0b12906fa8bcf6f11dde1987e75cad0ee34677a8131de01faa998121a304c60dfa8370b17ce94e746f0f5172f66963f
  hash  25e767fd86769e0b2dd0dc8f1ece1e786a6cad91124acf6e29f1010bfd65a095b85aba7314975528b22177bde17beb26
  maced 805801e0a5edd4b6cda59ced54f8d4924c8701c084243103429e55d1f09812ee30f974e3e0aff72dd3d1b041f2668cdc
 > verify data true
   > secret [0x00000207] 6b06f07b08907b6582cf9f413c19a4a3275632c4b16e67bc05b85e92cb065d6e675f99d71c2eb584d89f575394801148 (secret_c_hs_traffic)
   > algorithm sha384 size 48
   > verify data 805801e0a5edd4b6cda59ced54f8d4924c8701c084243103429e55d1f09812ee30f974e3e0aff72dd3d1b041f2668cdc
   > maced       805801e0a5edd4b6cda59ced54f8d4924c8701c084243103429e55d1f09812ee30f974e3e0aff72dd3d1b041f2668cdc
hook client_finished (server)
    > application data
# record (client) [size 0x7d(125) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0078(120)
    > application data
      00000000 : 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 0D 0A | PRI * HTTP/2.0..
      00000010 : 0D 0A 53 4D 0D 0A 0D 0A 00 00 12 04 00 00 00 00 | ..SM............
      00000020 : 00 00 03 00 00 00 64 00 04 00 01 00 00 00 02 00 | ......d.........
      00000030 : 00 00 00 00 00 04 08 00 00 00 00 00 3E 7F 00 01 | ............>...
      00000040 : 00 00 1E 01 05 00 00 00 01 82 87 41 8A A0 E4 1D | ...........A....
      00000050 : 13 9D 09 B8 F8 00 0F 84 7A 88 25 B6 50 C3 CB 88 | ........z.%.P...
      00000060 : 0B 83 53 03 2A 2F 2A -- -- -- -- -- -- -- -- -- | ..S.*/*
+ read
   00000000 : 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 0D 0A | PRI * HTTP/2.0..
   00000010 : 0D 0A 53 4D 0D 0A 0D 0A 00 00 12 04 00 00 00 00 | ..SM............
   00000020 : 00 00 03 00 00 00 64 00 04 00 01 00 00 00 02 00 | ......d.........
   00000030 : 00 00 00 00 00 04 08 00 00 00 00 00 3E 7F 00 01 | ............>...
   00000040 : 00 00 1E 01 05 00 00 00 01 82 87 41 8A A0 E4 1D | ...........A....
   00000050 : 13 9D 09 B8 F8 00 0F 84 7A 88 25 B6 50 C3 CB 88 | ........z.%.P...
   00000060 : 0B 83 53 03 2A 2F 2A -- -- -- -- -- -- -- -- -- | ..S.*/*
# record (client) [size 0x30(48) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x002b(43)
    > application data
      00000000 : 00 00 04 08 00 00 00 00 01 00 9F 00 01 00 00 04 | ................
      00000010 : 08 00 00 00 00 01 00 9F 00 01 -- -- -- -- -- -- | ..........
+ read
   00000000 : 00 00 04 08 00 00 00 00 01 00 9F 00 01 00 00 04 | ................
   00000010 : 08 00 00 00 00 01 00 9F 00 01 -- -- -- -- -- -- | ..........
* protocol complete 51 out of 103
* protocol complete 13 out of 52
* protocol complete 39 out of 39
* protocol complete 13 out of 26
* protocol complete 13 out of 13
- http/2 frame type 4 SETTINGS
 > length 0x12(18) type 4 flags 00 stream identifier 00000000
 > flags [ ]
 > identifier 2 value 0 (SETTINGS_ENABLE_PUSH 0x00000000)
 > identifier 3 value 100 (SETTINGS_MAX_CONCURRENT_STREAMS 0x00000064)
 > identifier 4 value 65536 (SETTINGS_INITIAL_WINDOW_SIZE 0x00010000)
# write record content type 0x17(23) (application_data)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x002c(44)
- http/2 frame type 8 WINDOW_UPDATE
 > length 0x04(4) type 8 flags 00 stream identifier 00000000
 > flags [ ]
 > window size increment 1048510465
# record (client) [size 0x1f(31) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x001a(26)
    > application data
      00000000 : 00 00 00 04 01 00 00 00 00 -- -- -- -- -- -- -- | .........
+ read
   00000000 : 00 00 00 04 01 00 00 00 00 -- -- -- -- -- -- -- | .........
+ insert entry[0] :authority=localhost:9000
+ insert entry[1] user-agent=curl/8.20.0
+ insert entry[2] accept=*/*
- http/2 frame type 1 HEADERS
 > length 0x1e(30) type 1 flags 05 stream identifier 00000001
 > flags [ END_STREAM END_HEADERS ]
 > fragment
   00000000 : 82 87 41 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 84 7A | ..A............z
   00000010 : 88 25 B6 50 C3 CB 88 0B 83 53 03 2A 2F 2A -- -- | .%.P.....S.*/*
 > :method: GET
 > :scheme: https
 > :authority: localhost:9000
 > :path: /
 > user-agent: curl/8.20.0
 > accept: */*
- http/2 frame type 1 HEADERS
 > length 0x10(16) type 1 flags 04 stream identifier 00000001
 > flags [ END_HEADERS ]
 > fragment
   00000000 : 88 0F 10 87 49 7C A5 89 D3 4D 1F 0F 0D 82 13 E1 | ....I|...M......
 > :status: 200
 > content-type: text/html
 > content-length: 291

- http/2 frame type 0 DATA
 > length 0x123(291) type 0 flags 01 stream identifier 00000001
 > flags [ END_STREAM ]
 > data
   00000000 : 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E 0A | <!DOCTYPE html>.
   00000010 : 3C 68 74 6D 6C 3E 0A 3C 68 65 61 64 3E 0A 20 20 | <html>.<head>.
   00000020 : 3C 74 69 74 6C 65 3E 74 65 73 74 3C 2F 74 69 74 | <title>test</tit
   00000030 : 6C 65 3E 0A 20 20 3C 6D 65 74 61 20 63 68 61 72 | le>.  <meta char
   00000040 : 73 65 74 3D 22 55 54 46 2D 38 22 3E 0A 3C 2F 68 | set="UTF-8">.</h
   00000050 : 65 61 64 3E 0A 3C 62 6F 64 79 3E 0A 20 20 3C 70 | ead>.<body>.  <p
   00000060 : 3E 48 65 6C 6C 6F 20 77 6F 72 6C 64 3C 2F 70 3E | >Hello world</p>
   00000070 : 0A 20 20 3C 75 6C 3E 0A 20 20 20 20 3C 6C 69 3E | .  <ul>.    <li>
   00000080 : 3C 61 20 68 72 65 66 3D 22 2F 61 70 69 2F 68 74 | <a href="/api/ht
   00000090 : 6D 6C 22 3E 68 74 6D 6C 20 72 65 73 70 6F 6E 73 | ml">html respons
   000000A0 : 65 3C 2F 61 3E 3C 2F 6C 69 3E 0A 20 20 20 20 3C | e</a></li>.    <
   000000B0 : 6C 69 3E 3C 61 20 68 72 65 66 3D 22 2F 61 70 69 | li><a href="/api
   000000C0 : 2F 6A 73 6F 6E 22 3E 6A 73 6F 6E 20 72 65 73 70 | /json">json resp
   000000D0 : 6F 6E 73 65 3C 2F 61 3E 3C 2F 6C 69 3E 0A 20 20 | onse</a></li>.
   000000E0 : 20 20 3C 6C 69 3E 3C 61 20 68 72 65 66 3D 22 2F |   <li><a href="/
   000000F0 : 61 70 69 2F 74 65 73 74 22 3E 72 65 73 70 6F 6E | api/test">respon
   00000100 : 73 65 3C 2F 61 3E 3C 2F 6C 69 3E 0A 20 20 3C 2F | se</a></li>.  </
   00000110 : 75 6C 3E 0A 3C 2F 62 6F 64 79 3E 0A 3C 2F 68 74 | ul>.</body>.</ht
   00000120 : 6D 6C 3E -- -- -- -- -- -- -- -- -- -- -- -- -- | ml>

# write record content type 0x17(23) (application_data)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0156(342)
- http/2 frame type 8 WINDOW_UPDATE
 > length 0x04(4) type 8 flags 00 stream identifier 00000001
 > flags [ ]
 > window size increment 10420225
- http/2 frame type 8 WINDOW_UPDATE
 > length 0x04(4) type 8 flags 00 stream identifier 00000001
 > flags [ ]
 > window size increment 10420225
* protocol complete 9 out of 9
- http/2 frame type 4 SETTINGS
 > length 0x00(0) type 4 flags 01 stream identifier 00000000
 > flags [ ACK ]
# write record content type 0x17(23) (application_data)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x001a(26)
# record (client) [size 0x30(48) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x002b(43)
    > application data
      00000000 : 00 00 11 07 00 00 00 00 00 00 00 00 00 00 00 00 | ................
      00000010 : 00 73 68 75 74 64 6F 77 6E 00 -- -- -- -- -- -- | .shutdown.
+ read
   00000000 : 00 00 11 07 00 00 00 00 00 00 00 00 00 00 00 00 | ................
   00000010 : 00 73 68 75 74 64 6F 77 6E 00 -- -- -- -- -- -- | .shutdown.
# record (client) [size 0x18(24) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0013(19)
hook client_close_notify (server)
 > alert
 > alert level 1 warning
 > alert desc  0 close_notify
    > application data
* protocol complete 26 out of 26
- http/2 frame type 7 GOAWAY
 > length 0x11(17) type 7 flags 00 stream identifier 00000000
 > flags [ ]
 > last stream id 0
 > error code 0
 > debug data
   00000000 : 73 68 75 74 64 6F 77 6E 00 -- -- -- -- -- -- -- | shutdown.

- event_loop_break_concurrent : break 1/4
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
