#### server

$ ./test-tlsserver.exe -r -d -T -cert mldsa &
````
ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_AES_256_CCM:TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
# set ciphersuite(s)
 > 0x1301 TLS_AES_128_GCM_SHA256
 > 0x1302 TLS_AES_256_GCM_SHA384
 > 0x1303 TLS_CHACHA20_POLY1305_SHA256
 > 0x1304 TLS_AES_128_CCM_SHA256
 > 0x1305 TLS_AES_128_CCM_8_SHA256
 > 0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 > 0xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 > 0xc02b TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 > 0xc02c TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 > 0xc0ac TLS_ECDHE_ECDSA_WITH_AES_128_CCM
 > 0xc0ad TLS_ECDHE_ECDSA_WITH_AES_256_CCM
 > 0xc0ae TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
 > 0xc0af TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
 > 0xcca9 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 > 0xc023 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 > 0xc024 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
 > 0xc02f TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 > 0xc030 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 > 0xcca8 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
openssl version 40000000
socket 252 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 00000194 created
socket 432 created family 23(AF_INET6) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001bc created
- event_loop_new tid 00007fc0
- event_loop_new tid 00006f88
- event_loop_new tid 000098ec
- event_loop_new tid 000037e0
iocp handle 000001bc bind 556
connect 556
# record (client) [size 0x574(1396) pos 0x0]
> record content type 0x16(22) (handshake)
 > record version 0x0301 (TLS v1.0)
 > len 0x056f(1391)
# read handshake type 0x01(1) (client_hello)
 > handshake type 0x01(1) (client_hello)
  > length 0x00056b(1387)
  > version 0x0303 (TLS v1.2)
  > random
    4fef438e1e687e0888797f2dddda175e015f077e3343def84ff7957c36be6ddd
  > session id 20(32)
    53d838c15357861ff459f72f61c4ae9a4dea32517bd1b6e8e3bfc66542cd6342
  > cookie
  > cipher suite len 0002(1 ent.)
    [0] 0x1304 TLS_AES_128_CCM_SHA256
  > compression method len 1
    [0] 0x00 null
  > extension len 0x0520(1312)
  > extension - 000a supported_groups
   > extension len 0x0004(4)
   > curves (1 ent.)
     [0] 0x11ec(4588) X25519MLKEM768
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
   > extension len 0x04c6(1222)
+ add pub key CH.pub (group X25519MLKEM768)
   > len 1220(0x04c4)
    > key share entry
     > group 0x11ec (X25519MLKEM768)
     > public key len 04c0(1216)
       dcb4ce09e154de5c82c7b151ec5c7fa9f216b2ba0a18d93dc4d6b0b35c652f266047c16646c6109e71c0942cc64f11c1d283495dd249631417b1c89c0be72ab15b5fc2a07e54f9aa0793b860a55b02d482f44cb78b76218b694efb2801aac08da1aa2ab4a9c9a956970ae83d9f24c689f51f81574df581b90fbac6df4a63a592b0e6f5366d1796bbe6a1bed57f9164945c1b6937666ca292b980221c34751b71e519c270b68ee07914c65f67718ce2a25832f65f872b25f25109b468c3bd0031db996f7afc76384c54330cd0c9813b145a5d5c583e364842db2a68cb41c331bba123fc45a273ba224c044d269ceb368bddf799de61c7b0c67f125484af38a622e399fa755f56c5c2e03c3a23576d88e638bf14a30a267d8224cf779707de9a5da5a24f13251469c6a786a44dfc986f1a6c494e7bb198261875550efa56445ce7a5267216895a422ba9c78a52acfc1a3a2cbc56d6a1c5cb30230cd53975a1c712719861eac93a7696d7c8c166ccc7dd8b4eed344d79909643230c73a5c3c3b7cbe8e148580401cc94c037057627c02515c170b6420aeefa29cd189a593a5f49956907d9c4eec2ae0ac41da8b7b5b194a7b470c81571abf77a2532031cf94840c003b89b2cc6bd2740023871576c045df76d159604d784b42b169d2d4b43024c86ef2c4989a752123a90b4bc0928b64638b81e7b8b0416a29af45c3cf54b77e7e33c8689ca9992b6eb5a460674c2257b45af00267108065bea7b51b32b587c095f7788f8eb57023a721df94ec5d5133dcc7e044629fb41c9a4833fe955b1f9ca4e43f27e8404b20157ca1e2bb4aafc27d5d34333b76c356389c1b854b0184550776b8b63bb5cc415c293c5f8b038ddcc10b257bfeec149393417cfd1852319710c0c1a31d66a4245793576146fa7670cec890b870582d6c5df438e353a0e205a45ea10c503b122a2726bd54c03eba69e9011c5b4511bd7b90bd84b921e57656aa5641c05cfe4449b8d6931789560fa911662d93392e0491d1cbee7dcb8f31a0178516f44d08f1e0323e1833e1f7b0b2847593c541a08d532eea298749b2190f37e27945117a06a8f8c933dd603aee550452649d8673a2d7763e2da3689428398d9555ae97f292350b96266c6272aaeb7be43e384af43ce04744123cc17db085be694420bd666cac36b19c48cf7ebb79066552d2c3a255490ce396edb543a1dfab4773272f97ba0b64a458e2c38b8c47004c70a7966cb22f0a6ca45a4ede7952fe8077c817d4af8383fcb3ab6bc4a4698b31040ae4588a02577392a77268dd18f55567c4cf0a418da0c4f965c6be7069406cdcde036f62470500660decb56b4650c67a46f3fc29243e94cb973b1254c40a226565e9a2964db916e886165e9a6587085d770c20d858684254f0102b0fcb83bea1ca048fa46afb688919115116a9669d9535e101ddd0cb63c995c432b25b835c7d064106f246c1112b5c0514efd2cb7264a782e77357e292458388f06c2c5662459b9b1a7ff716dc27a05bff93da210828fe3c5ff20ac2af603db9b6c30459af83743e2997328c215ea340c2d933fa1809d59603676981967f129635744db8c574c18a452a3a1e35b9a60671b06d12c9fb066a8f567d19b286dc8eca4ec1f597f2c3132c592530f026be84bd5bca8f5143696ce2650793fbc6b24f2bb9e5b7d54d6b3075fd5199e97e5de18f9e1ed2b
  > extension - 001b compress_certificate
   > extension len 0x0003(3)
   > algorithm len 2 (1 ent.)
     [0] 0x0001 zlib
hook client_hello (server)
 ? # 0x1304 TLS_AES_128_CCM_SHA256
 ! # 0x1304 TLS_AES_128_CCM_SHA256
 - # 0x11ec X25519MLKEM768
+ add keypair SH.priv (group X25519MLKEM768)
# write record content type 0x16(22) (handshake)
# write 0x2c96bd49520 handshake type 0x02(2) (server_hello)
   > encaps
   > group X25519MLKEM768 759194b86a99fb682617aa0ebbd9f9b389a1341395301a887f323817d6851211b04044669fd87f8c51e1bc1fd7c18c6a066f176289638792d4372922f09ddb6d5766f750925de17cf4a9e2f243f8ac94d62c7de68c446ed5975d90a054d7d7da96a7196147a38b0028825bedca62b4650193edd9b8c0be0f677fed0a848ed9ee999a1333e92fa73b83405ac8a7511ef52c5a2fcb16c0638c5112175eb6d8cf7f6f9594dba96c61f91bf256b5ec121ef50a9834bc2caa378b279d2eec8972bbe7a4705057b8c0240bd84b178f37c9c2b2b3301128e0af6c09045cb7dd47c37696c48e9ce486b6c908a6faf213b37d147823cb21a08dd6eff8ec57b8dd01ea6a349d9c0e6a2356aae5f09f7afcecb94422bda8c428f0e4dc47239e8516ea014e5ac5143154431cef724346e980a9a99472670b9e342bdb0eee8ab9b98afb881e7f5531b646c28216ef3d69ec83ec624569b6c9f8907dcdef040856f5a47868b246eb76833ff7b5d605aa335de1d1e06dd3cdc4283f9670c081ffa687c3c9a2be0f6eddc4420e60f32eaf534334662b3d6d388f4d5518abcdbd14ec3c3e6620c0198f4c69d8dcfea2f66cd92650159e8f0d7b83ee6aea73f59e08c232958472eceeb0c8f17571ca70356dd8a0db4725a33e5b43db4ee0d623017b6f14af2cdb0f688c8147c0dac35ed03f73387bb231ffa8be727ff6b103a57da9e9892fed8da3a7cafe2369eb4c93e0410af50009462bdc9ce3f6c2f786114d826cab5828cef3e0b34ee9afc187eec9f6b6e7ea4ea1c2d2fd2abd965051ec278b2ce234de0f7361e9ee7b492334aaaa84bed53f9dc663d235b46dfdfce4c2b6112e86900ae13f7cf74b8cc50bdf0377247f12197f8cd4e47469010f751a4a7b28916889424b8a3954bf6c4a9d2b62323ee473bc2880f694f706b29bd5dbedb601c773d25f15325e3f9005d020bd188a6d31da8e48187cbe95842920c1542451f5a52c74a5de49447483e3001f77ed0825df7847d70204a93288a90042c1d770edba34a64299cea3453560f64d1956b31b79a1b516e8f9f6491bf047e2d8a50ff9183e6925b0a99ac5b2e93b15b56beb5ca199f0dc439b6c019bd31122d7b5ffca34b34433714298b5f4e23e7ef3ce986b72fc6cc658c3f07d112b8dc05b412e873159cb1a24eddb2e9314bb3b978dbe3a671cf6c77d729139a22374af967595c5c50fbfa41f1d6a5fbf79be4078f6e4518dd5e9f4b7eefcdb7a27b3ffa19cbb1bc7b44ff98fe0456018db5d3563e95e62ad38db911871b0dff1c64d93a030e5a61b7194dda7ba1e08694d01b4a671690929e56b6ba3c2db41359a1e0d094522556586b680b72a7f66991ed0855fc25fdc24e86e7c0a537b3b0d116e2056e3401b83a68c0e949cccb285d52614511a6be1969e1164e485a8acc5a0a289776f305ae0b433f5eb38a170d8f271620825d7598d824c379b1ab114e52f5a5723ec198463bfa3627f122c84fd6a9fddaf168cc8ebb5f8bdfa0560a3df11b20a4c16c153357caa2ea425231d6c010c494e16a360898ca5555d2ec016a3da4e8d791eda79d27f39b02b8911
> encrypt_then_mac 0
> extended master secret 0
 # handshake
 > handshake type 0x02(2) (server_hello)
  > length 0x0004b6(1206)
# starting transcript_hash
 > cipher suite 0x1304 TLS_AES_128_CCM_SHA256
 > sha256
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
# write 0x2c96bd49520 handshake type 0x08(8) (encrypted_extensions)
 # handshake
 > handshake type 0x08(8) (encrypted_extensions)
  > length 0x000002(2)
hook  (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
# write record content type 0x17(23) (application_data)
# write 0x2c96bd49520 handshake type 0x0b(11) (certificate)
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
# write 0x2c96bd49520 handshake type 0x0f(15) (certificate_verify)
 # handshake
 > handshake type 0x0f(15) (certificate_verify)
  > length 0x000cf1(3313)
hook server_certificate_verified (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0d06(3334)
# write record content type 0x17(23) (application_data)
# write 0x2c96bd49520 handshake type 0x14(20) (finished)
> finished
  key   db0ce8289341014f51e5b854ce655033aa7064600f191fe1b36556f9212262c1
  hash  9d9d1ec8a108d34a910897e5bc0daa95f80ecb5a490c476bbb854411e44b2d1d
  maced 7f127e480a99ecfcf576864b05710d5dcc817ee536bdbe777ddf32391e46f81e
> verify data
  > secret [0x0000020a] f7e35be27608fc0773a3c9bc19aa1a132696038e27d2fab6c226d7045513d19a (secret_s_hs_traffic)
  > algorithm sha256 size 32
  > verify data 7f127e480a99ecfcf576864b05710d5dcc817ee536bdbe777ddf32391e46f81e
 # handshake
 > handshake type 0x14(20) (finished)
  > length 0x000020(32)
hook server_finished (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0035(53)
# record (client) [size 0x40(64) pos 0x0]
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
> change_cipher_spec client
# record (client) [size 0x40(64) pos 0x6]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0035(53)
# read handshake type 0x14(20) (finished)
 > handshake type 0x14(20) (finished)
  > length 0x000020(32)
> finished
  key   618c927c53eed22faf269485137b38e0f6801c7ac8c976ecf5e03118e5a685b9
  hash  9b0ac3c3b7bc20887b687a9261bbd540f0d789dbca5c59c9d021531ef10af43f
  maced b03a56a50925c2806623d57951e5184a94b1e15864e547b12d47ea69240b9f1f
 > verify data true
   > secret [0x00000207] f16411422c3b93836b2274be8e0c80a05bb9de39ced87d104fb8212031dcff51 (secret_c_hs_traffic)
   > algorithm sha256 size 32
   > verify data b03a56a50925c2806623d57951e5184a94b1e15864e547b12d47ea69240b9f1f
   > maced       b03a56a50925c2806623d57951e5184a94b1e15864e547b12d47ea69240b9f1f
hook client_finished (server)
    > application data
# record (client) [size 0x1c(28) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
    > application data
      00000000 : 74 65 73 74 0D 0A -- -- -- -- -- -- -- -- -- -- | test..
+ read
   00000000 : 74 65 73 74 0D 0A -- -- -- -- -- -- -- -- -- -- | test..
read 556 msg [test
]
# write record content type 0x17(23) (application_data)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
# record (client) [size 0x18(24) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0013(19)
hook client_close_notify (server)
 > alert
 > alert level 1 warning
 > alert desc  0 close_notify
    > application data
disconnect 556
iocp handle 000001bc bind 556
connect 556
# record (client) [size 0x574(1396) pos 0x0]
> record content type 0x16(22) (handshake)
 > record version 0x0301 (TLS v1.0)
 > len 0x056f(1391)
# read handshake type 0x01(1) (client_hello)
 > handshake type 0x01(1) (client_hello)
  > length 0x00056b(1387)
  > version 0x0303 (TLS v1.2)
  > random
    591188eb46a848497b159dead62f5232e92fb0ddff1027ee70b8f1ab78cf4a9a
  > session id 20(32)
    740dd9d8c2383847f3814346bfad81296acc4623fc68086b2895a67a744642a8
  > cookie
  > cipher suite len 0002(1 ent.)
    [0] 0x1304 TLS_AES_128_CCM_SHA256
  > compression method len 1
    [0] 0x00 null
  > extension len 0x0520(1312)
  > extension - 000a supported_groups
   > extension len 0x0004(4)
   > curves (1 ent.)
     [0] 0x11ec(4588) X25519MLKEM768
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
   > extension len 0x04c6(1222)
+ add pub key CH.pub (group X25519MLKEM768)
   > len 1220(0x04c4)
    > key share entry
     > group 0x11ec (X25519MLKEM768)
     > public key len 04c0(1216)
       85b23d318c433249c4b7eb6ef4333e82044df0288ca3517f4d2112f6aa5512e55578ec2da542c8f2cbb36d00a4380b9b20f362629915a6e209f3fbc4accb178ff55fc5b913db181ec3a6773715badbd3962fbc68e21535f2cb7ef694ad73e712a62982635690695a99dda0c0f7e68b30e2469438a595798260153b0cb899d2219cf4c6711dd7af7f20586f385d83c8bcf2c94daa09348c0a0ebe83576a18c29406b7c8e38ee49246cae3b54455c842dc980427555cfb417791b04328c07201cc57570250966e0da62af70b4329236db1566bc93a9525b31509b7649f799bbe51aac0141ebbda85ef1ca98ea07528a51d0dca0068b3aac8b42cbc8c3c47c37106e23a11b5cd7c945b40635ebb7b91fe56b374101bc95569b5e04bda8b1fdb809e65294cfc98222d5a87ad47b2941cca121963ec312be2752432e0162ce49586b12c2ce59d435c7ca8b36f88599636a9b82d31505c3559fe6999e0a20300a49e9ed4a88c01ce0ba7c52cea93125c4ccbdaced0b17015603b31f81118ac21acf654f7cc351f1594180ca94ea441d34830a5f88cd8b49899a4bd0d1643bceccec00c209e187350faa47c2852f9b40f2b6010f965a701db8f5c738bdd053e18784f896306d4c3c442f36624d4cd176ab2d1a5b7e19bac624b1178acac83b4150e0654c5e1ac3e7a91bba48fb76b3146a3216b54ba00d6c90c1a91c324c8c3a9905c829e9b0acfd9e408b1f42d79d036f639bbdb80873039cde4e46a1239859c983d29d13fe5cc6b00c44ebd7026ad746d6811b576bba3738b24a6b96afaf5c799b8c81b468e729843aca43a6cb96176754e12ea741c1477ff55470b8b6d63c977d19049665c9dc7537021fb43045c32f1e0ce0e174b5b2b523f34849f6c9fdbdc4232a98bd2278bdf3989415765598c02c9917708798aca962bacc1a3230220af90106da68cbef841f6b4846053a999218de1a2c783c8269acc573e48ab502655a5c0b31ee04fc14a961434a163771539a623f49832c4e83ac1c2a6e0f8328df48c45b5a37054b9ec984d19d7774c5cc17e24c0684274d0468aef859eaffc63789075f6b4433e0115d0ecb66991cbffc259cab919a79626acd756a13a8140c083e001b764c453b1dbb12493a3f5f17e47c6c231d41d9cd82f35c90f83aba49f6cc8d4ac9fcf717276b705f3124634f5972b06c294b522f47b716e97790ab29610c06b1d90c6e05a9af4a5b0d201cefa5c471073984203472f45368446c491917a1c24c9e1650cf340b2926345681505b919cfb35885f1292017b5c82be4b261846a9c779b6f954fa0fb6b5b5714de46b9d5c41e1a79724b48a8c2fcb4f849b9301697f2c6c7bc5bc4f84409bd05676858a46a6c81f66393372468961671b7148980e8b8a6565c54c307d6f6a925a7a72fea9683d91513736c4b3742f65940e65602f3335b1bdaa7eeabbd25c118af1b28ac4325cbc5b77a217ffc480d71d711dcd2b9a89b36d0a537f63484ccf496673472b6865e67ac0ccb0453dff84e547875608a2b3503a9f379b5448aa3c781000eb70ac86a6ebb8061cda32b3839687cc4796981718ce52264d4207fc1ad20877614821d43b80619618d9d56638b131d670b75554dd8babd944a5ac7fa09967df07cb5e132cb732213031da446c4acb5574c637d4f615380b3e46928e4087eaf03c9eeebe7153eca387e4d663c82f4c70e0a3e
  > extension - 001b compress_certificate
   > extension len 0x0003(3)
   > algorithm len 2 (1 ent.)
     [0] 0x0001 zlib
hook client_hello (server)
 ? # 0x1304 TLS_AES_128_CCM_SHA256
 ! # 0x1304 TLS_AES_128_CCM_SHA256
 - # 0x11ec X25519MLKEM768
+ add keypair SH.priv (group X25519MLKEM768)
# write record content type 0x16(22) (handshake)
# write 0x2c96bd49520 handshake type 0x02(2) (server_hello)
   > encaps
   > group X25519MLKEM768 4336d46b8b7d8209dbabf7eaa686b5c867dfce606a6a86316630b4415a4c361c121b22e5949b4258ddad6d972a829116b76c4a61e676fe0961ed5d4983febbc23cf9216e804cf84d1a5eecb8059cbc194df5621924b33c003ee8a8250ad39e8dbbcd378f30fd9460ec47eabfb1d4a094bbb375cfdddb209210c8eefb9373e8ae15c652a84e65a460ef9411ae03ede80bdcab069a146c62a02b8150358c68563b218fd624faafeb4326f7bab1811934c3c2c46d3d5d81cf9563c4fdd4e1e70df44f629ee993a26d03da73950cac930804d2dc0a302bf7a3a849f15cd596f1169c4872fa611765cc21bf39d3e27327251478a6a143f446c217dad34d51c9cdc89b9e336c6d027db780ae1c7ff696f870c42afcb22ad7c8da8086208ad458bd592de41485d0969c0ed95fcb7ca1b9727e2d619da4141613bbc35deacfa5180f66fa673267a64c8776b549d8eba97fa5c0bb740ce8f255fa2735a7e94c290dd767e545d9926653579d83f7baee69588f7ce038ce11ab53d7aa241683515807f787a4807321ea54a23f0900f7929991ea061c518fe5bc127203e1f825ed35692da6ad234b78612b90a4613d4204c5d4c825d8ee981a6bad1b51aaca97ec126edf407a3621774b142fcfe307d9d5aa0c4840c1fb843d02b0a9b455daee5888a3073682b4a56f05ff8dde68fea68b59a9f9268f756674bd77a4b32a3ec3c3a570a5fa724693e3d866038fd8e6531a6b84f05d66f8521bfe6d6e969a3d83be7a7fc5763a19a54cf8f1f5d3088a5855a90f16d5fed169d1ce64b1d0e58e84fd2483b9d8d9251ca4a60df2082fea48c3e2934e35ddadcfb8aa192d5a84f678169bb30638442ffb4e16596d4383ad31cd74d234d841d1b8f7c3d1f61a9adae3cec44691451a22207c50cdcc4164b7902b2b88f0aeb6ed6552d70db8381412ff22ab50b879a4f4796175ea580ec7257d7b6addc8ec7b901b7d83a2f00c288d3d75d140f7cc27f0cabcf07511273ee518dba6beb6f27c649e863044c3a78dc2822e449fc7457a053eb96a1703b48eb323ffe77094f0d3d0058fcc0d8f7297aa0f1193b4c40217ca1e8f65084d11552ec80c568d686e7623b30f05f8be587a8e334f7f4660085ff5632cd6cf150fbf6a35db01e31aafd8f1adc1e46bd3999dcb9c76a4c87df424c14833cf2fe8727ff298d0a51850d0a9c4110722cc972ce1401716a1aeb2414e52df3e3835f53fdf78098db38304383b7b503af68dc0cb5962d129553dfca5f307c3b3ab8af199f8b48d9cd60acfceecefba6f9caf948ce4fc1e3de641cb3dc6203ca9ac4b23718bc1144c254e2a5e502d8eaf0420ba85c96da4408146418a6971c57b6380d27b55f79ebaeb4182c8e70980c40e3522a27547cabf8c9de6fd2d7f05aab45de4ae3c2cab12ae76aec9f804f947f983d0ebf401978b3dfbcbae987e9f773570128218d1e98930a07d6995a4efb49c9b8fef24ceddfc0195473ce60f3b771608a4dd18206272c8fb4eaef5249051af2fdf0eb8660a51d22614630224cee173924c9d91997b67370b088472273f627ec8dcf585ad32d1b2b7a67616
> encrypt_then_mac 0
> extended master secret 0
 # handshake
 > handshake type 0x02(2) (server_hello)
  > length 0x0004b6(1206)
# starting transcript_hash
 > cipher suite 0x1304 TLS_AES_128_CCM_SHA256
 > sha256
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
# write 0x2c96bd49520 handshake type 0x08(8) (encrypted_extensions)
 # handshake
 > handshake type 0x08(8) (encrypted_extensions)
  > length 0x000002(2)
hook  (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
# write record content type 0x17(23) (application_data)
# write 0x2c96bd49520 handshake type 0x0b(11) (certificate)
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
# write 0x2c96bd49520 handshake type 0x0f(15) (certificate_verify)
 # handshake
 > handshake type 0x0f(15) (certificate_verify)
  > length 0x000cf1(3313)
hook server_certificate_verified (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0d06(3334)
# write record content type 0x17(23) (application_data)
# write 0x2c96bd49520 handshake type 0x14(20) (finished)
> finished
  key   5ee99b2affb4ba5ade811cee520c6dcc923e290fc2f207dd77e51014aa7d562f
  hash  901546e59193816d5cfb016f2f66372dcd3889a0373d0c0a566ccaa201a4089a
  maced dc8b28d7edf7aa1010a9bdae9620d74f518b576ee6b10397751e89885be4d4fb
> verify data
  > secret [0x0000020a] 7106beda42f02aa332c87666654e69fa0753712b3cc1a845b15039109f735c5b (secret_s_hs_traffic)
  > algorithm sha256 size 32
  > verify data dc8b28d7edf7aa1010a9bdae9620d74f518b576ee6b10397751e89885be4d4fb
 # handshake
 > handshake type 0x14(20) (finished)
  > length 0x000020(32)
hook server_finished (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0035(53)
# record (client) [size 0x40(64) pos 0x0]
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
> change_cipher_spec client
# record (client) [size 0x40(64) pos 0x6]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0035(53)
# read handshake type 0x14(20) (finished)
 > handshake type 0x14(20) (finished)
  > length 0x000020(32)
> finished
  key   6012c8c1cccea8c62d8e479001d73bacb9da0ee2c9cc3a246912f56b10cd13cd
  hash  ec13d7e32eeec769defd0e8482a0dc2fa5a792bb344035b92fb4c671a7d293bb
  maced bdf53cb5d8bc5cd4718b9c2cc2724c4ba4a65d4e572d062a5ff518199d572a3a
 > verify data true
   > secret [0x00000207] 93ca03c7c94e2dd9a8a74cf5b3957e4726db7ba6b537ee4fc252436e9bbd8525 (secret_c_hs_traffic)
   > algorithm sha256 size 32
   > verify data bdf53cb5d8bc5cd4718b9c2cc2724c4ba4a65d4e572d062a5ff518199d572a3a
   > maced       bdf53cb5d8bc5cd4718b9c2cc2724c4ba4a65d4e572d062a5ff518199d572a3a
hook client_finished (server)
    > application data
# record (client) [size 0x1c(28) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
    > application data
      00000000 : 74 65 73 74 0D 0A -- -- -- -- -- -- -- -- -- -- | test..
+ read
   00000000 : 74 65 73 74 0D 0A -- -- -- -- -- -- -- -- -- -- | test..
read 556 msg [test
]
# write record content type 0x17(23) (application_data)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
# record (client) [size 0x18(24) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0013(19)
hook client_close_notify (server)
 > alert
 > alert level 1 warning
 > alert desc  0 close_notify
    > application data
disconnect 556
- event_loop_break_concurrent : break 1/2
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/1
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/2
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/1
- event_loop_test_broken : broken detected
````

[TOC](README.md)
