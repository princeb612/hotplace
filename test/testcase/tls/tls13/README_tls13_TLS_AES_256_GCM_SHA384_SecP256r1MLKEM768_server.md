#### server

````
$ ./test-tlsserver.exe --trace -r -k -T &
# [test case] tls server
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
openssl version 30500020
socket 256 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000000f0 created
socket 524 created family 23(AF_INET6) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 0000021c created
- event_loop_new tid 000065b8
- event_loop_new tid 00009ec8
- event_loop_new tid 00009098
- event_loop_new tid 000047f8
iocp handle 0000021c bind 656
connect 656
# record (client) [size 0x599(1433) pos 0x0]
> record content type 0x16(22) (handshake)
 > record version 0x0301 (TLS v1.0)
 > len 0x0594(1428)
# read handshake type 0x01(1) (client_hello)
 > handshake type 0x01(1) (client_hello)
  > length 0x000590(1424)
  > version 0x0303 (TLS v1.2)
  > random
    848966168f6d2421b7f2107ad342d89341b37ff00eb5bc22cb1f4d4df8993ee8
  > session id 20(32)
    8aaad716c2ad4ec00a953548f62cfa19075e0c95d84df1bce8836c5a3dd370b6
  > cookie
  > cipher suite len 0006(3 ent.)
    [0] 0x1302 TLS_AES_256_GCM_SHA384
    [1] 0x1303 TLS_CHACHA20_POLY1305_SHA256
    [2] 0x1301 TLS_AES_128_GCM_SHA256
  > compression method len 1
    [0] 0x00 null
  > extension len 0x0541(1345)
  > extension - 000a supported_groups
   > extension len 0x0004(4)
   > curves (1 ent.)
     [0] 0x11eb(4587) SecP256r1MLKEM768
  > extension - 0023 session_ticket
   > extension len 0x0000(0)
  > extension - 0016 encrypt_then_mac
   > extension len 0x0000(0)
  > extension - 0017 extended_master_secret
   > extension len 0x0000(0)
  > extension - 000d signature_algorithms
   > extension len 0x002a(42)
   > algorithms (20 ent.)
     [00] 0x0905
     [01] 0x0906
     [02] 0x0904
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
   > extension len 0x04e7(1255)
+ add pub key CH.pub (group SecP256r1MLKEM768)
   > len 1253(0x04e5)
    > key share entry
     > group 0x11eb (SecP256r1MLKEM768)
     > public key len 04e1(1249)
       043c2efe313b835d2f91308c02b85ab298e1dbeb41f4358d3dc0380d2d94b5d417eb7f2938ad579e3fbf4d1046fb5f6311506c9fa0be612d0c9d4748358395664aba9825e666371fcc0c8e95141ff5bd257858f4a2568e8160c1c01a73aac9c32813d78c9dddd9c8a10b675e737b57156cae8069aab1a8e1341badc27a2052b361387c66d15b249b9b15457723d00d82f0738138bb14907407511b96752054f930fee153f46ca7741b5d74046e30f8a08d01134865cec3f2b0de8ba5de948cda7bbbcb38990fb06b1ba50e34364981db55cc0270ca76caf8aa510a6736b5d312b5eb5d92904de57c3b956c275bcb8985f9adfde96af72324d4856209ab2477290e11206646919e07d8a0ead63acb4a49924b7803dac7fd2c6314830623d584140a91a4b94f8b7b52bb0661de942b0dbc18adf49852a3baa425bdf2ab5eee56916406ae22b70a09023eef937d641304fdc516aab9aba9fa40edfb2dea986e0f922ff6f720535bc791301d15216d51261f07b48c0cd2757c0c6b12c9b485f25b66b25f31077963e97b34f51c4b7546b640c099c5020961cd555767f09821b8436e700b356899cf7184a9dd9432fef361003d43ed5007c3ec4154e0ccf05bc3435a2439335743f343633838620880e7a381e7602565494bd405b7fa041cc449b2f1750db9429a7a5118fdb53738611f063492ed7765c59704b6c51b0ae1b00d187030910d16a8c17b195d10b92072c046050b914af87c337710f1864d4b694fd710434b765d34a223aa712afc209c0a499f9e409a6ca4c7a98c6a9bfa726be1bfb286b47428c05b583c08915190ecc1da5aa213ca7708fa855eb5923f518557d72bda665b3b689eae07364042266e9307cba1767c371eb2f8c92188b91aa946c360a5f4c243d8d972458366f7344131d207dcd7c76319125d0763fb15c7970213ed974c55f8ba410b5857935f58d119bec7bbb8561b2fe7b3f22c9e71c7431e33c6be29673dba30f8820a0f52122fea56a20658a3ac5f0b6029acb0ce269a36362306e2b63e7a6296f42b3017e5c98ef9cff11682c6331177d95b28b1b0b6f6a2f3616d9f8b719ffc3f27290dc1dacfe22a9c4c66be32b1c4bfeaa748b8581f49b68da2c24bfaa6bcfc9598daaac41baf32d67ef9d00bf9a81f474889133c7c2b9363b2f8155447603d0ab421d35c2e253cdb896c6fa217295c12a4c6089b07b35b6b4e59a68d9f40042899624fe83347e52215a2c167c022dae3c2bba2469d250e65fc47eb55641bf8cd2594726c077440a75f56047db82ac25ee5561e80403bbc9599f98b59827089bc0dcda193e074b46ff6c669da5c11d360c3f0056a165f65e8bcdba2a11772c365f55193d9b614c1868f9029198b3f141b2d7a5b5a9ce2c0a97952a4b8a85589cd7ab82816b89359c8312b3364b2600f7913a75e241702028276eb063cf60096341b0f4a8b621a368e0c5dced872df702637793be250778c373a0fdc5b8187267c56265b934f7dab8a963b0a6273447b65635aa2882f7a82fb199081111ac6f15bdcd172fb9a315d526b31a5cd1e4950e00a1cd6744dc3d6affe1a9cf2a0be3fd10821ab9dd4e883ed475ad7f7b42c1031e8b31b44581c735a2a06438ad65184de2892469cb5cd3b63567c6d1d188602e29e6606b1aac296ab6c3b80d83bc23c16f9b036d1321bb5f7c2ed079e7bc62b4c5b4b8635100294696a080b88fbcb2079b5fbaf097fab3572a2edfe7cab151ab43a5ac4f9b3eecb21
  > extension - 001b compress_certificate
   > extension len 0x0003(3)
   > algorithm len 2 (1 ent.)
     [0] 0x0001 zlib
hook client_hello (server)
 ? # 0x1302 TLS_AES_256_GCM_SHA384
 ? # 0x1303 TLS_CHACHA20_POLY1305_SHA256
 ? # 0x1301 TLS_AES_128_GCM_SHA256
 ! # 0x1302 TLS_AES_256_GCM_SHA384
 - # 0x11eb SecP256r1MLKEM768
+ add keypair SH.priv (group SecP256r1MLKEM768)
# write record content type 0x16(22) (handshake)
# write 0x26bf2bcd5d0 handshake type 0x02(2) (server_hello)
   > encaps
   > group SecP256r1MLKEM768 0446e178dc5bcc6ddbefe15fcad6d54f0493063c32412d7f3d9e23cf20cee35930ce3e81b1a12b82677bb6263d438ba0bb4ab22359306c4a445eaeec4d34d14b7cf8bb1517494a8e7cb6644957e2bcf5f8576ab6d7c30a0e3b68d9f0edfdb30fe5f267bba4618f2cd3ac719e6aef03c1c647b2e45bcfd204cdb298bb62a916f626e50d55cf6cd0087990604369166a442df83bc735433f6c0a33fca153fec8c8bfb657c071258425e16f88f70eeaa9e7f7d258f68d4e1ea3fc8645f165d2e8eeb7092c055388f215cfd62a70e2b573e226d3a736c2cdf890c0d27c4f27ef0fe7019bc0f662615297b19ae98ccbc45886a2eca866a639683e4223840afaf74c4935f3a14d6757da2756d993267c483768d890567b10c00897891e5c4d5851a006cf55a22cc691796fff67880d41e631fee7eaf0f470118707eaf2d0fd6e422981f49830777d2a396b8d5608bfde0d24f82712b1f8bbd1e5483f02045ab3eacfe132732aded6504577aad884e182bcf17dabaf10faad73d35f59536db9adb76906ea047fe109e855624c97fe65b2ca3fab352f0bb82895c338932f0c72e5cad8b0af0ec7eb8ccbef251568f16d5c1c1d643f6e0315e04e306b3bb705a4731f00595813f35fed1603f23f3e27c17a087ef442206ab64b5d97b3ce98e25c62ea0c03b68174491af6cca5be61e863a9024610ccdffac9496718bb1732ec3e60af5612cf2a1600c2607a2ac0305728d70be46a81aa302eadd3693b4038df537f4e02399eb3f1e365b651798056289b90518a8a4f5cefc536ca3d3ccd29cba6c66b83a11a777152df269329ec228a6d70b0a76de2d5190fe34664d5175844fe2e5fb55dd38d4f3f0f79a607ec2f7d354ab3dd2f1cba0503e07b4c7cd8f79bcf76eb056dd5cba29d3557f3c62c3d195675121ade53eb9aba7e901fcdbc11af33010748713590d65e852388d3319be37cc2b94bf028cac5381fd7fa658fa0b6c48e3547512f6e1c402494b0ad1880a439375d2680ad73f10ff125e01f38d6c844f8dbfdad6353b85d7f222d635d781cd3e48c087d79fffd7ed720325d8825531ef735b1af771f416103e3c94eaad1d34c6fcca66b2e26d985b7902b9a24ff352732b4f6477c03fe752ffe0212ffc332f6f75c2db6f3121a6b2332e4a4c4cebbe561a3cc0027eba62be0fc4248742c82c860fdc5a394609800e9e0844326a33b333c0feb9527966cb5f2e7d70afb7f4276bc8f720da3296af3ca46d2a83a59a246232ce0c2500db9074fcb1010cad26c32fc18eb1d973cf522ccbad7a048ed2e8e12df27e29ec450e98cd480b108ce0ae1dc537af162eece35b7d010a0da91183968ccc2279e8a2e22871c1c6ea448075a389de901e384943623068921ba93c7d46d975099e3b96dc40df0aef0fa7bd25324df72f6373fdae77255b2b711875f98c702429f372781e231f319b3aa689393eac3d56df2565cc6b097ce866c7749e3c44139f9c963fb978db9591079087b642d68da637021f02337510d6174dee2efb893995a7401936adac52ca3574623cfb1782068ecf0682cf8587eb090dd16972e5ca46149728f0907de4f59cbd652f9f70fdcb52b81adf4adcc4245fa029d3e375b2e28c5
> encrypt_then_mac 0
> extended master secret 0
 # handshake
 > handshake type 0x02(2) (server_hello)
  > length 0x0004d7(1239)
# starting transcript_hash
 > cipher suite 0x1302 TLS_AES_256_GCM_SHA384
 > sha384
CLIENT_HANDSHAKE_TRAFFIC_SECRET 848966168f6d2421b7f2107ad342d89341b37ff00eb5bc22cb1f4d4df8993ee8 aae3878cff98ec40f1de576637bbdb4437cfb85145f029e32b7d5b2b883d0709e165ca13e6658f28eac9d2a2cfef00a8
SERVER_HANDSHAKE_TRAFFIC_SECRET 848966168f6d2421b7f2107ad342d89341b37ff00eb5bc22cb1f4d4df8993ee8 f7245cf21058e13d85a04c17bf35e1c86ddccdb83322eeb46b91960f07f46bfcb1673dd023d6aeb425a54ff66d61a56e
hook server_hello (server)
# record (server)
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x04db(1243)
# write record content type 0x14(20) (change_cipher_spec)
# record (server)
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
> change_cipher_spec server
# write record content type 0x17(23) (application_data)
# write 0x26bf2bcd5d0 handshake type 0x08(8) (encrypted_extensions)
 # handshake
 > handshake type 0x08(8) (encrypted_extensions)
  > length 0x000002(2)
hook  (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
# write record content type 0x17(23) (application_data)
# write 0x26bf2bcd5d0 handshake type 0x0b(11) (certificate)
 > certificate
 # handshake
 > handshake type 0x0b(11) (certificate)
  > length 0x000369(873)
hook server_certificate (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x037e(894)
# write record content type 0x17(23) (application_data)
# write 0x26bf2bcd5d0 handshake type 0x0f(15) (certificate_verify)
 # handshake
 > handshake type 0x0f(15) (certificate_verify)
  > length 0x000104(260)
hook server_certificate_verified (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0119(281)
# write record content type 0x17(23) (application_data)
# write 0x26bf2bcd5d0 handshake type 0x14(20) (finished)
> finished
  key   ab3fe23f08011f89dc6a0492172ae765671e08488058ad0df5ab10a5d8451b502e495e172a689db0c1b8d766d4991355
  hash  83d6ef8bd5577e038c2c58f0b5626cb1c13cc6df2ab574f097a017a566f7061ce078a9c8e70c935733403f18e400cccf
  maced d16d1c7ab80d63c4d7256208201c6ba422422bf2ec36bd02cbc8a3f0ac6bd615fd928796bb632a5ca72cec9a400747bc
> verify data
  > secret [0x0000020a] f7245cf21058e13d85a04c17bf35e1c86ddccdb83322eeb46b91960f07f46bfcb1673dd023d6aeb425a54ff66d61a56e (secret_s_hs_traffic)
  > algorithm sha384 size 48
  > verify data d16d1c7ab80d63c4d7256208201c6ba422422bf2ec36bd02cbc8a3f0ac6bd615fd928796bb632a5ca72cec9a400747bc
 # handshake
 > handshake type 0x14(20) (finished)
  > length 0x000030(48)
CLIENT_TRAFFIC_SECRET_0 848966168f6d2421b7f2107ad342d89341b37ff00eb5bc22cb1f4d4df8993ee8 4fa94e4fcbb223c71a11ecf6d3511fde012b02c7cebd5249479f5017b7d08017896f5e548126b69cb6f5f57dd188726d
SERVER_TRAFFIC_SECRET_0 848966168f6d2421b7f2107ad342d89341b37ff00eb5bc22cb1f4d4df8993ee8 7275b4832693b648612d7ebf4f574e7a6b499d221c648d39681f6f02cd5edba5b0d1f4a6e3bccc23d4d2454b0357c32c
EXPORTER_SECRET 848966168f6d2421b7f2107ad342d89341b37ff00eb5bc22cb1f4d4df8993ee8 1a7bd526c4573e0222acf13f878e9205ae3bc99f751e3513488f3fa291be2e0e9018356e08f9ae659f7065d02ddc64ae
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
  key   12449ed6f0ddcbe19fc56594cf361ce2c19209413fcf1df812c46821821bfe6f05be5a59799aa229d12448f4acedf2fe
  hash  45339d9fb42de7e9124b13a4bde45d9f5c23328891dce8815f82ced56e9c87c5f012460191f7b619c74bb8492cf64654
  maced d667abca5a0aa167b0868089f3b22dcd06e9babe08b8c8d782d8b0da0e803a88c84b6e6b6ffe78a315a47fa7dd2b2a71
 > verify data true
   > secret [0x00000207] aae3878cff98ec40f1de576637bbdb4437cfb85145f029e32b7d5b2b883d0709e165ca13e6658f28eac9d2a2cfef00a8 (secret_c_hs_traffic)
   > algorithm sha384 size 48
   > verify data d667abca5a0aa167b0868089f3b22dcd06e9babe08b8c8d782d8b0da0e803a88c84b6e6b6ffe78a315a47fa7dd2b2a71
   > maced       d667abca5a0aa167b0868089f3b22dcd06e9babe08b8c8d782d8b0da0e803a88c84b6e6b6ffe78a315a47fa7dd2b2a71
hook client_finished (server)
# record (client) [size 0x1c(28) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
    > application data
read 656 msg [test
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
disconnect 656
````

[TOC](README.md)
