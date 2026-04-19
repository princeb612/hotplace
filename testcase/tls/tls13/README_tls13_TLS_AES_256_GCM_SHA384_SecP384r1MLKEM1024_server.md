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
socket 488 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001d4 created
socket 532 created family 23(AF_INET6) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 00000220 created
- event_loop_new tid 000040f0
- event_loop_new tid 00004e48
- event_loop_new tid 00008604
- event_loop_new tid 00004ca4
iocp handle 00000220 bind 652
connect 652
# record (client) [size 0x739(1849) pos 0x0]
> record content type 0x16(22) (handshake)
 > record version 0x0301 (TLS v1.0)
 > len 0x0734(1844)
# read handshake type 0x01(1) (client_hello)
 > handshake type 0x01(1) (client_hello)
  > length 0x000730(1840)
  > version 0x0303 (TLS v1.2)
  > random
    a7731d19d7c400c193c55e68633ec3a87912106d6dc1cfd17706162a6f6540b0
  > session id 20(32)
    bb2538f8f71fc8c39379822e2ba6deeca89713c68c07fbd2fba6f12aaf5b7af0
  > cookie
  > cipher suite len 0006(3 ent.)
    [0] 0x1302 TLS_AES_256_GCM_SHA384
    [1] 0x1303 TLS_CHACHA20_POLY1305_SHA256
    [2] 0x1301 TLS_AES_128_GCM_SHA256
  > compression method len 1
    [0] 0x00 null
  > extension len 0x06e1(1761)
  > extension - 000a supported_groups
   > extension len 0x0004(4)
   > curves (1 ent.)
     [0] 0x11ed(4589) SecP384r1MLKEM1024
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
   > extension len 0x0687(1671)
+ add pub key CH.pub (group SecP384r1MLKEM1024)
   > len 1669(0x0685)
    > key share entry
     > group 0x11ed (SecP384r1MLKEM1024)
     > public key len 0681(1665)
       04035d2c7d4912cbe06e780f88357980fab5198384168948024644a73f4197bc17da7c23d9677724a15cfd41ac0c8bd747ac4d4d938e4b04de316618317083bae548a42a63c4d757e87da7e94ac152b60f0350ee8a91a634230877dba431837e06c441acee8912eddac9b3883a4025cd269127a4e09be7f5586ebb7474b95a0f094b5b626ef57846f4d687d8100dab94041038738de6485d040c758921f21572aae45c40dac49bfab69df83de718b87a5597ef1a48c4a49dbc772482c3878d6724dfb61b8c81baf79c5c095a6243340893a40f46aa159222440135b321e23051b572df1867219572f027154e0c6b1da0603af5a0cbfab89f64518f732e439905dcf953f1318a4725643521740879618003324c879288e550403a2e8580b135109fde73ce6eb81e0fa8c22b8b37bb878f901a1df100199b26acf981071bdcc5303c75edc404a1017ed4b8252c049d364c5ea5c087850b1e4546a91fb2b0647348729461e9883a39a3782169237fb609203272e2c57871645e5488b26883cf744658a6e076fdec0382241195e107d9b09410db14d4db2f8f22afad2a5cbac75d722700c3c02567238626237cbd7b61e488928c3a049655743c1c44f2acb38da3480b4b2122c21e932834222ab162052f2e238d44ab21f67715d615cb3f68a5ac85a4824785e78672103245e2d667501b8e5f66cb240c76a5183e7e2514bc2c138f35a9ba9981ee978fd19011a8b055bb675b670779320237d544148678722d390e939b6994e632fdd35dd419b921d458f5307180e9404aa42fcd917c1a27440f665231a7297a7445bfa06d6f28010e1a6a4396cb71eba55a509f37e063e4f96cc3b53a63c12de34cbf6cab676280be1b28276ba037ebec05c985a7eb634b7c482501181c31c512cb6c1b51dc4e1de57a9432743fa2a0c0cbabf7ccb231db8d9b775df9841af3e4ca722aaab9ca77deb4561063074b835a3c4a86d241c47440626618b1b9a39bb14c86973160bae16911c390e873bd8324b0a213a6c0c936cd16a685c556a63a3419f13d2188c4db74ce330a9187eab46f522bbc5217b67012d978c57851be1321628895008f2aca1ca3ba2678c38131071901b6eba32db865a71577278b431e4b286f375b87dfa848f2526c06f8a627c82e53e290a1f94e30676e6b96a3e2445b23a810ae7c0f5af648fd25666bebb48d6718ac687b2924c66a6a1b5696bc1fd6b220e637cbcb3de4869fa7f46972e9495820867ca4c6c087cd81014e00129680b631fda06657742c1d1519f94bca898c5d0bc3185c68acbeac14af4589cdc16ef82c71658886191c82b71b0f817289d2398dd74677783639fa6a493d34b3d9f7c5df7833eb7859b776ca0a8a6e6c39904ab3466a40af460078f87ba6c6f25b3e114b9179c302243eccdc0324784e83a2cd556c45b74623424137147a8580c7bc8ff06641c942dec2139d9c2ae460c9f9714663d52e9a5146051417626a84e471367a75576704781887a55b6c6910782252f52f100a85c5ebbaa708231cd6b8016818785b097922702c177940ca75d9eb97f515453d89486b9433c0bca745b34ddef4a77cf49324da9e60f5bdde7a4a6e8719d94385413b7771818169e07db9d52010a983191297e1d1535fa411a34ca11f392d6e542b51e21089c53c6715447fb03a38641c1da4b873c04f4bf2bbdbd8057214aff86878da91bba090b0f96b59da9696ca034ff2b53cbe628034e560b1fb8ae545b4ca437f8a7b7aec9a6b4ae476aef8af5352a3fd1248ba51bfcdaa8d57826d6b99b631a7b23c00bdc8314bf5948c8d4acdbf170e6ffb807603bce923420ba1a0db46cbda84ccd8bcc1bae144e3b468a42a7ad94598f040170f574b98a4af626518c4e196e2c09e68e2873e4a490ab19b2699c32621984d850e2739b1bd84c9e99b30b36365e770bcd6b9908d61cc68f94a08112088f894b53c21e8620f89d3ce4359549e3125af2712aa3c15b5d0132dbc9d21808803db4ee0b92257853fcbb159a7294118fb6569937056c19562e955bc9b387652c97ea878b7a22ca41012a631091d5214072b1cf6ea70c9b8556f5a25b675b52d544758bc2c39ebc66003c90b87af8fb674651a57c37557728072798641840a181341ce8dbbb598262a38677b1c27b93419135414cbe13123150759f394af245b86d0f369c437b106072359a2c928e172d3a70ed0e588a3a40c98b651b148b39cf731ff691394615231c58fed21067dc73f12a50aa1a619b9f97364a45829e73df4728ed1da0721882f0df0c41a80adeca806c8fcb660209520a473e1fa3981c671ec1f8bfed2ba541289e9abb331a5aa654b
  > extension - 001b compress_certificate
   > extension len 0x0003(3)
   > algorithm len 2 (1 ent.)
     [0] 0x0001 zlib
hook client_hello (server)
 ? # 0x1302 TLS_AES_256_GCM_SHA384
 ? # 0x1303 TLS_CHACHA20_POLY1305_SHA256
 ? # 0x1301 TLS_AES_128_GCM_SHA256
 ! # 0x1302 TLS_AES_256_GCM_SHA384
 - # 0x11ed SecP384r1MLKEM1024
+ add keypair SH.priv (group SecP384r1MLKEM1024)
# write record content type 0x16(22) (handshake)
# write 0x24f7f92d760 handshake type 0x02(2) (server_hello)
   > encaps
   > group SecP384r1MLKEM1024 04d0ecc1579c2fa2483c18726199680775b9792833652344d2edfe48f4de611e8dc76ee8edffc0e63b69d9661f9b3457418a00f8fbe969d2aa2bf8be9adf4c23a1fd957c5ce5aebd228751c1a5e0befdf4da996bcd1e2eaeaa163611033c55f8217638f70c8fd072995a70e065a9ab5e0e91e8add35c087aaabdf2da0dc0b44ebb2ef858c57cf95f9dd688d289d9a6b6b57c8dac690e4a78f6a727d872a03c6742512d15d7299276343c836639ac60c012d4cc8d43d1d964cdf8916b4e83927fe983ebf6c6a738b76d5fc89921b6419296c7f19a62d34a4df50bf3a92686a0b52eed761e6fbfa087deaac7ed6c7457f34edec898cf96e33f91fe252d35901e4faf8fbdb1cf9237af7a7783aba8973783a39ad8b92aa2d18b253696e676c2b2051868c711d4491c5b9526a790770fcb2dfcfc2f27e384cceafd741472a36fc6dcd7664d83e1219fd041b57282b157830d3bf4e4588228298c9f7636cf113ab25329d7822d42c779c66e363003c5678abb5b3fa93f2854a1a33acf5957725b3e0fc1e55065037954e96f35cac9f53c71d9859fd1494820094ba6ad8da4297fe63f86d3ad9979c1960287603082304893205ddd2f02d97e3281b0a8cba045aa90ad29b6cc017edf715cc25f46bfca32727fb89eea54c5c29176596d304360876311a557c7e84c2f4786b8f43cc2c0e11f087ee71b474c333f10ce35024f5c1d8d2462af5eaf42b471d7770bcf909beb27834f58c930361da68d2e69d7b61f1c8add578c94ca79aa54f3a4025a0da5176df5cce7803ebdae76983a18965f31a9dcf5fe2d6e4ce4c916991adf0de1691e1c8a294d490b91add2b3d15d499c97c5c89cf90875945a6472a2f6ea653ad95b30084637ae2bae54c80e7588c555bfd96d4d03ae3768a96c6121e3a4b67086a7c7c397567ed2525d9e441b1d45047e5268f534c921e4d132a38eb64c8d1d18948aac2ad158b12c49c57e20a6a488e8421cb76d4434074284b9b1edbb33c34f8e1197f3077314034dfec9e42753b99fc7eb5b4a08b58b40bd7727f6246d0ff9436dcb1042b0a4f9238c665a4f9e645ae4578c33704164af38ffd2f1fb69cf0d0dbefe7ac7206aa7fb4961cfc52fdb0d13007c2bafeff5ad4b87571dd5455d7c92e4489abed728008ef98c19b3835b559b89a14c03bc16da78b44269407cd376981a80198c7a7eab8cbfcde45123fff0ccc166196f6b556ea731a52601b90dabfc83bb1368c826696df4874566059c13d0d0ad91c6c20cf9d2833d11379b4712812b10abaaa210cf80742af6e4f110d234a6c5137049ad6681f1a80ed7792929da127cff6034a06489e6221abfea9cc6fc1b7c8628154e2a9d3e46d9b379e0006d05935d07bcc449241061c79e60665b74228ffeccf793e2c32597f0010b5f6d53344dfc0f5a0cc320ed9ec775f0187972d7d05bb123457efaafcaa4681339b080149d81a54ad3abe1732cefdfea04252c05880ad6d1c5e434d2a1b7f2a1c51b49d3896849e16660ad5f87242fe997fc4d00c48682e50aa51a47b318b252045a3e1598e30a3d584127c1e1605fcd2e8164819390bfe91072b75aa0d2af587191fcbfac05ced236b183dc792993b796ed43ae85d62eebdfda67785cd7198d9fbd0856be45d5ae46e8d0b4ecafa9e2fac6ef5abee184343999c1556f82c6d12f96c134f8c64184d580cf99329fded9d6bd8e39721c1a8821da38fb41ec6ba09d2027d24355384d105c02a03df41dfb3e7629ee2137d2274f2b7ff88f2a0cfea04e0cff3324843d60566e8bae63f3dcb1a22cc95e892d575170552232cc50a9d4cd55870bc10ce57db0de9a9f105a0abfd76598dfab9f919473bba71e8fbd0166fd16b348100529d26b93987d164df3231a0d787a88a483741e71c526666661097077c1a77c4494e8febd2281e02be3ea1d8829092750300ccb3963ec71e8ca977e4b43192ed608e6a2529f974876828e75d4cdffc69a1951e65fa5d6b7fc7775aedb498cead6122dc118efeb5fb452121e47e5ee9448f026e756a58a4d99d32e3f749eb5709853264b00bb3972cbe14dcb693497ce7e11947573c05ac8065a4dc12c0a2b48cecba6f7fde74ee0193a4defc1927d5a467c90d306048426a95d7cc92fbcfc1827e145af8ed5be457bb8c0c145a2c46b85ca01245b366621701395720e7b4d55966abb4c760bfd49250e0cecab1310178d29c20ebee8130da233d3449956eb11c3f83d8184e7a5a0300d1a7635a99c5c5537637c81a87e92a032004c1a09ce53c45ca072f85201cdc0388f4d5cd32acaf0ab9cc216bf3a17bb01534843e16b4a3078c9fbdd09facd13f9e1be44755c34
> encrypt_then_mac 0
> extended master secret 0
 # handshake
 > handshake type 0x02(2) (server_hello)
  > length 0x0006d7(1751)
# starting transcript_hash
 > cipher suite 0x1302 TLS_AES_256_GCM_SHA384
 > sha384
CLIENT_HANDSHAKE_TRAFFIC_SECRET a7731d19d7c400c193c55e68633ec3a87912106d6dc1cfd17706162a6f6540b0 e411ce56a16bdea08ee7f8c4e12b2ed8d77ac9ce0a5103d8e37edc18fc0205315803f7206fd2fee17ec296ab0275f081
SERVER_HANDSHAKE_TRAFFIC_SECRET a7731d19d7c400c193c55e68633ec3a87912106d6dc1cfd17706162a6f6540b0 8e23ac75b1d2d92bb4ab008f27d86706f6e06275669f37a02a0b5cfd3c3e1e96a73d21c6bff043b83f9c3bcfdaaf8b20
hook server_hello (server)
# record (server)
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x06db(1755)
# write record content type 0x14(20) (change_cipher_spec)
# record (server)
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
> change_cipher_spec server
# write record content type 0x17(23) (application_data)
# write 0x24f7f92d760 handshake type 0x08(8) (encrypted_extensions)
 # handshake
 > handshake type 0x08(8) (encrypted_extensions)
  > length 0x000002(2)
hook  (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
# write record content type 0x17(23) (application_data)
# write 0x24f7f92d760 handshake type 0x0b(11) (certificate)
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
# write 0x24f7f92d760 handshake type 0x0f(15) (certificate_verify)
 # handshake
 > handshake type 0x0f(15) (certificate_verify)
  > length 0x000104(260)
hook server_certificate_verified (server)
# record (server)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0119(281)
# write record content type 0x17(23) (application_data)
# write 0x24f7f92d760 handshake type 0x14(20) (finished)
> finished
  key   4ba1277661d4578574b77893f5988b0215f53a096581c7ee685857588e8c16309764f56896dd388d574aac95c9abdef1
  hash  6db5307c314a4734c31af5f28d554cba793f3e19fc42e78452ec7d94169a367c611cd6efcc657aeb4771909add7af75b
  maced 50ac1d7cf27c8e3b8e8e8e6c6b640f370b08b5b8014518d682dd7dc369b16718a3446be3dcab0eeeefb6b8f4afc62ff7
> verify data
  > secret [0x0000020a] 8e23ac75b1d2d92bb4ab008f27d86706f6e06275669f37a02a0b5cfd3c3e1e96a73d21c6bff043b83f9c3bcfdaaf8b20 (secret_s_hs_traffic)
  > algorithm sha384 size 48
  > verify data 50ac1d7cf27c8e3b8e8e8e6c6b640f370b08b5b8014518d682dd7dc369b16718a3446be3dcab0eeeefb6b8f4afc62ff7
 # handshake
 > handshake type 0x14(20) (finished)
  > length 0x000030(48)
CLIENT_TRAFFIC_SECRET_0 a7731d19d7c400c193c55e68633ec3a87912106d6dc1cfd17706162a6f6540b0 118a2cea635a3c5086025151afbc847736e907dd7683674d53e99689c75740ae2117b8c6d1c364ba3c79ad3cbbb06c3a
SERVER_TRAFFIC_SECRET_0 a7731d19d7c400c193c55e68633ec3a87912106d6dc1cfd17706162a6f6540b0 95f590a861bea598f5053da818c531e23c061ee829a1528f6ef14097c36e9bbee690ca63baa7cae95a4a2e09697320c4
EXPORTER_SECRET a7731d19d7c400c193c55e68633ec3a87912106d6dc1cfd17706162a6f6540b0 59f909fec10c5a6d447a306422a8c4f05ee65335ba567214db422650c9018b8042d1c24d6906630dd83db00e344b5e92
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
  key   6d538063ba50c878585989c0668119ad058319f90c15e06f9f16e102092709b336b2c4e4e4eaa2d47ae60d353b08e207
  hash  4172788b338c81d8d9526afc8ace598960a9ba00ea9ef6e1b7f3f88c3d35456c56198b61c8d78182e0141573d48e85c7
  maced dce01d55c5530069e37a12a5efbd136e921860afd041de63bc3cdc88a75542505796120ea5a12063171d6c3eb2d79803
 > verify data true
   > secret [0x00000207] e411ce56a16bdea08ee7f8c4e12b2ed8d77ac9ce0a5103d8e37edc18fc0205315803f7206fd2fee17ec296ab0275f081 (secret_c_hs_traffic)
   > algorithm sha384 size 48
   > verify data dce01d55c5530069e37a12a5efbd136e921860afd041de63bc3cdc88a75542505796120ea5a12063171d6c3eb2d79803
   > maced       dce01d55c5530069e37a12a5efbd136e921860afd041de63bc3cdc88a75542505796120ea5a12063171d6c3eb2d79803
hook client_finished (server)
# record (client) [size 0x1c(28) pos 0x0]
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0017(23)
    > application data
read 652 msg [test
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
disconnect 652
````

[TOC](README.md)
