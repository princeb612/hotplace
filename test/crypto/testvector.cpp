#include "sample.hpp"

// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip

const test_vector_nist_cavp_blockcipher_t test_vector_nist_cavp_blockcipher[] = {
    {
        "CBCGFSbox128.rsp, count = 0",
        "aes-128-cbc",
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "CBCGFSbox192.rsp, count = 0",
        "aes-192-cbc",
        "000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "CBCGFSbox256.rsp, count = 0",
        "aes-256-cbc",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },

    {
        "CFB128GFSbox128.rsp, count = 0",
        "aes-128-cfb",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00000000000000000000000000000000",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "CFB128GFSbox192.rsp, count = 0",
        "aes-192-cfb",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00000000000000000000000000000000",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "CFB128GFSbox256.rsp, count = 0",
        "aes-256-cfb",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00000000000000000000000000000000",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },

#if 0
    {
        "CFB1GFSbox128.rsp, count = 0",
        "aes-128-cfb1",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00",
        "00",
    },
    {
        "CFB1GFSbox192.rsp, count = 0",
        "aes-192-cfb1",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00",
        "00",
    },
    {
        "CFB1GFSbox256.rsp, count = 0",
        "aes-256-cfb1",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00",
        "00",
    },
#endif

    {
        "CFB8GFSbox128.rsp, count = 0",
        "aes-128-cfb8",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00",
        "03",
    },
    {
        "CFB8GFSbox192.rsp, count = 0",
        "aes-192-cfb8",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00",
        "27",
    },
    {
        "CFB8GFSbox256.rsp, count = 0",
        "aes-256-cfb8",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00",
        "5c",
    },

    {
        "ECBGFSbox128.rsp, count = 0",
        "aes-128-ecb",
        "00000000000000000000000000000000",
        "",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "ECBGFSbox192.rsp, count = 0",
        "aes-192-ecb",
        "000000000000000000000000000000000000000000000000",
        "",
        "1b077a6af4b7f98229de786d7516b639",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "ECBGFSbox256.rsp, count = 0",
        "aes-256-ecb",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "",
        "014730f80ac625fe84f026c60bfd547d",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },

    {
        "OFBGFSbox128.rsp, count = 0",
        "aes-128-ofb",
        "00000000000000000000000000000000",
        "f34481ec3cc627bacd5dc3fb08f273e6",
        "00000000000000000000000000000000",
        "0336763e966d92595a567cc9ce537f5e",
    },
    {
        "OFBGFSbox192.rsp, count = 0",
        "aes-192-ofb",
        "000000000000000000000000000000000000000000000000",
        "1b077a6af4b7f98229de786d7516b639",
        "00000000000000000000000000000000",
        "275cfc0413d8ccb70513c3859b1d0f72",
    },
    {
        "OFBGFSbox256.rsp, count = 0",
        "aes-256-ofb",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "014730f80ac625fe84f026c60bfd547d",
        "00000000000000000000000000000000",
        "5c9d844ed46f9885085e5d6a4f94c7d7",
    },
};

const size_t sizeof_test_vector_nist_cavp_blockcipher = RTL_NUMBER_OF(test_vector_nist_cavp_blockcipher);

const test_vector_rfc3394_t test_vector_rfc3394[] = {
    {// RFC 3394 4.1 Wrap 128 bits of Key Data with a 128-bit KEK
     // KEK 000102030405060708090A0B0C0D0E0F
     // Key Data 00112233445566778899AABBCCDDEEFF
     // Ciphertext:  1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5
     crypt_algorithm_t::aes128, "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
     "RFC 3394 4.1 Wrap 128 bits of Key Data with a 128-bit KEK"},
    {// RFC 3394 4.2 Wrap 128 bits of Key Data with a 192-bit KEK
     // KEK 000102030405060708090A0B0C0D0E0F1011121314151617
     // Key Data 00112233445566778899AABBCCDDEEFF
     // Ciphertext: 96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D
     crypt_algorithm_t::aes192, "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
     "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D", "RFC 3394 4.2 Wrap 128 bits of Key Data with a 192-bit KEK"},
    {// RFC 3394 4.3 Wrap 128 bits of Key Data with a 256-bit KEK
     // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
     // Key Data 00112233445566778899AABBCCDDEEFF
     // Ciphertext: 64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7
     crypt_algorithm_t::aes256, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
     "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7", "RFC 3394 4.3 Wrap 128 bits of Key Data with a 256-bit KEK"},
    {// RFC 3394 4.4 Wrap 192 bits of Key Data with a 192-bit KEK
     // KEK 000102030405060708090A0B0C0D0E0F1011121314151617
     // Key Data 00112233445566778899AABBCCDDEEFF0001020304050607
     // Ciphertext: 031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2
     crypt_algorithm_t::aes192, "000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
     "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2", "RFC 3394 4.4 Wrap 192 bits of Key Data with a 192-bit KEK"},
    {// RFC 3394 4.5 Wrap 192 bits of Key Data with a 256-bit KEK
     // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
     // Key Data 00112233445566778899AABBCCDDEEFF0001020304050607
     // Ciphertext: A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1
     crypt_algorithm_t::aes256, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607",
     "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1", "RFC 3394 4.5 Wrap 192 bits of Key Data with a 256-bit KEK"},
    {// RFC 3394 4.6 Wrap 256 bits of Key Data with a 256-bit KEK
     // KEK 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
     // Key Data 00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F
     // Ciphertext: 28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
     crypt_algorithm_t::aes256, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
     "RFC 3394 4.6 Wrap 256 bits of Key Data with a 256-bit KEK"}};

const size_t sizeof_test_vector_rfc3394 = RTL_NUMBER_OF(test_vector_rfc3394);

// https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
const test_vector_aead_aes_cbc_hmac_sha2_t test_vector_aead_aes_cbc_hmac_sha2[] = {
    {
        "5.1.  AEAD_AES_128_CBC_HMAC_SHA256",
        "aes-128-cbc",
        "sha256",
        /* k */ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        /* A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience */
        "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f"
        "2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
        /* iv */ "1af38c2dc2b96ffdd86694092341bc04",
        /* a */ "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        /* q */
        "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf829"
        "35ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db",
        /* s */
        "1af38c2dc2b96ffdd86694092341bc04c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489"
        "f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b88"
        "51ffb598f7f80074b9473c82e2db",
        /* t */ "652c3fa36b0a7c5b3219fab3a30bc1c4",
        /* c */
        "1af38c2dc2b96ffdd86694092341bc04c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489"
        "f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b88"
        "51ffb598f7f80074b9473c82e2db652c3fa36b0a7c5b3219fab3a30bc1c4",
    },
    {
        "5.2.  AEAD_AES_192_CBC_HMAC_SHA384",
        "aes-192-cbc",
        "sha384",
        /* k */ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        /* p */
        "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066"
        "616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
        /* iv */ "1af38c2dc2b96ffdd86694092341bc04",
        /* a */ "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        /* q */
        "ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b226d1746214bf8cfc2400add9f5126e4"
        "79663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0c4e79c7b11efc60054e3",
        /* s */
        "1af38c2dc2b96ffdd86694092341bc04ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b"
        "226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0"
        "c4e79c7b11efc60054e3",
        /* t */ "8490ac0e58949bfe51875d733f93ac2075168039ccc733d7",
        /* c */
        "1af38c2dc2b96ffdd86694092341bc04ea65da6b59e61edb419be62d19712ae5d303eeb50052d0dfd6697f77224c8edb000d279bdc14c1072654bd30944230c657bed4ca0c9f4a8466f22b"
        "226d1746214bf8cfc2400add9f5126e479663fc90b3bed787a2f0ffcbf3904be2a641d5c2105bfe591bae23b1d7449e532eef60a9ac8bb6c6b01d35d49787bcd57ef484927f280adc91ac0"
        "c4e79c7b11efc60054e38490ac0e58949bfe51875d733f93ac2075168039ccc733d7",
    },
    {
        "5.3.  AEAD_AES_256_CBC_HMAC_SHA384",
        "aes-256-cbc",
        "sha384",
        /* k */ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        /* p */
        "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066"
        "616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
        /* iv */ "1af38c2dc2b96ffdd86694092341bc04",
        /* a */ "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        /* q */
        "893129b0f4ee9eb18d75eda6f2aaa9f3607c98c4ba0444d34162170d8961884e58f27d4a35a5e3e3234aa99404f327f5c2d78e986e5749858b88bcddc2ba05218f195112d6ad48fa3b1e89"
        "aa7f20d596682f10b3648d3bb0c983c3185f59e36d28f647c1c13988de8ea0d821198c150977e28ca768080bc78c35faed69d8c0b7d9f506232198a489a1a6ae03a319fb30",
        /* s */
        "1af38c2dc2b96ffdd86694092341bc04893129b0f4ee9eb18d75eda6f2aaa9f3607c98c4ba0444d34162170d8961884e58f27d4a35a5e3e3234aa99404f327f5c2d78e986e5749858b88bc"
        "ddc2ba05218f195112d6ad48fa3b1e89aa7f20d596682f10b3648d3bb0c983c3185f59e36d28f647c1c13988de8ea0d821198c150977e28ca768080bc78c35faed69d8c0b7d9f506232198"
        "a489a1a6ae03a319fb30",
        /* t */ "dd131d05ab3467dd056f8e882bad70637f1e9a541d9c23e7",
        /* c */
        "1af38c2dc2b96ffdd86694092341bc04893129b0f4ee9eb18d75eda6f2aaa9f3607c98c4ba0444d34162170d8961884e58f27d4a35a5e3e3234aa99404f327f5c2d78e986e5749858b88bc"
        "ddc2ba05218f195112d6ad48fa3b1e89aa7f20d596682f10b3648d3bb0c983c3185f59e36d28f647c1c13988de8ea0d821198c150977e28ca768080bc78c35faed69d8c0b7d9f506232198"
        "a489a1a6ae03a319fb30dd131d05ab3467dd056f8e882bad70637f1e9a541d9c23e7",
    },
    {
        "5.4.  AEAD_AES_256_CBC_HMAC_SHA512",
        "aes-256-cbc",
        "sha512",
        /* k */ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        /* p */
        "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066"
        "616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
        /* iv */ "1af38c2dc2b96ffdd86694092341bc04",
        /* a */ "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        /* q */
        "4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea7"
        "5c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6",
        /* s */
        "1af38c2dc2b96ffdd86694092341bc044affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df"
        "829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7"
        "a4930930806d0703b1f6",
        /* t */ "4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5",
        /* c */
        "1af38c2dc2b96ffdd86694092341bc044affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df"
        "829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7"
        "a4930930806d0703b1f64dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5",
    },
};

const size_t sizeof_test_vector_aead_aes_cbc_hmac_sha2 = RTL_NUMBER_OF(test_vector_aead_aes_cbc_hmac_sha2);
