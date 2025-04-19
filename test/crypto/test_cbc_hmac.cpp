/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

struct cbchmac_testvector_t {
    const char* desc;
    uint16 flag;
    hash_algorithm_t hashalg;
    const char* key;
    const char* iv;
    const char* mackey;
    const char* aad;
    const char* plaintext;
    const char* cbcmaced;
};

cbchmac_testvector_t testvector_mte[] = {
    {
        // https://tls12.xargs.org/#client-handshake-finished
        // # TLS Record
        //    00000000 : 16 03 03 00 40 40 41 42 43 44 45 46 47 48 49 4A | ....@@ABCDEFGHIJ
        //    00000010 : 4B 4C 4D 4E 4F 22 7B C9 BA 81 EF 30 F2 A8 A7 8F | KLMNO"{....0....
        //    00000020 : F1 DF 50 84 4D 58 04 B7 EE B2 E2 14 C3 2B 68 92 | ..P.MX.......+h.
        //    00000030 : AC A3 DB 7B 78 07 7F DD 90 06 7C 51 6B AC B3 BA | ...{x.....|Qk...
        //    00000040 : 90 DE DF 72 0F -- -- -- -- -- -- -- -- -- -- -- | ...r.
        "client finished",
        tls_mac_then_encrypt,
        sha1,
        "f656d037b173ef3e11169f27231a84b6",
        "404142434445464748494a4b4c4d4e4f",
        "1b7d117c7d5f690bc263cae8ef60af0f1878acc2",
        "0000000000000000160303",
        "1400000ccf919626f1360c536aaad73a",
        "227bc9ba81ef30f2a8a78ff1df50844d5804b7eeb2e214c32b6892aca3db7b78077fdd90067c516bacb3ba90dedf720f",
    },
};

void test_cbc_hmac(cbchmac_testvector_t* testvector, size_t size) {
    return_t ret = errorcode_t::success;
    crypto_cbc_hmac cbchmac;

    for (auto i = 0; i < size; i++) {
        const cbchmac_testvector_t* item = testvector + i;

        binary_t key = std::move(base16_decode(item->key));
        binary_t iv = std::move(base16_decode(item->iv));
        binary_t mackey = std::move(base16_decode(item->mackey));
        binary_t aad = std::move(base16_decode(item->aad));
        binary_t plaintext = std::move(base16_decode_rfc(item->plaintext));
        binary_t cbcmaced = std::move(base16_decode_rfc(item->cbcmaced));
        basic_stream desc;

        if (tls_mac_then_encrypt == item->flag) {
            desc = "mac_then_encrypt";
        } else if (tls_encrypt_then_mac == item->flag) {
            desc = "encrypt_then_mac";
        }
        desc.printf(R"(" %s")", item->desc);

        cbchmac.set_enc(aes128).set_mac(item->hashalg).set_flag(item->flag);

        _logger->writeln("> enckey %s", base16_encode(key).c_str());
        _logger->writeln("> iv     %s", base16_encode(iv).c_str());
        _logger->writeln("> mackey %s", base16_encode(mackey).c_str());
        _logger->writeln("> aad    %s", base16_encode(aad).c_str());

        binary_t pt;
        ret = cbchmac.decrypt(key, mackey, iv, aad, cbcmaced, pt);
        _test_case.test(ret, __FUNCTION__, "%s #decryption", desc.c_str());
        _logger->hdump("> cbcmaced", cbcmaced, 16, 2);
        _logger->writeln("  %s", base16_encode(cbcmaced).c_str());
        _logger->hdump("> plaintext", pt, 16, 2);
        _logger->writeln("  %s", base16_encode(pt).c_str());
        _test_case.assert(plaintext == pt, __FUNCTION__, "%s #decryption", desc.c_str());

        binary_t ct;
        ret = cbchmac.encrypt(key, mackey, iv, aad, plaintext, ct);
        _test_case.test(ret, __FUNCTION__, "%s #encryption", desc.c_str());
        _logger->hdump("> plaintext", plaintext, 16, 2);
        _logger->writeln("  %s", base16_encode(plaintext).c_str());
        _logger->hdump("> cbcmaced", ct, 16, 2);
        _logger->writeln("  %s", base16_encode(ct).c_str());
        ret = cbchmac.decrypt(key, mackey, iv, aad, ct, pt);
        _test_case.assert(plaintext == pt, __FUNCTION__, "%s #decryption", desc.c_str());
    }
}

void test_cbc_hmac_mte() {
    _test_case.begin("mac_then_encrypt");

    test_cbc_hmac(testvector_mte, RTL_NUMBER_OF(testvector_mte));
}

cbchmac_testvector_t testvector_etm[] = {
    {
        // test/tls/tls12/tls12etm.pcapng

        // # CLIENT_RANDOM 968988b10ed8d72be87faea564a0d815a462f141ca8019adc533aec989152bff
        // #               3a3847a4d20f9766ff81040b9db89f85f56b1b9526afc626c0138e5b89d62c74680af78ba4d827ee38989518845bc985

        // > secret_client_mac_key[00000102] 05eaa1434e103c19701b389ed010afdd5753fc039fbc9a01da45361c642582cb
        // > secret_client_key[00000108] 12edab3ca03602d1f8f97c4fbe97a414
        // > secret_client_iv[00000109] c27bdd86b59b64171cb1f15bce8c6cc8

        // ECDHE-RSA-AES128-SHA256

        // TLS 1.2 client finished
        // 16 03 03 00 50 b2 08 4a 5b 1d d6 15 cd 05 6d 1f
        // 28 8f b8 e5 7b 7e eb d2 6f bb 00 18 32 c0 6c de
        // 4b 8f a4 77 10 43 71 e5 ba 2a 09 1b 70 3b bc 80
        // 69 bc 97 bc 2d d0 d2 36 fa 30 89 55 3b 17 e9 6e
        // c6 a4 64 10 c0 00 2d ab 9e 5c e6 df b4 a8 53 9c
        // 90 63 48 d9 ab"

        "client finished",
        tls_encrypt_then_mac,
        sha2_256,
        "12edab3ca03602d1f8f97c4fbe97a414",
        "c27bdd86b59b64171cb1f15bce8c6cc8",
        "05eaa1434e103c19701b389ed010afdd5753fc039fbc9a01da45361c642582cb",
        "0000000000000000160303",
        "1400000c9bf2cb3b4a834cc4dfa8478f",
        "b2084a5b1dd615cd056d1f288fb8e57b7eebd26fbb001832c06cde4b8fa477104371e5ba2a091b703bbc8069bc97bc2d"
        "d0d236fa3089553b17e96ec6a46410c0002dab9e5ce6dfb4a8539c906348d9ab",
    },
    {
        // test/tls/tls12/tls12etm.pcapng
        "server finished",
        tls_encrypt_then_mac,
        sha2_256,
        "5e058192412a704bfe33f7dcb3ab736b",
        "71bc51c5e88ed247052cb5a13e15ac4c",
        "e4c1f413f96d2b21a34702c47a48628952fa1c9239ce15e902d53a265ebbeb83",
        "0000000000000000160303",
        "1400000ce9408ea8d4897cf1a4a5bbec",
        "aa69b78025eb0b3df40c35dc01a895fcd25366af6bb18346a7275f5c482d623980c2b38420c1eababbb2082a41c9e1e1"
        "29a5cec9a866ebf1f8efe4e56286bee28ab6c69342924f2b7691e79e40f43331",
    },
    {
        // test/tls/tls12/tls12etm.pcapng
        // client application data "hello"
        "hello",
        tls_encrypt_then_mac,
        sha2_256,
        "12edab3ca03602d1f8f97c4fbe97a414",
        "c27bdd86b59b64171cb1f15bce8c6cc8",
        "05eaa1434e103c19701b389ed010afdd5753fc039fbc9a01da45361c642582cb",
        "0000000000000001170303",
        "68656c6c6f0d0a",
        "94b362f11e8d445d51bb336bbd236575f87eb64f32e9fe2316a37f055f6f5466"
        "49a00559dfe39d94d8829f85e77649147348d7e39e02e3f620f8d7b29509c06a",
    },
    {
        // wireshark capture
        "client finished",
        tls_encrypt_then_mac,
        sha2_256,
        "05c85c3cb998c8701a05e26b326e3ebf",
        "d4127df6bf0b3b352dc473a28a23eba1",
        "d99e86a1556c859b35777daa55b18d297d10165c2befed04dc4d9f5c2fec7752",
        "0000000000000000160303",
        "1400000ccb805a3f49bec1a39d55c414",
        "3a11d2ef0be9027aea7c4ee6f74913a622280ca8e71e42e84cc5c613905e6f0d2ab5f2e5766b298c85a822e5799fe89c"
        "cec6a7c4d65738d97ad2adb1cbe4659a05db0b2c9c9d6b5768b8f38f289e3e68",
    },
    {
        // wireshark capture
        "client finished",
        tls_encrypt_then_mac,
        sha2_256,
        "08e314b2703fc111d6177b20e421a793",
        "6ebde512a771bd15394af9845ebbfcef",
        "4a800ddfde0001fdca4d3f03f5e60c3a419030fb22d0251b92aeed100aa7e133",
        "0000000000000000160303",
        "1400000ccb5643c8860e24c25a02c5ed",
        "e9647811b475b1b5d0bcadb55937d81326ee5aaa57d007987dd81517e9916758a9efdcbe190e96aa821104805f92ff64"
        "f0ba8d7b4b9f8165765bc4f556afb7fa50486b22fa377f686eae9d6d9d7cf8f2",
    },
};

void test_cbc_hmac_etm() {
    _test_case.begin("encrypt_then_mac");

    test_cbc_hmac(testvector_etm, RTL_NUMBER_OF(testvector_etm));
}
