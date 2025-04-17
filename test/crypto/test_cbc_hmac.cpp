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

void test_cbc_hmac_mte() {
    _test_case.begin("mac_then_encrypt");

    // https://tls12.xargs.org/#client-handshake-finished
    // # TLS Record
    //    00000000 : 16 03 03 00 40 40 41 42 43 44 45 46 47 48 49 4A | ....@@ABCDEFGHIJ
    //    00000010 : 4B 4C 4D 4E 4F 22 7B C9 BA 81 EF 30 F2 A8 A7 8F | KLMNO"{....0....
    //    00000020 : F1 DF 50 84 4D 58 04 B7 EE B2 E2 14 C3 2B 68 92 | ..P.MX.......+h.
    //    00000030 : AC A3 DB 7B 78 07 7F DD 90 06 7C 51 6B AC B3 BA | ...{x.....|Qk...
    //    00000040 : 90 DE DF 72 0F -- -- -- -- -- -- -- -- -- -- -- | ...r.

    const char* encdata =
        "22 7b c9 ba 81 ef 30 f2 a8 a7 8f f1 df 50 84 4d"
        "58 04 b7 ee b2 e2 14 c3 2b 68 92 ac a3 db 7b 78"
        "07 7f dd 90 06 7c 51 6b ac b3 ba 90 de df 72 0f";
    const char* content = "14 00 00 0c cf 91 96 26 f1 36 0c 53 6a aa d7 3a -- -- --";

    binary_t ciphertext = std::move(base16_decode_rfc(encdata));
    binary_t key = std::move(base16_decode("f656d037b173ef3e11169f27231a84b6"));
    binary_t iv = std::move(base16_decode("404142434445464748494a4b4c4d4e4f"));
    binary_t mackey = std::move(base16_decode("1b7d117c7d5f690bc263cae8ef60af0f1878acc2"));
    binary_t aad;
    binary_t plaintext;

    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    crypto_cbc_hmac cbchmac;

    {
        binary_append(aad, uint64(0), hton64);
        binary_append(aad, uint8(0x16));
        binary_append(aad, uint16(0x0303), hton16);

        plaintext = std::move(base16_decode_rfc(content));
    }

    {
        cbchmac.set_enc(aes128).set_mac(sha1).set_flag(tls_mac_then_encrypt);
        _logger->hdump("> key", key, 16, 3);
        _logger->hdump("> iv", iv, 16, 3);
        _logger->hdump("> mackey", mackey, 16, 3);
        _logger->hdump("> aad", aad, 16, 3);
    }
    {
        binary_t pt;
        ret = cbchmac.decrypt(key, mackey, iv, aad, ciphertext, pt);
        _test_case.test(ret, __FUNCTION__, "mac then encrypt");
        _logger->hdump("> ciphertext", ciphertext, 16, 3);
        _logger->hdump("> plaintext", pt, 16, 3);
        _test_case.assert(plaintext == pt, __FUNCTION__, "AES-128-CBC-SHA #decryption");
    }
    {
        binary_t ct;
        ret = cbchmac.encrypt(key, mackey, iv, aad, plaintext, ct);
        _test_case.test(ret, __FUNCTION__, "mac then encrypt");
        _logger->hdump("> plaintext", plaintext, 16, 3);
        _logger->hdump("> ciphertext", ct, 16, 3);
        _test_case.assert(ciphertext == ct, __FUNCTION__, "AES-128-CBC-SHA #mac-then-encrypt");
    }
}

void test_cbc_hmac_etm() {
    _test_case.begin("encrypt_then_mac");

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

    const char* encdata =
        "b2 08 4a 5b 1d d6 15 cd 05 6d 1f 28 8f b8 e5 7b"
        "7e eb d2 6f bb 00 18 32 c0 6c de 4b 8f a4 77 10"
        "43 71 e5 ba 2a 09 1b 70 3b bc 80 69 bc 97 bc 2d"  // b2..2d ciphertext
        "d0 d2 36 fa 30 89 55 3b 17 e9 6e c6 a4 64 10 c0"
        "00 2d ab 9e 5c e6 df b4 a8 53 9c 90 63 48 d9 ab";       // d0..ab tag
    const char* content_aad = "0000000000000000 160303";         // sequence || type || version
    const char* block16 = "cace85bac5cfeea0bb0ae507869d2e4c";    // ?
    const char* plaindata = "1400000c9bf2cb3b4a834cc4dfa8478f";  // wo pad

    binary_t ciphertext = std::move(base16_decode_rfc(encdata));
    binary_t key = std::move(base16_decode("12edab3ca03602d1f8f97c4fbe97a414"));
    binary_t iv = std::move(base16_decode("c27bdd86b59b64171cb1f15bce8c6cc8"));
    binary_t mackey = std::move(base16_decode("05eaa1434e103c19701b389ed010afdd5753fc039fbc9a01da45361c642582cb"));
    binary_t aad = std::move(base16_decode_rfc(content_aad));
    binary_t plaintext = std::move(base16_decode_rfc(plaindata));

    return_t ret = errorcode_t::success;
    {
        _logger->writeln("> key       %s", base16_encode(key).c_str());
        _logger->writeln("> iv        %s", base16_encode(iv).c_str());
        _logger->writeln("> mackey    %s", base16_encode(mackey).c_str());
        _logger->writeln("> aad       %s", base16_encode(aad).c_str());
        _logger->writeln("> plaintext %s", base16_encode(plaintext).c_str());
    }

    crypto_cbc_hmac cbchmac;
    cbchmac.set_enc(aes128).set_mac(sha2_256).set_flag(tls_encrypt_then_mac);
    binary_t pt;
    binary_t ct;
    {
        ret = cbchmac.decrypt(key, mackey, iv, aad, ciphertext, pt);
        _logger->writeln("> pt        %s", base16_encode(pt).c_str());
        _test_case.assert(pt == plaintext, __FUNCTION__, "encrypt_then_mac #decryption");
    }
    {
        ret = cbchmac.encrypt(key, mackey, iv, aad, pt, ct);
        _test_case.test(ret, __FUNCTION__, "encrypt_then_mac #encryption");
        ret = cbchmac.decrypt(key, mackey, iv, aad, ct, pt);
        _test_case.test(ret, __FUNCTION__, "encrypt_then_mac #decryption");
        _logger->writeln("> ct        %s", base16_encode(ct).c_str());
        _logger->writeln("> pt        %s", base16_encode(pt).c_str());
        _test_case.assert(pt == plaintext, __FUNCTION__, "encrypt_then_mac #encryption");
    }

    {
        binary_t cbcblock;
        cipher_encrypt_builder builder;
        auto cipher = builder.set(aes128, cbc).build();
        if (cipher) {
            cipher->encrypt(key, iv, &plaintext[0], 16, cbcblock);
            cipher->release();
        }
        _logger->writeln("> cbcblock  %s", base16_encode(cbcblock).c_str());
    }
}
