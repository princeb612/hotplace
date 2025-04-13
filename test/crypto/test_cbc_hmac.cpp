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

    // const char* record_header = "16 03 03 00 40";
    // size_t record_size = 5;
    // const char* encryption_iv = "40 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f";
    // size_t ivsize = 16;
    const char* encdata =
        "22 7b c9 ba 81 ef 30 f2 a8 a7 8f f1 df 50 84 4d"
        "58 04 b7 ee b2 e2 14 c3 2b 68 92 ac a3 db 7b 78"
        "07 7f dd 90 06 7c 51 6b ac b3 ba 90 de df 72 0f";
    const char* content_aad = "00 00 00 00 00 00 00 00 16 03 03";  // 00 10
    const char* content = "14 00 00 0c cf 91 96 26 f1 36 0c 53 6a aa d7 3a -- -- --";

    binary_t ciphertext = std::move(base16_decode_rfc(encdata));
    binary_t key = std::move(base16_decode("f656d037b173ef3e11169f27231a84b6"));
    binary_t iv = std::move(base16_decode("404142434445464748494a4b4c4d4e4f"));
    binary_t mackey = std::move(base16_decode("1b7d117c7d5f690bc263cae8ef60af0f1878acc2"));
    binary_t aad = std::move(base16_decode_rfc(content_aad));
    binary_t plaintext = std::move(base16_decode_rfc(content));

    return_t ret = errorcode_t::success;
    openssl_crypt crypt;

    {
        _logger->hdump("> key", key, 16, 3);
        _logger->hdump("> iv", iv, 16, 3);
        _logger->hdump("> mackey", mackey, 16, 3);
        _logger->hdump("> aad", aad, 16, 3);
    }
    {
        binary_t out;
        size_t ptsize = 0;
        ret = crypt.cbc_hmac_mte_decrypt(aes128, sha1, key, mackey, iv, aad, ciphertext, out, ptsize);
        _test_case.test(ret, __FUNCTION__, "mac then encrypt");
        _logger->hdump("> ciphertext", ciphertext, 16, 3);
        _logger->hdump("> plaintag", out, 16, 3);
        binary_t pt(out.begin(), out.begin() + ptsize);
        _logger->writeln("> plaintext.size %zi", ptsize);
        _logger->hdump("> plaintext", pt, 16, 3);
        _test_case.assert(plaintext == pt, __FUNCTION__, "AES-128-CBC-SHA #decryption");
    }
    {
        binary_t out;
        crypt.cbc_hmac_mte_encrypt(aes128, sha1, key, mackey, iv, aad, plaintext, out);
        _logger->hdump("> plaintext", plaintext, 16, 3);
        _logger->hdump("> ciphertext", out, 16, 3);
        _test_case.assert(ciphertext == out, __FUNCTION__, "AES-128-CBC-SHA #mac-then-encrypt");
    }
}

void test_cbc_hmac_etm() {
#if 0
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
        "b2 08 4a 5b 1d d6 15 cd 05 6d 1f"
        "28 8f b8 e5 7b 7e eb d2 6f bb 00 18 32 c0 6c de"
        "4b 8f a4 77 10 43 71 e5 ba 2a 09 1b 70 3b bc 80"
        "69 bc 97 bc 2d";
    const char* enctag = "d0d236fa3089553b17e96ec6a46410c0002dab9e5ce6dfb4a8539c906348d9ab";
    const char* content_aad = "00000000000000001603030050";

    //  RFC 7366 Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
    //    3.  Applying Encrypt-then-MAC
    //    encrypt( data || MAC || pad )
    //    MAC(MAC_write_key, seq_num +
    //        TLSCipherText.type +
    //        TLSCipherText.version +
    //        TLSCipherText.length +
    //        IV +
    //        ENC(content + padding + padding_length));

    binary_t ciphertext = std::move(base16_decode_rfc(encdata));
    binary_t key = std::move(base16_decode("12edab3ca03602d1f8f97c4fbe97a414"));
    binary_t iv = std::move(base16_decode("c27bdd86b59b64171cb1f15bce8c6cc8"));
    binary_t mackey = std::move(base16_decode("05eaa1434e103c19701b389ed010afdd5753fc039fbc9a01da45361c642582cb"));
    binary_t aad = std::move(base16_decode(content_aad));
    binary_t tag = std::move(base16_decode(enctag));

    return_t ret = errorcode_t::success;
    openssl_crypt crypt;
    {
        _logger->hdump("> key", key, 16, 3);
        _logger->hdump("> iv", iv, 16, 3);
        _logger->hdump("> mackey", mackey, 16, 3);
        _logger->hdump("> aad", aad, 16, 3);
    }
    {
        binary_t ct;
        binary_t pt;
        size_t ptsize = 0;
        ret = crypt.cbc_hmac_etm_decrypt(aes128, sha2_256, key, mackey, iv, aad, ciphertext, pt, tag);
        _test_case.test(ret, __FUNCTION__, "encrypt then mac");
        // crypt.cbc_hmac_mte_encrypt(aes128, sha2_256, key, mackey, iv, aad, plaintext, ct, encrypt_then_mac);
        // _logger->hdump("> plaintext", plaintext, 16, 3);
        _logger->hdump("> ciphertext", ciphertext, 16, 3);
        // crypt.cbc_hmac_mte_decrypt(aes128, sha2_256, key, mackey, iv, aad, ct, pt, ptsize, encrypt_then_mac);
        _logger->hdump("> plaintext", pt, 16, 3);
        // _test_case.assert(plaintext == pt, __FUNCTION__, "AES-128-CBC-SHA #encrypt-then-mac");
    }
#endif
}
