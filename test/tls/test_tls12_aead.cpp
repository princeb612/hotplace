/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void test_tls12_aead_aes128gcm() {
    _test_case.begin("TLS 1.2 AEAD-AES-128-GCM");

    // see also
    //   test_tls12_aead
    //   pcap_tls12_aes128gcm_sha256

    // tls12_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.pcapng
    // client finished

    // # record (client) [size 0x5d pos 0x30]
    //    00000000 : 16 03 03 00 28 F1 B1 D2 E2 78 B9 F2 34 5D D1 73 | ....(....x..4].s
    //    00000010 : BB F2 F3 7C EF 1F 1E 54 C5 AF BB 79 B6 B0 E2 F8 | ...|...T...y....
    //    00000020 : 03 E9 98 40 94 3C 28 51 8B 1D B1 8F A8 -- -- -- | ...@.<(Q.....
    // > record content type 0x16(22) (handshake)
    //  > record version 0x0303 (TLS v1.2)
    //  > len 0x0028(40)
    // > ciphertext
    //    00000000 : 5D D1 73 BB F2 F3 7C EF 1F 1E 54 C5 AF BB 79 B6 | ].s...|...T...y.
    // > plaintext
    //    00000000 : 14 00 00 0C FF 74 86 F7 D9 A3 13 84 A3 8C F5 62 | .....t.........b

    return_t ret = errorcode_t::success;
    tls_session session;
    uint16 cs = 0xc02b;  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    auto dir = from_client;

    auto& protection = session.get_tls_protection();
    protection.set_cipher_suite(cs);
    protection.set_tls_version(tls_12);

    {
        binary_t client_hello_random = std::move(base16_decode("8d4e72acf55111544eadc50e5e9e0c3015648025881194328bce1573dec89ed6"));
        binary_t server_hello_random = std::move(base16_decode("074a0cb6fe8a12a0470fc32988f98eefee81e3d6a6099ddf444f574e47524401"));
        binary_t secret_master = std::move(base16_decode("20c27d23fd3f64170b2b63917ccfe7251b792ea9492fa52b59c6adccc71095102e72ad1b08880a78f3f8316c1234a89b"));

        ret = protection.calc_keyblock(sha2_256, secret_master, client_hello_random, server_hello_random, cs);

        // > secret_client_key[00000108] 844cba68a2aada5c04524664ad93b1e7
        // > secret_server_key[0000010b] dd6dfdfdee502df4402f56bc5d7b42c5
        // > secret_client_iv[00000109] 1bdcb38a
        // > secret_server_iv[0000010c] dc3e240a

        auto lambda_test_secret = [&](tls_secret_t secret, const char* value) -> return_t {
            const binary_t& bin_secret = protection.get_secrets().get(secret);
            binary_t bin_value = std::move(base16_decode(value));
            return (bin_secret == bin_value) ? success : mismatch;
        };

        ret = lambda_test_secret(tls_secret_client_key, "844cba68a2aada5c04524664ad93b1e7");
        _test_case.test(ret, __FUNCTION__, "secret_client_key");
        ret = lambda_test_secret(tls_secret_client_iv, "1bdcb38a");
        _test_case.test(ret, __FUNCTION__, "secret_client_iv");
    }

    {
        // aad 0000000000000000 || 1603030028
        // tag b0e2f803e99840943c28518b1db18fa8
        // nonce 1bdcb38a || f1b1d2e278b9f234

        binary_t ciphertext = std::move(base16_decode("1603030028f1b1d2e278b9f2345dd173bbf2f37cef1f1e54c5afbb79b6b0e2f803e99840943c28518b1db18fa8"));
        binary_t plaintext;

        ret = protection.decrypt(&session, dir, &ciphertext[0], ciphertext.size(), 0, plaintext);

        _test_case.test(ret, __FUNCTION__, "decrypt");
    }
}

void test_tls12_aead_chacha20poly1305() {
    _test_case.begin("TLS 1.2 chacha20-poly1305");

    // tls12_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.pcapng
    // see also test_pcap_tls12()

    return_t ret = errorcode_t::success;
    tls_session session;
    uint16 cs = 0xcca9;  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

    auto& protection = session.get_tls_protection();
    protection.set_cipher_suite(cs);
    protection.set_tls_version(tls_12);

    {
        binary_t client_hello_random = std::move(base16_decode("19587698676b7fe86d78564051c0c44d0d8123939567dafbc01bbf8f78b323c0"));
        binary_t server_hello_random = std::move(base16_decode("55fb6e5dbe1f6ec97a7e30a6d228abc670793ad3f6e5bba6444f574e47524401"));
        binary_t secret_master = std::move(base16_decode("6525943d87978a14a4553a956b6f71501d0cbfd97aa856ce69b9aca4a7b5c1209d663b389778393170e9e4c068e51843"));

        ret = protection.calc_keyblock(sha2_256, secret_master, client_hello_random, server_hello_random, cs);

        auto lambda_test_secret = [&](tls_secret_t secret, const char* value) -> return_t {
            const binary_t& bin_secret = protection.get_secrets().get(secret);
            binary_t bin_value = std::move(base16_decode(value));
            return (bin_secret == bin_value) ? success : mismatch;
        };

        ret = lambda_test_secret(tls_secret_client_key, "4b403a5ecddb11ca66b808b90086a530ca1b0137a37db67b432dbf83e335f28a");
        _test_case.test(ret, __FUNCTION__, "secret_client_key");
        ret = lambda_test_secret(tls_secret_client_iv, "6918cfa52543e1f89455ca42");
        _test_case.test(ret, __FUNCTION__, "secret_client_iv");
    }

    // decrypt finished messages

    // #8 encrypted handshake message
    // 0000   16 03 03 00 20 be f5 78 ab c8 59 33 50 3c cf 80
    // 0010   07 91 fe 3c 78 e2 af 2c 60 e7 f4 4b c7 ea 33 21
    // 0020   c5 9d f9 02 36

    // content type (uint8) || version (uint16) || len[ciphertext + mac] (uint16) || ciphertext || mac (16)

    {
        binary_t ciphertext = std::move(base16_decode("1603030020bef578abc85933503ccf800791fe3c78e2af2c60e7f44bc7ea3321c59df90236"));
        binary_t plaintext;

        ret = protection.decrypt(&session, from_client, &ciphertext[0], ciphertext.size(), 0, plaintext);

        constexpr char expect[] = "1400000c06d57e2441096bd4dd68343f";
        _test_case.assert(base16_decode_rfc(expect) == plaintext, __FUNCTION__, "client_finished");
    }

    // #10 encrypted handshake message
    // 0000   16 03 03 00 20 fc 96 42 59 c2 1b ce 2a 85 75 b5
    // 0010   a8 ce a0 c5 71 ec 99 dd 73 47 b4 15 2a 1c 2e f7
    // 0020   c3 7d 34 5e 64

    {
        binary_t ciphertext = std::move(base16_decode("1603030020fc964259c21bce2a8575b5a8cea0c571ec99dd7347b4152a1c2ef7c37d345e64"));
        binary_t plaintext;

        ret = protection.decrypt(&session, from_server, &ciphertext[0], ciphertext.size(), 0, plaintext);

        constexpr char expect[] = "1400000c1416a0981f02d6cd6b0b84b1";
        _test_case.assert(base16_decode_rfc(expect) == plaintext, __FUNCTION__, "server_finished");
    }
}

void test_tls12_aead() {
    test_tls12_aead_aes128gcm();
    test_tls12_aead_chacha20poly1305();
}
