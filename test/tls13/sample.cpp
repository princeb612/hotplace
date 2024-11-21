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
 *  RFC 8446
 *  RFC 5246
 *  -- RFC 8996 --
 *  RFC 4346
 *  RFC 2246
 */

// studying ...

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

test_case _test_case;
t_shared_instance<logger> _logger;

typedef struct _OPTION {
    int verbose;
    int log;
    int time;

    _OPTION() : verbose(0), log(0), time(0) {
        // do nothing
    }
} OPTION;
t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void debug_handler(trace_category_t category, uint32 event, stream_t* s) {
    std::string ct;
    std::string ev;
    basic_stream bs;
    auto advisor = trace_advisor::get_instance();
    advisor->get_names(category, event, ct, ev);
    bs.printf("[%s][%s]%.*s", ct.c_str(), ev.c_str(), (unsigned int)s->size(), s->data());
    _logger->writeln(bs);
};

crypto_key keys;
crypto_keychain keychain;

void test_rfc8448_2() {
    _test_case.begin("RFC 8448 2.  Private Keys");
    basic_stream bs;
    {
        const char* n =
            "b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c"
            "0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab"
            "bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87"
            "a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f"
            "da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0"
            "3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e"
            "3f";
        const char* e = "01 00 01";
        const char* d =
            "04 de a7 05 d4 3a 6e a7 20 9d d8 07 21 11 a8 3c 81"
            "e3 22 a5 92 78 b3 34 80 64 1e af 7c 0a 69 85 b8 e3 1c 44 f6 de 62"
            "e1 b4 c2 30 9f 61 26 e7 7b 7c 41 e9 23 31 4b bf a3 88 13 05 dc 12"
            "17 f1 6c 81 9c e5 38 e9 22 f3 69 82 8d 0e 57 19 5d 8c 84 88 46 02"
            "07 b2 fa a7 26 bc f7 08 bb d7 db 7f 67 9f 89 34 92 fc 2a 62 2e 08"
            "97 0a ac 44 1c e4 e0 c3 08 8d f2 5a e6 79 23 3d f8 a3 bd a2 ff 99"
            "41";
        keychain.add_rsa(&keys, "server RSA certificate", "RSA", base16_decode_rfc(n), base16_decode_rfc(e), base16_decode_rfc(d));
        dump_key(keys.find("server RSA certificate"), &bs);
        _logger->writeln(bs);
    }
}

void test_rfc8448_3() {
    _test_case.begin("RFC 8448 3.  Simple 1-RTT Handshake");
    return_t ret = errorcode_t::success;
    basic_stream bs;
    size_t pos = 0;

    const char* x =
        "99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d"
        "ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c";
    const char* y = "";
    const char* d =
        "49 af 42 ba 7f 79 94 85 2d 71 3e f2 78"
        "4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05";
    keychain.add_ec(&keys, "client epk", "EdDSA", "X25519", base16_decode_rfc(x), base16_decode_rfc(y), base16_decode_rfc(d));
    dump_key(keys.find("client epk"), &bs);
    _logger->writeln(bs);
    bs.clear();

    const char* client_hello =
        "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63"
        "ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83"
        "02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b"
        "00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00"
        "12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23"
        "00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2"
        "3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a"
        "af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03"
        "02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06"
        "02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";
    const char* client_handshake =
        "01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba"
        "1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02"
        "4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00"
        "09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12"
        "00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00"
        "00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d"
        "8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af"
        "2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02"
        "03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02"
        "02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";
    // [
    //   {
    //     "ClientHello": {
    //       "version": "Tls12",
    //       "random_data": "cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef628324dece7",
    //       "session_id": "",
    //       "cipherlist": [
    //         "0x1301(TLS_AES_128_GCM_SHA256)",
    //         "0x1303(TLS_CHACHA20_POLY1305_SHA256)",
    //         "0x1302(TLS_AES_256_GCM_SHA384)"
    //       ],
    //       "compressionlist": [
    //         "Null"
    //       ],
    //       "extensions": [
    //         "TlsExtension::SNI([\"type=HostName,name=server\"])",
    //         "TlsExtension::RenegotiationInfo(data=[])",
    //         "TlsExtension::EllipticCurves([\"EcdhX25519\", \"Secp256r1\", \"Secp384r1\", \"Secp521r1\", \"Ffdhe2048\", \"Ffdhe3072\",
    //              \"Ffdhe4096\", \"Ffdhe6144\", \"Ffdhe8192\"])",
    //         "TlsExtension::SessionTicket(data=[])",
    //         "TlsExtension::KeyShare(
    //              data=[00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af 2c])",
    //         "TlsExtension::SupportedVersions(v=[\"Tls13\"])",
    //         "TlsExtension::SignatureAlgorithms([\"ecdsa_secp256r1_sha256\", \"ecdsa_secp384r1_sha384\", \"ecdsa_secp521r1_sha512\", \"ecdsa_sha1\",
    //             \"rsa_pss_rsae_sha256\", \"rsa_pss_rsae_sha384\", \"rsa_pss_rsae_sha512\", \"rsa_pkcs1_sha256\", \"rsa_pkcs1_sha384\", \"rsa_pkcs1_sha512\",
    //             \"rsa_pkcs1_sha1\", \"HashSign(Sha256,Dsa)\", \"HashSign(Sha384,Dsa)\", \"HashSign(Sha512,Dsa)\", \"HashSign(Sha1,Dsa)\"])",
    //         "TlsExtension::PskExchangeModes([1])",
    //         "TlsExtension::RecordSizeLimit(data=16385)"
    //       ]
    //     }
    //   }
    // ]
    const char* client_record =
        "16 03 01 00 c4 01 00 00 c0 03 03 cb"
        "34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12"
        "ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00"
        "00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01"
        "00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02"
        "01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d"
        "e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d"
        "54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e"
        "04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02"
        "01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01";

    binary_t bin_client_hello = base16_decode_rfc(client_hello);
    binary_t bin_client_handshake = base16_decode_rfc(client_handshake);
    binary_t bin_client_record = base16_decode_rfc(client_record);
    tls_session session;

    auto lambda_dump_record = [&](const char* text, const binary_t& bin) -> return_t {
        _logger->hdump(format("> %s", text), bin);

        return_t ret = errorcode_t::success;
        pos = 0;
        ret = tls_dump_record(&bs, &session, &bin[0], bin.size(), pos);
        _logger->writeln(bs);
        bs.clear();

        // https://williamlieurance.com/tls-handshake-parser/
        _logger->writeln("copy and paste https://williamlieurance.com/tls-handshake-parser/");
        _logger->writeln(base16_encode(bin));

        return ret;
    };

    // bin_client_hello == bin_client_handshake
    ret = lambda_dump_record("client record", bin_client_record);
    _test_case.test(ret, __FUNCTION__, "dump handshake record");
}

void test_rfc8448_4() {
    _test_case.begin("RFC 8448 4.  Resumed 0-RTT Handshake");
    //
}

void test_rfc8448_5() {
    _test_case.begin("RFC 8448 5.  HelloRetryRequest");
    //
}

void test_rfc8448_6() {
    _test_case.begin("RFC 8448 6.  Client Authentication");
    //
}

void test_rfc8448_7() {
    _test_case.begin("RFC 8448 7.  Compatibility Mode");
    //
}

void test_tls13_xargs_org() {
    _test_case.begin("https://tls13.xargs.org/");

    tls_session session;
    tls_handshake_key& handshake_key = session.get_handshake_key();
    crypto_key& keys = handshake_key.get_key();
    crypto_keychain keychain;
    openssl_digest dgst;
    openssl_kdf kdf;
    basic_stream bs;
    size_t pos = 0;
    binary_t bin_client_hello;
    binary_t bin_server_hello;
    tls_advisor* advisor = tls_advisor::get_instance();

    /**
     * https://tls13.xargs.org/#client-key-exchange-generation
     */
    {
        // Client Key Exchange Generation
        const char* x = "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        const char* y = "";
        const char* d = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        keychain.add_ec_b16(&keys, "client key", "EdDSA", "X25519", x, y, d);
        basic_stream bs;
        dump_key(keys.find("client key"), &bs);
        _logger->writeln(bs);
    }
    // https://tls13.xargs.org/#client-hello
    {
        const char* client_hello =
            "16 03 01 00 F8 01 00 00 F4 03 03 00 01 02 03 04"
            "05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14"
            "15 16 17 18 19 1A 1B 1C 1D 1E 1F 20 E0 E1 E2 E3"
            "E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3"
            "F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 00 08 13 02"
            "13 03 13 01 00 FF 01 00 00 A3 00 00 00 18 00 16"
            "00 00 13 65 78 61 6D 70 6C 65 2E 75 6C 66 68 65"
            "69 6D 2E 6E 65 74 00 0B 00 04 03 00 01 02 00 0A"
            "00 16 00 14 00 1D 00 17 00 1E 00 19 00 18 01 00"
            "01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00"
            "00 17 00 00 00 0D 00 1E 00 1C 04 03 05 03 06 03"
            "08 07 08 08 08 09 08 0A 08 0B 08 04 08 05 08 06"
            "04 01 05 01 06 01 00 2B 00 03 02 03 04 00 2D 00"
            "02 01 01 00 33 00 26 00 24 00 1D 00 20 35 80 72"
            "D6 36 58 80 D1 AE EA 32 9A DF 91 21 38 38 51 ED"
            "21 A2 8E 3B 75 E9 65 D0 D2 CD 16 62 54 -- -- --";
        bin_client_hello = base16_decode_rfc(client_hello);
        pos = 0;
        tls_dump_record(&bs, &session, &bin_client_hello[0], bin_client_hello.size(), pos);
        _logger->hdump("> client hello", bin_client_hello, 16, 3);
        _logger->writeln(bs);
        bs.clear();
    }
    // https://tls13.xargs.org/#server-key-exchange-generation
    binary_t shared_secret;
    {
        const char* x = "9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
        const char* y = "";
        const char* d = "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
        keychain.add_ec_b16(&keys, "server key", "EdDSA", "X25519", x, y, d);
    }
    // https://tls13.xargs.org/#server-hello
    {
        const char* server_hello =
            "16 03 03 00 7A 02 00 00 76 03 03 70 71 72 73 74"
            "75 76 77 78 79 7A 7B 7C 7D 7E 7F 80 81 82 83 84"
            "85 86 87 88 89 8A 8B 8C 8D 8E 8F 20 E0 E1 E2 E3"
            "E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3"
            "F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF 13 02 00 00"
            "2E 00 2B 00 02 03 04 00 33 00 24 00 1D 00 20 9F"
            "D7 AD 6D CF F4 29 8D D3 F9 6D 5B 1B 2A F9 10 A0"
            "53 5B 14 88 D7 F8 FA BB 34 9A 98 28 80 B6 15 --";
        bin_server_hello = base16_decode_rfc(server_hello);
        pos = 0;
        tls_dump_record(&bs, &session, &bin_server_hello[0], bin_server_hello.size(), pos);
        _logger->hdump("> server hello", bin_server_hello, 16, 3);
        _logger->writeln(bs);
        bs.clear();
    }

    // > handshake type 2 (server_hello)
    //  > cipher suite 0x1302 TLS_AES_256_GCM_SHA384
    uint16 cipher_suite = session.get_cipher_suite();
    _test_case.assert(0x1302 == cipher_suite, __FUNCTION__, "cipher suite");

    // https://quic.xargs.org/#server-handshake-keys-calc
    {
        handshake_key.key_agreement("server key", "client key", shared_secret);

        basic_stream bs;
        dump_key(keys.find("server key"), &bs);
        _logger->writeln(bs);
        bs.clear();
        // _logger->hdump("> shared secret", shared_secret, 16, 3);
        _logger->writeln("> %s : %s", "shared_secret", base16_encode(shared_secret).c_str());
        _test_case.assert(shared_secret == base16_decode("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"), __FUNCTION__, "shared secret");
    }

    {
        bin_client_hello.erase(bin_client_hello.begin(), bin_client_hello.begin() + 5);
        bin_server_hello.erase(bin_server_hello.begin(), bin_server_hello.begin() + 5);
        // _logger->hdump("> client hello", bin_client_hello, 16, 3);
        // _logger->hdump("> server hello", bin_server_hello, 16, 3);

        //  > cipher suite 0x1302 TLS_AES_256_GCM_SHA384
        // ... Cipher AES_256_GCM for Protection, MAC SHA384 for Key Derivation

        binary_t hello_hash;
        handshake_key.calc_hello_hash(cipher_suite, hello_hash, bin_client_hello, bin_server_hello);
        _test_case.assert(hello_hash == base16_decode_rfc("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd"),
                          __FUNCTION__, "hello_hash");
        handshake_key.calc(cipher_suite, hello_hash, shared_secret);

        auto lambda_test = [&](tls_secret_t tls_secret, binary_t& secret, const char* text, const char* expect) -> void {
            handshake_key.get_item(tls_secret, secret);
            _logger->writeln("> %s : %s", text, base16_encode(secret).c_str());
            _test_case.assert(secret == base16_decode(expect), __FUNCTION__, text);
        };

        binary_t early_secret;
        lambda_test(tls_secret_early_secret, early_secret, "early_secret",
                    "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5");
        binary_t empty_hash;
        lambda_test(tls_secret_empty_hash, empty_hash, "empty_hash",
                    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        binary_t derived_secret;
        lambda_test(tls_secret_derived_secret, derived_secret, "derived_secret",
                    "1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b");
        binary_t handshake_secret;
        lambda_test(tls_secret_handshake_secret, handshake_secret, "handshake_secret",
                    "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299");
        binary_t client_secret;
        lambda_test(tls_secret_client_secret, client_secret, "client_secret",
                    "db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0");
        binary_t server_secret;
        lambda_test(tls_secret_server_secret, server_secret, "server_secret",
                    "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622");
        binary_t client_handshake_key;
        lambda_test(tls_secret_client_handshake_key, client_handshake_key, "client_handshake_key",
                    "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69");
        binary_t client_handshake_iv;
        lambda_test(tls_secret_client_handshake_iv, client_handshake_iv, "client_handshake_iv", "4256d2e0e88babdd05eb2f27");
        binary_t server_handshake_key;
        lambda_test(tls_secret_server_handshake_key, server_handshake_key, "server_handshake_key",
                    "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f");
        binary_t server_handshake_iv;
        lambda_test(tls_secret_server_handshake_iv, server_handshake_iv, "server_handshake_iv", "9563bc8b590f671f488d2da3");
    }
    // https://tls13.xargs.org/#server-change-cipher-spec
    {
        const char* change_cipher_spec = "14 03 03 00 01 01";
        binary_t bin_change_cipher_spec = base16_decode_rfc(change_cipher_spec);
        pos = 0;
        tls_dump_record(&bs, &session, &bin_change_cipher_spec[0], bin_change_cipher_spec.size(), pos);
        _logger->writeln(bs);
        bs.clear();
    }
    // https://tls13.xargs.org/#wrapped-record
    {
        const char* record =
            "17 03 03 00 17 6B E0 2F 9D A7 C2 DC 9D DE F5 6F"
            "24 68 B9 0A DF A2 51 01 AB 03 44 AE -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        pos = 0;
        tls_dump_record(&bs, &session, &bin_record[0], bin_record.size(), pos);
        _logger->writeln(bs);
        bs.clear();
    }
    // https://tls13.xargs.org/#wrapped-record-2
    {
        const char* record =
            "17 03 03 03 43 BA F0 0A 9B E5 0F 3F 23 07 E7 26"
            "ED CB DA CB E4 B1 86 16 44 9D 46 C6 20 7A F6 E9"
            "95 3E E5 D2 41 1B A6 5D 31 FE AF 4F 78 76 4F 2D"
            "69 39 87 18 6C C0 13 29 C1 87 A5 E4 60 8E 8D 27"
            "B3 18 E9 8D D9 47 69 F7 73 9C E6 76 83 92 CA CA"
            "8D CC 59 7D 77 EC 0D 12 72 23 37 85 F6 E6 9D 6F"
            "43 EF FA 8E 79 05 ED FD C4 03 7E EE 59 33 E9 90"
            "A7 97 2F 20 69 13 A3 1E 8D 04 93 13 66 D3 D8 BC"
            "D6 A4 A4 D6 47 DD 4B D8 0B 0F F8 63 CE 35 54 83"
            "3D 74 4C F0 E0 B9 C0 7C AE 72 6D D2 3F 99 53 DF"
            "1F 1C E3 AC EB 3B 72 30 87 1E 92 31 0C FB 2B 09"
            "84 86 F4 35 38 F8 E8 2D 84 04 E5 C6 C2 5F 66 A6"
            "2E BE 3C 5F 26 23 26 40 E2 0A 76 91 75 EF 83 48"
            "3C D8 1E 6C B1 6E 78 DF AD 4C 1B 71 4B 04 B4 5F"
            "6A C8 D1 06 5A D1 8C 13 45 1C 90 55 C4 7D A3 00"
            "F9 35 36 EA 56 F5 31 98 6D 64 92 77 53 93 C4 CC"
            "B0 95 46 70 92 A0 EC 0B 43 ED 7A 06 87 CB 47 0C"
            "E3 50 91 7B 0A C3 0C 6E 5C 24 72 5A 78 C4 5F 9F"
            "5F 29 B6 62 68 67 F6 F7 9C E0 54 27 35 47 B3 6D"
            "F0 30 BD 24 AF 10 D6 32 DB A5 4F C4 E8 90 BD 05"
            "86 92 8C 02 06 CA 2E 28 E4 4E 22 7A 2D 50 63 19"
            "59 35 DF 38 DA 89 36 09 2E EF 01 E8 4C AD 2E 49"
            "D6 2E 47 0A 6C 77 45 F6 25 EC 39 E4 FC 23 32 9C"
            "79 D1 17 28 76 80 7C 36 D7 36 BA 42 BB 69 B0 04"
            "FF 55 F9 38 50 DC 33 C1 F9 8A BB 92 85 83 24 C7"
            "6F F1 EB 08 5D B3 C1 FC 50 F7 4E C0 44 42 E6 22"
            "97 3E A7 07 43 41 87 94 C3 88 14 0B B4 92 D6 29"
            "4A 05 40 E5 A5 9C FA E6 0B A0 F1 48 99 FC A7 13"
            "33 31 5E A0 83 A6 8E 1D 7C 1E 4C DC 2F 56 BC D6"
            "11 96 81 A4 AD BC 1B BF 42 AF D8 06 C3 CB D4 2A"
            "07 6F 54 5D EE 4E 11 8D 0B 39 67 54 BE 2B 04 2A"
            "68 5D D4 72 7E 89 C0 38 6A 94 D3 CD 6E CB 98 20"
            "E9 D4 9A FE ED 66 C4 7E 6F C2 43 EA BE BB CB 0B"
            "02 45 38 77 F5 AC 5D BF BD F8 DB 10 52 A3 C9 94"
            "B2 24 CD 9A AA F5 6B 02 6B B9 EF A2 E0 13 02 B3"
            "64 01 AB 64 94 E7 01 8D 6E 5B 57 3B D3 8B CE F0"
            "23 B1 FC 92 94 6B BC A0 20 9C A5 FA 92 6B 49 70"
            "B1 00 91 03 64 5C B1 FC FE 55 23 11 FF 73 05 58"
            "98 43 70 03 8F D2 CC E2 A9 1F C7 4D 6F 3E 3E A9"
            "F8 43 EE D3 56 F6 F8 2D 35 D0 3B C2 4B 81 B5 8C"
            "EB 1A 43 EC 94 37 E6 F1 E5 0E B6 F5 55 E3 21 FD"
            "67 C8 33 2E B1 B8 32 AA 8D 79 5A 27 D4 79 C6 E2"
            "7D 5A 61 03 46 83 89 19 03 F6 64 21 D0 94 E1 B0"
            "0A 9A 13 8D 86 1E 6F 78 A2 0A D3 E1 58 00 54 D2"
            "E3 05 25 3C 71 3A 02 FE 1E 28 DE EE 73 36 24 6F"
            "6A E3 43 31 80 6B 46 B4 7B 83 3C 39 B9 D3 1C D3"
            "00 C2 A6 ED 83 13 99 77 6D 07 F5 70 EA F0 05 9A"
            "2C 68 A5 F3 AE 16 B6 17 40 4A F7 B7 23 1A 4D 94"
            "27 58 FC 02 0B 3F 23 EE 8C 15 E3 60 44 CF D6 7C"
            "D6 40 99 3B 16 20 75 97 FB F3 85 EA 7A 4D 99 E8"
            "D4 56 FF 83 D4 1F 7B 8B 4F 06 9B 02 8A 2A 63 A9"
            "19 A7 0E 3A 10 E3 08 41 58 FA A5 BA FA 30 18 6C"
            "6B 2F 23 8E B5 30 C7 3E -- -- -- -- -- -- -- --";
        binary_t bin_record = base16_decode_rfc(record);
        pos = 0;
        tls_dump_record(&bs, &session, &bin_record[0], bin_record.size(), pos);
        _logger->writeln(bs);
        bs.clear();
    }
    // https://tls13.xargs.org/#server-encrypted-extensions/annotated
    {
        // > decrypted
        //   00000000 : 08 00 00 02 00 00 16 -- -- -- -- -- -- -- -- -- | .......
    }
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    _cmdline.make_share(new t_cmdline_t<OPTION>);
    *_cmdline << t_cmdarg_t<OPTION>("-v", "verbose", [](OPTION& o, char* param) -> void { o.verbose = 1; }).optional()
              << t_cmdarg_t<OPTION>("-l", "log", [](OPTION& o, char* param) -> void { o.log = 1; }).optional()
              << t_cmdarg_t<OPTION>("-t", "log time", [](OPTION& o, char* param) -> void { o.time = 1; }).optional();
    _cmdline->parse(argc, argv);

    const OPTION& option = _cmdline->value();

    logger_builder builder;
    builder.set(logger_t::logger_stdout, option.verbose);
    if (option.log) {
        builder.set(logger_t::logger_flush_time, 1).set(logger_t::logger_flush_size, 1024).set_logfile("test.log");
    }
    if (option.time) {
        builder.set_timeformat("[Y-M-D h:m:s.f]");
    }
    _logger.make_share(builder.build());

    if (option.verbose) {
        set_trace_debug(debug_handler);
        set_trace_option(trace_bt | trace_except | trace_debug);
    }

    openssl_startup();

    // RFC 8448 Example Handshake Traces for TLS 1.3
    test_rfc8448_2();
    test_rfc8448_3();
    test_rfc8448_4();
    test_rfc8448_5();
    test_rfc8448_6();
    test_rfc8448_7();

    // https://tls13.xargs.org/
    test_tls13_xargs_org();

    openssl_cleanup();

    _logger->flush();

    _test_case.report(5);
    _cmdline->help();
    return _test_case.result();
}
