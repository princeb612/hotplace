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

void test_crypto_key() {
    _test_case.begin("crypto_key");
    return_t ret = errorcode_t::success;
    crypto_key key;
    crypto_keychain keychain;
    basic_stream bs;

    struct curves_t {
        uint32 nid;
        const char* name;
    };
// {NID_X9_62_prime192v1, "NID_X9_62_prime192v1"}
#define ENTRY(x) {x, #x}
    curves_t curves[] = {
        ENTRY(NID_secp112r1),       ENTRY(NID_secp112r2),       ENTRY(NID_secp128r1),        ENTRY(NID_secp128r2),        ENTRY(NID_secp160k1),
        ENTRY(NID_secp160r1),       ENTRY(NID_secp160r2),       ENTRY(NID_secp192k1),        ENTRY(NID_X9_62_prime192v1), ENTRY(NID_secp224k1),
        ENTRY(NID_secp224r1),       ENTRY(NID_secp256k1),       ENTRY(NID_X9_62_prime256v1), ENTRY(NID_secp384r1),        ENTRY(NID_secp521r1),
        ENTRY(NID_sect113r1),       ENTRY(NID_sect113r2),       ENTRY(NID_sect131r1),        ENTRY(NID_sect131r2),        ENTRY(NID_sect163k1),
        ENTRY(NID_sect163r1),       ENTRY(NID_sect163r2),       ENTRY(NID_sect193r1),        ENTRY(NID_sect193r2),        ENTRY(NID_sect233k1),
        ENTRY(NID_sect233r1),       ENTRY(NID_sect239k1),       ENTRY(NID_sect283k1),        ENTRY(NID_sect283r1),        ENTRY(NID_sect409k1),
        ENTRY(NID_sect409r1),       ENTRY(NID_sect571k1),       ENTRY(NID_sect571r1),        ENTRY(NID_X25519),           ENTRY(NID_X448),
        ENTRY(NID_ED25519),         ENTRY(NID_ED448),           ENTRY(NID_brainpoolP160r1),  ENTRY(NID_brainpoolP160t1),  ENTRY(NID_brainpoolP192r1),
        ENTRY(NID_brainpoolP192t1), ENTRY(NID_brainpoolP224r1), ENTRY(NID_brainpoolP224t1),  ENTRY(NID_brainpoolP256r1),  ENTRY(NID_brainpoolP256t1),
        ENTRY(NID_brainpoolP320r1), ENTRY(NID_brainpoolP320t1), ENTRY(NID_brainpoolP384r1),  ENTRY(NID_brainpoolP384t1),  ENTRY(NID_brainpoolP512r1),
        ENTRY(NID_brainpoolP512t1),
    };
    curves_t ffdhes[] = {
        ENTRY(NID_ffdhe2048), ENTRY(NID_ffdhe3072), ENTRY(NID_ffdhe4096), ENTRY(NID_ffdhe6144), ENTRY(NID_ffdhe8192),
    };

    // public, private
    keychain.add_ec_b64u(&key, "P-256", "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8", "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
                         "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM", keydesc("11"));
    keychain.add_ec_b64u(&key, "P-384", "kTJyP2KSsBBhnb4kjWmMF7WHVsY55xUPgb7k64rDcjatChoZ1nvjKmYmPh5STRKc",
                         "mM0weMVU2DKsYDxDJkEP9hZiRZtB8fPfXbzINZj_fF7YQRynNWedHEyzAJOX2e8s", "ok3Nq97AXlpEusO7jIy1FZATlBP9PNReMU7DWbkLQ5dU90snHuuHVDjEPmtV0fTo",
                         keydesc("P384"));
    keychain.add_ec_b64u(&key, "P-521", "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                         "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
                         "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt",
                         keydesc("bilbo.baggins@hobbiton.example", "ES512"));
    keychain.add_ec_b16(&key, "Ed25519", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", keydesc("11", "EdDSA"));
    keychain.add_ec_b16(&key, "Ed448", "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180", "",
                        "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
                        keydesc("ed448", "EdDSA"));
    keychain.add_ec_b16(&key, "P-256", "863aa7bc0326716aa59db5bf66cc660d0591d51e4891bc2e6a9baff5077d927c",
                        "ad4eed482a7985be019e9b1936c16e00190e8bcc48ee12d35ff89f0fc7a099ca", "d42044eb2cd2691e926da4871cf3529ddec6b034f824ba5e050d2c702f97c7a5",
                        keydesc("Alice Lovelace", "ES256"));
    keychain.add_ec_b16(&key, "X25519", "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E", "",
                        "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655", keydesc("X25519-1", "X25519"));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", keydesc("our-secret", nullptr, crypto_use_t::use_enc));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJico", keydesc("sec-48", nullptr, crypto_use_t::use_enc));
    keychain.add_oct_b64u(&key, "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYgAESIzd4iZqiEiIyQlJicoqrvM3e7_paanqKmgsbKztA",
                          keydesc("sec-64", nullptr, crypto_use_t::use_enc));

    keychain.add_rsa_b16(
        &key, nid_rsa,
        "bc7e29d0df7e20cc9dc8d509e0f68895922af0ef452190d402c61b554334a7bf91c9a570240f994fae1b69035bcfad4f7e249eb26087c2665e7c958c967b1517413dc3f97a"
        "431691a5999b257cc6cd356bad168d929b8bae9020750e74cf60f6fd35d6bb3fc93fc28900478694f508b33e7c00e24f90edf37457fc3e8efcfd2f42306301a8205ab74051"
        "5331d5c18f0c64d4a43be52fc440400f6bfc558a6e32884c2af56f29e5c52780cea7285f5c057fc0dfda232d0ada681b01495d9d0e32196633588e289e59035ff664f05618"
        "9f2f10fe05827b796c326e3e748ffa7c589ed273c9c43436cddb4a6a22523ef8bcb2221615b799966f1aba5bc84b7a27cf",
        "010001",
        "0969ff04fcc1e1647c20402cf3f736d4cae33f264c1c6ee3252cfcc77cdef533d700570ac09a50d7646edfb1f86a13bcabcf00bd659f27813d08843597271838bc46ed4743"
        "fe741d9bc38e0bf36d406981c7b81fce54861cebfb85ad23a8b4833c1bee18c05e4e436a869636980646eecb839e4daf434c9c6dfbf3a55ce1db73e4902f89384bd6f9ecd3"
        "399fb1ed4b83f28d356c8e619f1f0dc96bbe8b75c1812ca58f360259eaeb1d17130c3c0a2715a99be49898e871f6088a29570dc2ffa0cefffa27f1f055cbaabfd8894e0cc2"
        "4f176e34ebad32278a466f8a34a685acc8207d9ec1fcbbd094996dc73c6305fca31668be57b1699d0bb456cc8871bffbcd",
        keydesc("meriadoc.brandybuck@rsa.example"));

    // generate

    for (auto item : curves) {
        keychain.add_ec(&key, item.nid, keydesc(item.name));
    }
    for (auto item : ffdhes) {
        keychain.add_dh(&key, item.nid, keydesc(item.name));
    }

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        bs.printf(R"(> kid "%s")", item->get_desc().get_kid_cstr());
        bs.printf("\n");
        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        _logger->writeln(bs);
        bs.clear();
    };
    key.for_each(dump_crypto_key, nullptr);

    crypto_advisor* advisor = crypto_advisor::get_instance();
    for (auto item : curves) {
        auto pkey = key.find(item.name);
        if (pkey) {
            binary_t bin_x, bin_y, bin_d;
            key.get_key(pkey, bin_x, bin_y, bin_d);
            auto hint = advisor->hintof_curve_nid(item.nid);
            uint8 keysize = bin_x.size();
            bool test = ((hint->keysize == keysize) || (hint->keysize - 1 == keysize));
            _test_case.assert(test, __FUNCTION__, "%s keysize(x) %zi", item.name, bin_x.size());
        } else {
            _test_case.test(not_found, __FUNCTION__, "%s", item.name);
        }
    }

    json_web_key jwk;
    ret = jwk.write(&key, &bs);
    _logger->writeln(bs);
    bs.clear();
    _test_case.test(ret, __FUNCTION__, "JWK");

    cbor_web_key cwk;
    ret = cwk.diagnose(&key, &bs);
    _logger->writeln(bs);
    bs.clear();
    _test_case.test(ret, __FUNCTION__, "CWK");
}

void test_eckey_compressed() {
    _test_case.begin("EC compressed/uncompressed");
    basic_stream bs;
    crypto_keychain keychain;
    crypto_key key;
    binary_t bin_x;
    binary_t bin_y;
    binary_t bin_d;

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        bs.printf(R"(> kid "%s")", item->get_desc().get_kid_cstr());
        bs.printf("\n");
        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        _logger->writeln(bs);
        bs.clear();
    };

    {
        keychain.add_ec_b16(&key, ec_p256, "98F50A4FF6C05861C8860D13A638EA56C3F5AD7590BBFBF054E1C7B4D91D6280", true, nullptr, keydesc("test"));
        key.for_each(dump_crypto_key, nullptr);

        const EVP_PKEY* pkey = key.find("test");
        key.get_key(pkey, bin_x, bin_y, bin_d, true);
        // Appendix_C_3_1
        // x mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA
        // y 8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs
        std::string y_compressed("8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs");
        bool test = (bin_y == base64_decode(y_compressed, base64_encoding_t::base64url_encoding));
        _test_case.assert(test, __FUNCTION__, "EC compressed");
    }

    const char* uncompressed_key_p256 =
        "04a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780";
    {
        keychain.add_ec_b16(&key, "P-256",
                            uncompressed_key_p256,  // 04 + x + y
                            "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39", keydesc("P-256 uncompressed"));
        keychain.add_ec_b16(&key, ec_p256, "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280", true, nullptr, keydesc("P-256 compressed"));
        keychain.add_ec_b16(
            &key, ec_p521, "72992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
            true, nullptr, keydesc("P-521 compressed"));
    }

    auto uncompressed_key = key.find("P-256 uncompressed", use_any, true);  // refcounter ++
    if (uncompressed_key) {
        const char* x = "a6da7392ec591e17abfd535964b99894d13befb221b3def2ebe3830eac8f0151";
        const char* y = "812677c4d6d2237e85cf01d6910cfb83954e76ba7352830534159897e8065780";
        const char* d = "ab5473467e19346ceb0a0414e41da21d4d2445bc3025afe97c4e8dc8d513da39";

        binary_t bin_x, bin_y, bin_d;
        key.get_key(uncompressed_key, bin_x, bin_y, bin_d);

        binary_t bin_uncompressed;
        key.ec_uncompressed_key(uncompressed_key, bin_uncompressed, bin_d);

        EVP_PKEY_free((EVP_PKEY*)uncompressed_key);  // refcounter --

        _test_case.assert(bin_x == base16_decode(x), __FUNCTION__, "uncompressed key x");
        _test_case.assert(bin_y == base16_decode(y), __FUNCTION__, "uncompressed key y");
        _test_case.assert(bin_d == base16_decode(d), __FUNCTION__, "d");
        _test_case.assert(bin_uncompressed == base16_decode(uncompressed_key_p256), __FUNCTION__, "uncompressed");
    } else {
        _test_case.test(errorcode_t::not_found, __FUNCTION__, "uncompressed key");
    }

    {
        auto compressed_key = key.find("P-256 compressed", use_any);
        if (compressed_key) {
            binary_t bin_compressed;
            binary_t bin_d;
            key.ec_compressed_key(compressed_key, bin_compressed, bin_d);

            const char* compressed = "0398f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280";
            _test_case.assert(bin_compressed == base16_decode(compressed), __FUNCTION__, "compressed %s", base16_encode(bin_compressed).c_str());
        } else {
            _test_case.test(errorcode_t::not_found, __FUNCTION__, "compressed key");
        }
    }
    {
        // rfc8152_c_7_1.diag kid:"bilbo.baggins@hobbiton.example"
        auto compressed_key = key.find("P-521 compressed", use_any);
        if (compressed_key) {
            binary_t bin_compressed;
            binary_t bin_x, bin_y, bin_d;
            key.ec_compressed_key(compressed_key, bin_compressed, bin_d);

            key.get_key(compressed_key, bin_x, bin_y, bin_d);

            // preserve leading zero
            // 3 || x ; ybit true
            const char* compressed_x =
                "030072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad";
            const char* y =
                "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475";
            _test_case.assert(bin_compressed == base16_decode(compressed_x), __FUNCTION__, "compressed %s", base16_encode(bin_compressed).c_str());
            _test_case.assert(bin_y == base16_decode(y), __FUNCTION__, "y %s", base16_encode(bin_y).c_str());
        } else {
            _test_case.test(errorcode_t::not_found, __FUNCTION__, "compressed key");
        }
    }
}

void test_ffdhe() {
    _test_case.begin("ffdhe");

    crypto_key key;
    crypto_keychain keychain;

    const char* pub =
        "6845918d1559c5a47a14f05ec4a3c81e3728d4fecedecc840ace7942d91d7f82d3c3dfc26bf8123375d874f1189a9490a92c875b2df396d54306398054e6b085519339b642447c5971c19f"
        "9b028cd9d799fe4d6ddcad3cd68845aede4ff9f8a74f5ce099b88f00761568114efc0c5a00d8121ff86b4a16553f3c68a57f264ccac08beccdffaf3c92f6592d956a5f7a3d77d5744332de"
        "3557f53ca3d34ed0f9b449c9f27759ae57fc477d748ad5c2a8139fc95d1148f509689e75c0d1e51e15081dfce4a488dc350fe39b7c06d62f9a7626d09c3b5f881a01bebc3d66b60b15ec85"
        "1e6e793d9296f767a8c30034e2e68fe4af4e1282e74b7dd8c2f153d64214ee";
    const char* priv = "01c1d7379d44d3dc33e01ead0bb1f8ad8c6f485fbc3078574f68a6b6b1";

    keychain.add_dh_b16(&key, NID_ffdhe2048, pub, priv, keydesc("ffdhe2048"));

    // generate
    keychain.add_dh(&key, NID_ffdhe2048, keydesc("NID_ffdhe2048"));
    keychain.add_dh(&key, NID_ffdhe3072, keydesc("NID_ffdhe3072"));
    keychain.add_dh(&key, NID_ffdhe4096, keydesc("NID_ffdhe4096"));
    keychain.add_dh(&key, NID_ffdhe6144, keydesc("NID_ffdhe6144"));
    keychain.add_dh(&key, NID_ffdhe8192, keydesc("NID_ffdhe8192"));

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        basic_stream bs;
        bs.printf(R"(> kid "%s")", item->get_desc().get_kid_cstr());
        bs.printf("\n");
        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        _logger->writeln(bs);
    };
    key.for_each(dump_crypto_key, nullptr);

    auto pkey = key.find("ffdhe2048");
    if (pkey) {
        binary_t bin_pub;
        binary_t bin_pub2;
        binary_t bin_priv;
        key.get_key(pkey, bin_pub, bin_pub2, bin_priv);
        _test_case.assert(bin_pub == base16_decode(pub), __FUNCTION__, "ffdhe2048 public");
        _test_case.assert(bin_priv == base16_decode(priv), __FUNCTION__, "ffdhe2048 private");
    } else {
        _test_case.test(not_found, __FUNCTION__, "ffdhe2048");
    }
}