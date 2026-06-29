/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_keygen.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/testcase/crypto/sample.hpp>

void test_keygen() {
    _test_case.begin("keygen");

    // sketch

    crypto_key key;
    auto advisor = crypto_advisor::get_instance();

    auto lambda_gen = [&](const char* name, const char* kid) -> void {
        crypto_keygen keygen(&key, name);
        keygen.set(keydesc(kid)).gen();
    };

    lambda_gen("rsaEncryption", "RSA gen");
    lambda_gen("RSASSA-PSS", "RSASSA-PSS gen");
    lambda_gen("P-256", "P-256 gen");
    lambda_gen("X25519", "X25519 gen");
    lambda_gen("X448", "X448 gen");
    lambda_gen("Ed25519", "Ed25519 gen");
    lambda_gen("Ed448", "Ed448 gen");

    // kty_okp, x25519, base16
    crypto_keygen keygen_x25519(&key, "X25519");
    keygen_x25519.set(keydesc("X25519"))
        .set("x", "7FFE91F5F932DAE92BE603F55FAC0F4C4C9328906EE550EDCB7F6F7626EBC07E")
        .set("d", "00a943daa2e38b2edbf0da0434eaaec6016fe25dcd5ecacbc07dc30300567655")
        .build();  // private key (x, d)

    // other testcases moved into "testvector_keygen.yml"

    std::map<std::string, bool> keymap;
    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        keymap.emplace(item->get_desc().get_kid_str(), true);

        auto pkey = item->get_pkey();

        _logger->write([&](basic_stream& bs) -> void {
            bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", item->get_desc().get_kid_cstr());
            dump_key(pkey, &bs, 16, 3, dump_notrunc);
        });
    };
    key.for_each(dump_crypto_key, nullptr);

    // is key generated

    auto lambda_check = [&](const char* function, uint32 nid, const char* kid) -> void {
        auto pkey = key.find(kid);

        crypto_kty_t kty = {};
        uint32 id = 0;
        advisor->ktyof_evp_pkey(pkey, kty, id);

        _test_case.assert(keymap[kid] && (nid == id), function, "%s nid %u %u", kid, nid, id);
    };

    lambda_check(__FUNCTION__, nid_rsa, "RSA gen");
    lambda_check(__FUNCTION__, nid_rsapss, "RSASSA-PSS gen");
    lambda_check(__FUNCTION__, NID_X9_62_prime256v1, "P-256 gen");
    lambda_check(__FUNCTION__, NID_X25519, "X25519 gen");
    lambda_check(__FUNCTION__, NID_ED25519, "Ed25519 gen");
    lambda_check(__FUNCTION__, NID_X448, "X448 gen");
    lambda_check(__FUNCTION__, NID_ED448, "Ed448 gen");
    lambda_check(__FUNCTION__, NID_X25519, "X25519");
}

void testcase_keygen() { test_keygen(); }
