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
        _logger->write(bs);
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

void test_ffdhe_dh() {
    _test_case.begin("ffdhe");

    return_t ret = errorcode_t::success;
    crypto_key key;
    crypto_keychain keychain;

    const char* pub =
        "6845918d1559c5a47a14f05ec4a3c81e3728d4fecedecc840ace7942d91d7f82d3c3dfc26bf8123375d874f1189a9490a92c875b2df396d54306398054e6b085519339b642447c5971c19f"
        "9b028cd9d799fe4d6ddcad3cd68845aede4ff9f8a74f5ce099b88f00761568114efc0c5a00d8121ff86b4a16553f3c68a57f264ccac08beccdffaf3c92f6592d956a5f7a3d77d5744332de"
        "3557f53ca3d34ed0f9b449c9f27759ae57fc477d748ad5c2a8139fc95d1148f509689e75c0d1e51e15081dfce4a488dc350fe39b7c06d62f9a7626d09c3b5f881a01bebc3d66b60b15ec85"
        "1e6e793d9296f767a8c30034e2e68fe4af4e1282e74b7dd8c2f153d64214ee";

    keychain.add_dh(&key, NID_ffdhe2048, keydesc("generated"));
    keychain.add_dh_b16(&key, NID_ffdhe2048, pub, nullptr, keydesc("pub"));

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        basic_stream bs;
        bs.println("\e[1;32m> kid \"%s\"\e[0m", item->get_desc().get_kid_cstr());
        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        _logger->write(bs);
    };
    key.for_each(dump_crypto_key, nullptr);

    auto genkey = key.find("generated");
    auto pubkey = key.find("pub");
    auto privkey = key.find("priv");

    binary_t shared;
    ret = dh_key_agreement(genkey, pubkey, shared);

    _logger->hdump("shared", shared, 16, 3);
    _test_case.test(ret, __FUNCTION__, "DH");
}
