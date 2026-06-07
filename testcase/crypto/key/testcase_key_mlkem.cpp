/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_key_mlkem.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_mlkem_keygen() {
    _test_case.begin("ML-KEM");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;
    crypto_keychain keychain;
    crypto_key key;

    ret = keychain.add_ossl3(&key, NID_ML_KEM_512, keydesc("ML-KEM-512"));
    _test_case.test(ret, __FUNCTION__, "ML-KEM-512");
    ret = keychain.add_ossl3(&key, NID_ML_KEM_768, keydesc("ML-KEM-768"));
    _test_case.test(ret, __FUNCTION__, "ML-KEM-768");
    ret = keychain.add_ossl3(&key, NID_ML_KEM_1024, keydesc("ML-KEM-1024"));
    _test_case.test(ret, __FUNCTION__, "ML-KEM-1024");

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        auto kid = item->get_desc().get_kid_cstr();
        auto pkey = key.find(kid);
        _test_case.assert(nullptr != pkey, __FUNCTION__, "find %s", kid);

        auto kty = ktyof_evp_pkey(pkey);
        _test_case.assert(kty_mlkem == kty, __FUNCTION__, "kty %s", nameof_key_type(kty));

        _logger->write([&](basic_stream& bs) -> void {
            bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", item->get_desc().get_kid_cstr());
            dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        });
    };
    key.for_each(dump_crypto_key, nullptr);
    _test_case.assert(3 == key.size(), __FUNCTION__, "add_mlkem");

    // and then encapsulate, decapsulate ... see example pqc
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void test_mlkem_keyuse_routine(tls_group_t group, const binary_t& share) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;
    crypto_keyexchange keyexchange;
    crypto_key key;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_tls_group(group);
    if (hint) {
        auto name = hint->name;

        ret = keyexchange.keystore(group, &key, "store", share);
        _test_case.test(ret, __FUNCTION__, "store %s", name);
        auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
            auto kid = item->get_desc().get_kid_cstr();

            _logger->write([&](basic_stream& bs) -> void {
                bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", kid);
                dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
            });
        };
        key.for_each(dump_crypto_key, nullptr);

        binary_t keycapsule;
        binary_t sharedsecret;
        ret = keyexchange.encaps(group, share, keycapsule, sharedsecret);
        _test_case.test(ret, __FUNCTION__, "encaps %s", name);
    } else {
        _test_case.test(errorcode_t::not_supported, __FUNCTION__, "unknown");
    }
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_key_mlkem() { test_mlkem_keygen(); }
