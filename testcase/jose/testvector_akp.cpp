/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_akp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

// https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/

void test_json_testvector_akp(const char* filename) {
    _test_case.begin("AKP");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;
    json_web_signature jws;
    json_web_key jwk;
    crypto_key key;
    json_t* json_root = nullptr;
    json_t* json_jwk = nullptr;
    char* contents = nullptr;
    __try2 {
        ret = json_open_file(&json_root, filename);
        if (errorcode_t::success != ret) {
            _test_case.test(ret, __FUNCTION__, "open %s", filename);
            __leave2;
        }

        json_unpack(json_root, "{s:o}", "jwk", &json_jwk);
        contents = json_dumps(json_jwk, 0);

        const char* value_jws = nullptr;
        const char* value_raw_to_be_signed = nullptr;
        const char* value_raw_public_key = nullptr;
        json_unpack(json_root, "{s:s}", "jws", &value_jws);
        json_unpack(json_root, "{s:s}", "raw_to_be_signed", &value_raw_to_be_signed);
        json_unpack(json_root, "{s:s}", "raw_public_key", &value_raw_public_key);

        if (nullptr == contents || nullptr == value_jws || nullptr == value_raw_to_be_signed || nullptr == value_raw_public_key) {
            ret = errorcode_t::bad_format;
            _test_case.test(ret, __FUNCTION__, "read %s", filename);
            __leave2;
        }

        ret = jwk.load(&key, key_ownspec, contents, strlen(contents));
        _test_case.test(ret, __FUNCTION__, "load jwk %s", filename);

        auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
            auto pkey = item->get_pkey();

            _logger->write([&](basic_stream& bs) -> void {
                bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", item->get_desc().get_kid_cstr());
                dump_key(pkey, &bs, 16, 3, dump_notrunc);
            });
        };
        key.for_each(dump_crypto_key, nullptr);

        {
            auto pkey = key.any();
            _test_case.assert(nullptr != pkey, __FUNCTION__, "read pkey from JWK %s", filename);

            binary_t bin_pub;
            binary_t bin_priv;
            key.get_key(pkey, public_key, bin_pub, bin_priv, true);

            bool result = false;
            binary_t bin_raw_public_key = base16_decode(value_raw_public_key);
            _test_case.assert(bin_raw_public_key == bin_pub, __FUNCTION__, "public key %s", filename);

            // It’s a dangerous business, Frodo, going out your door.
            _logger->writeln(value_jws);
            ret = jws.verify(&key, value_jws, result);
            _test_case.test(ret, __FUNCTION__, "verify %s", filename);
        }
    }
    __finally2 {
        if (contents) {
            free(contents);
        }
        if (json_jwk) {
            json_decref(json_jwk);
        }
        if (json_root) {
            json_decref(json_root);
        }
    }
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_testvector_akp() {
    test_json_testvector_akp("testvector_akp_mldsa44.json");
    test_json_testvector_akp("testvector_akp_mldsa65.json");
    test_json_testvector_akp("testvector_akp_mldsa87.json");
}
