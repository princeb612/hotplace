/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_testvector_akp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

// https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/

void test_json_testvector_akp(const char* filename) {
    _test_case.begin("AKP");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;
    // json_web_signature jws;
    cbor_web_key cwk;
    crypto_key key;
    json_t* json_root = nullptr;
    __try2 {
        ret = json_open_file(&json_root, filename);
        if (errorcode_t::success != ret) {
            _test_case.test(ret, __FUNCTION__, "open %s", filename);
            __leave2;
        }

        const char* value_key = nullptr;
        json_unpack(json_root, "{s:s}", "key", &value_key);

        const char* value_sign1 = nullptr;
        const char* value_raw_to_be_signed = nullptr;
        const char* value_raw_public_key = nullptr;
        json_unpack(json_root, "{s:s}", "key", &value_key);
        json_unpack(json_root, "{s:s}", "sign1", &value_sign1);
        json_unpack(json_root, "{s:s}", "raw_to_be_signed", &value_raw_to_be_signed);
        json_unpack(json_root, "{s:s}", "raw_public_key", &value_raw_public_key);

        if (nullptr == value_sign1 || nullptr == value_raw_to_be_signed || nullptr == value_raw_public_key) {
            ret = errorcode_t::bad_format;
            _test_case.test(ret, __FUNCTION__, "read %s", filename);
            __leave2;
        }

        ret = cwk.load_b16(&key, value_key, strlen(value_key));
        _test_case.test(ret, __FUNCTION__, "load cwk %s", filename);

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
            _logger->hdump("key", bin_pub, 16, 3);

            binary_t bin_raw_public_key = base16_decode(value_raw_public_key);
            _test_case.assert(bin_raw_public_key == bin_pub, __FUNCTION__, "public key %s", filename);

            // It’s a dangerous business, Frodo, going out your door.
            bool result = false;
            cose_context_t* cose_handle = nullptr;
            cbor_object_signing_encryption cose;
            cose.open(&cose_handle);
            ret = cose.verify(cose_handle, &key, base16_decode(value_sign1), result);
            cose.close(cose_handle);
            _logger->writeln(value_sign1);
            _test_case.test(ret, __FUNCTION__, "verify %s", filename);
        }
    }
    __finally2 {
        if (json_root) {
            json_decref(json_root);
        }
    }
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_testvector_akp() {
    test_json_testvector_akp("cose_mldsa44.json");
    test_json_testvector_akp("cose_mldsa65.json");
    test_json_testvector_akp("cose_mldsa87.json");
}
