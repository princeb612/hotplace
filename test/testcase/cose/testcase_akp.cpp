/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_akp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

// https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/

void test_akp() {
    _test_case.begin("AKP");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    crypto_key key;
    crypto_keychain keychain;

    keychain.add_ossl3(&key, "ML-DSA-44", keydesc("ML-DSA-44"));
    keychain.add_ossl3(&key, "ML-DSA-65", keydesc("ML-DSA-65"));
    keychain.add_ossl3(&key, "ML-DSA-87", keydesc("ML-DSA-87"));

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        auto pkey = item->get_pkey();

        _logger->write([&](basic_stream& bs) -> void {
            bs.println(ANSI_ESCAPE "1;32m> kid \"%s\"" ANSI_ESCAPE "0m", item->get_desc().get_kid_cstr());
            dump_key(pkey, &bs, 16, 3, dump_notrunc);
        });
    };
    key.for_each(dump_crypto_key, nullptr);

    const char* payload = "It's a dangerous business, Frodo, going out your door.";
    return_t ret = errorcode_t::success;
    cbor_object_signing_encryption cose;
    binary_t cbor;

    auto lambda_test = [&](cose_alg_t alg) -> void {
        cose_context_t* handle = nullptr;

        ret = cose.open(&handle);
        if (errorcode_t::success == ret) {
            cose_layer& body = handle->composer->get_layer();
            body.get_protected().add(cose_key_t::alg, alg);

            ret = cose.sign(handle, &key, to_binary(payload), cbor);
            _test_case.test(ret, __FUNCTION__, "sign");

            _logger->colorln([&](basic_stream& bs) -> void {
                cbor_reader_context_t* handle = nullptr;
                cbor_reader reader;
                auto ret = reader.open(&handle);
                if (errorcode_t::success == ret) {
                    ret = reader.parse(handle, cbor);
                    reader.publish(handle, &bs);
                    reader.close(handle);
                }
            });

            cose.close(handle);
        }

        _logger->writeln("%s", base16_encode(cbor).c_str());

        ret = cose.open(&handle);
        if (errorcode_t::success == ret) {
            bool res = false;
            ret = cose.verify(handle, &key, cbor, res);
            _test_case.test(ret, __FUNCTION__, "verify");

            cose.close(handle);
        }
    };

    lambda_test(cose_mldsa44);
    lambda_test(cose_mldsa65);
    lambda_test(cose_mldsa87);
#else
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_akp() { test_akp(); }
