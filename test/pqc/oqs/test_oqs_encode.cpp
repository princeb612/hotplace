/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/oqs.hpp>

#include "../sample.hpp"

// install oqsprovider.dll into ossl-modules

void do_encode(oqs_context* context, const std::string& alg, key_encoding_t encoding, const char* passphrase = nullptr) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();
    pqc_oqs pqc;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY* pkey_decoded = nullptr;
    binary_t keycapsule;
    binary_t sharedsecret;
    binary_t key_encoded;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    std::string name_encoding = advisor->nameof_encoding(encoding);

    pqc.keygen(context, &pkey, alg.c_str());
    _test_case.assert(nullptr != pkey, __FUNCTION__, "keygen %s", alg.c_str());

    ret = pqc.encode(context, pkey, key_encoded, encoding, passphrase);
    if (option.dump_keys) {
        if (KEY_ENCODING_PEM & encoding) {
            _logger->writeln("%.*s", (int)key_encoded.size(), (char*)&key_encoded[0]);
        } else {
            _logger->writeln("key %s", base16_encode(key_encoded).c_str());
        }
    }
    _test_case.test(ret, __FUNCTION__, "encode %s [%s]", alg.c_str(), name_encoding.c_str());

    if (errorcode_t::success == ret) {
        ret = pqc.decode(context, &pkey_decoded, key_encoded, encoding, passphrase);
        _test_case.test(ret, __FUNCTION__, "decode %s [%s]", alg.c_str(), name_encoding.c_str());
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey_decoded);
}

void test_oqs_encode() {
    _test_case.begin("OQS encode");
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        oqs_context* context = nullptr;
        pqc_oqs pqc;
        const char* passphrase = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";

        ret = pqc.open(&context);
        if (errorcode_t::success == ret) {
            pqc.for_each(context, OSSL_OP_KEM, [&](const std::string& alg, int flags) -> void {
                _logger->writeln("algorithm : %s flags %i", alg.c_str(), flags);
                if (oqs_alg_oid_registered & flags) {
                    do_encode(context, alg, key_encoding_priv_pem);
                    do_encode(context, alg, key_encoding_encrypted_priv_pem, passphrase);
                    do_encode(context, alg, key_encoding_pub_pem);
                    do_encode(context, alg, key_encoding_priv_der);
                    do_encode(context, alg, key_encoding_encrypted_priv_der, passphrase);
                    do_encode(context, alg, key_encoding_pub_der);
                } else {
                    _test_case.test(not_supported, __FUNCTION__, "No OID registered for %s", alg.c_str());
                }
            });
            pqc.for_each(context, OSSL_OP_SIGNATURE, [&](const std::string& alg, int flags) -> void {
                _logger->writeln("algorithm : %s flags %i", alg.c_str(), flags);
                if (oqs_alg_oid_registered & flags) {
                    do_encode(context, alg, key_encoding_priv_pem);
                    do_encode(context, alg, key_encoding_encrypted_priv_pem, passphrase);
                    do_encode(context, alg, key_encoding_pub_pem);
                    do_encode(context, alg, key_encoding_priv_der);
                    do_encode(context, alg, key_encoding_encrypted_priv_der, passphrase);
                    do_encode(context, alg, key_encoding_pub_der);
                } else {
                    _test_case.test(not_supported, __FUNCTION__, "No OID registered for %s", alg.c_str());
                }
            });

            pqc.close(context);
        }
    }
    __finally2 {}
}
