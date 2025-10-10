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

void test_oqs_dsa() {
    _test_case.begin("OQS DSA");
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        oqs_context* context = nullptr;
        pqc_oqs oqs;

        ret = oqs.open(&context);
        _test_case.test(ret, __FUNCTION__, "load oqsprovider");
        if (errorcode_t::success == ret) {
            const char* message = "We don't playing because we grow old; we grow old because we stop playing. - George Bernard Shaw";
            oqs.for_each(context, OSSL_OP_SIGNATURE, [&](const std::string& alg, int flags) -> void {
                _logger->writeln("algorithm : %s flags %i", alg.c_str(), flags);

                if (oqs_alg_oid_registered & flags) {
                    EVP_PKEY* pkey_keygen = nullptr;
                    binary_t pubkey;
                    binary_t privkey;
                    auto encoding_pubkey = key_encoding_pub_der;
                    auto encoding_privkey = key_encoding_priv_der;

                    // generate keypair
                    oqs.keygen(context, &pkey_keygen, alg.c_str());
                    _test_case.assert(nullptr != pkey_keygen, __FUNCTION__, "keygen %s", alg.c_str());

                    // public key
                    ret = oqs.encode(context, pkey_keygen, pubkey, encoding_pubkey);
                    if (option.dump_keys) {
                        _logger->writeln("pub key %s", base16_encode(pubkey).c_str());
                    }
                    _test_case.test(ret, __FUNCTION__, "public key %s", alg.c_str());
                    // private key
                    ret = oqs.encode(context, pkey_keygen, privkey, encoding_privkey);
                    if (option.dump_keys) {
                        _logger->writeln("priv key %s", base16_encode(privkey).c_str());
                    }
                    _test_case.test(ret, __FUNCTION__, "private key %s", alg.c_str());

                    // key distribution
                    EVP_PKEY* pkey_pub = nullptr;
                    ret = oqs.decode(context, &pkey_pub, pubkey, encoding_pubkey);
                    _test_case.test(ret, __FUNCTION__, "distribute public key %s", alg.c_str());

                    if (errorcode_t::success == ret) {
                        binary_t signature;
                        ret = oqs.sign(context, pkey_keygen, (const byte_t*)message, strlen(message), signature);
                        if (loglevel_debug == option.trace_level) {
                            _logger->writeln("signature %s", base16_encode(signature).c_str());
                        }
                        _test_case.test(ret, __FUNCTION__, "sign %s", alg.c_str());

                        ret = oqs.verify(context, pkey_pub, (const byte_t*)message, strlen(message), signature);
                        _test_case.test(ret, __FUNCTION__, "verify %s", alg.c_str());
                    }

                    EVP_PKEY_free(pkey_pub);
                    EVP_PKEY_free(pkey_keygen);
                } else {
                    ret = errorcode_t::not_supported;
                    _test_case.test(ret, __FUNCTION__, "No OID registered for %s", alg.c_str());
                }
            });

            oqs.close(context);
        }
    }
    __finally2 {}
}
