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

void test_oqs_kem() {
    _test_case.begin("OQS KEM");
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        oqs_context* context = nullptr;
        pqc_oqs oqs;

        ret = oqs.open(&context);
        _test_case.test(ret, __FUNCTION__, "load oqsprovider");
        if (errorcode_t::success == ret) {
            // p256_mlkem512, x25519_mlkem512 : OID registered only
            oqs.for_each(context, OSSL_OP_KEM, [&](const std::string& alg, int flags) -> void {
                _logger->writeln("algorithm : %s", alg.c_str());

                if (oqs_alg_oid_registered & flags) {
                    EVP_PKEY* pkey_keygen = nullptr;
                    EVP_PKEY* pkey_pub = nullptr;

                    binary_t keycapsule;
                    binary_t sharedsecret_bob;
                    binary_t pubkey;
                    binary_t privkey;
                    auto encoding_pubkey = key_encoding_pub_der;
                    auto encoding_privkey = key_encoding_priv_der;

                    // alice : generate keypair
                    oqs.keygen(context, &pkey_keygen, alg.c_str());
                    _test_case.assert(nullptr != pkey_keygen, __FUNCTION__, "keygen %s", alg.c_str());

                    // public key
                    ret = oqs.encode(context, pkey_keygen, pubkey, encoding_pubkey);
                    if (option.dump_keys) {
                        _logger->writeln("pub key %s", base16_encode(pubkey).c_str());
                    }
                    _test_case.test(ret, __FUNCTION__, "public key %s flags %i", alg.c_str(), flags);
                    // private key
                    ret = oqs.encode(context, pkey_keygen, privkey, encoding_privkey);
                    if (option.dump_keys) {
                        _logger->writeln("priv key %s", base16_encode(privkey).c_str());
                    }
                    _test_case.test(ret, __FUNCTION__, "private key %s", alg.c_str());

                    // alice -> bob : key distribution
                    ret = oqs.decode(context, &pkey_pub, pubkey, encoding_pubkey);
                    _test_case.test(ret, __FUNCTION__, "distribute public key %s", alg.c_str());

                    if (errorcode_t::success == ret) {
                        // bob : encapsulate using public key
                        ret = oqs.encapsule(context, pkey_pub, keycapsule, sharedsecret_bob);
                        if (option.is_loglevel_debug()) {
                            _logger->hdump("encapsulated key", keycapsule, 16, 3);
                            _logger->hdump("shared secret", sharedsecret_bob, 16, 3);
                        }
                        _test_case.test(ret, __FUNCTION__, "encapsulate %s", alg.c_str());

                        // alice : decapsulate using private key
                        binary_t sharedsecret_alice;
                        ret = oqs.decapsule(context, pkey_keygen, keycapsule, sharedsecret_alice);
                        _test_case.test(ret, __FUNCTION__, "decapsulate %s", alg.c_str());

                        // compare
                        _test_case.assert(sharedsecret_bob == sharedsecret_alice, __FUNCTION__, "compare");
                    }

                    EVP_PKEY_free(pkey_pub);
                    EVP_PKEY_free(pkey_keygen);
                } else {
                    _test_case.test(not_supported, __FUNCTION__, "No OID registered for %s", alg.c_str());
                }
            });

            oqs.close(context);
        }
    }
    __finally2 {}
}
