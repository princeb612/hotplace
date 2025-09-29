/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/pqc.hpp>

#include "sample.hpp"

// install oqsprovider.dll into ossl-modules

void test_kem() {
    _test_case.begin("KEM");
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        oqs_context* context = nullptr;
        pqc_oqs oqs;

        ret = oqs.open(&context);
        _test_case.test(ret, __FUNCTION__, "load oqsprovider");
        if (errorcode_t::success == ret) {
            // p256_mlkem512, x25519_mlkem512 : OID registered only
            oqs.for_each(context, OSSL_OP_KEM, [&](const std::string& alg) -> void {
                _logger->writeln("KEM algorithm : %s", alg.c_str());

                if (OBJ_sn2nid(alg.c_str())) {
                    EVP_PKEY* pkey = nullptr;
                    binary_t capsulekey;
                    binary_t sharedsecret;
                    binary_t pubkey;
                    auto encoding = oqs_key_encoding_pub_der;

                    // generate keypair
                    oqs.keygen(context, alg.c_str(), &pkey);
                    _test_case.assert(nullptr != pkey, __FUNCTION__, "keygen %s", alg.c_str());

                    // public key
                    ret = oqs.encode_key(context, pkey, pubkey, encoding);
                    _logger->writeln("pub key %s", base16_encode(pubkey).c_str());
                    _test_case.test(ret, __FUNCTION__, "public key %s", alg.c_str());

                    // key distribution
                    EVP_PKEY* pk = nullptr;
                    ret = oqs.decode_key(context, &pk, pubkey, encoding);
                    _test_case.test(ret, __FUNCTION__, "distribute public key %s", alg.c_str());

                    if (errorcode_t::success == ret) {
                        // encapsulate using public key
                        ret = oqs.encapsule(context, pk, capsulekey, sharedsecret);
                        if (option.is_loglevel_debug()) {
                            _logger->hdump("encapsulated key", capsulekey, 16, 3);
                            _logger->hdump("shared secret", sharedsecret, 16, 3);
                        }
                        _test_case.test(ret, __FUNCTION__, "encapsulate %s", alg.c_str());

                        // decapsulate using private key
                        binary_t sharedsecret2;
                        ret = oqs.decapsule(context, pkey, capsulekey, sharedsecret2);
                        _test_case.test(ret, __FUNCTION__, "decapsulate %s", alg.c_str());
                        _test_case.assert(sharedsecret == sharedsecret2, __FUNCTION__, "compare");
                    }

                    EVP_PKEY_free(pkey);
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
