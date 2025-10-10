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

void test_ossl_kem() {
    _test_case.begin("openssl-3.5 KEM");

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        crypto_keychain keychain;
        openssl_pqc pqc;

        std::list<std::string> algs;
        algs.push_back("ML-KEM-512");
        algs.push_back("ML-KEM-768");
        algs.push_back("ML-KEM-1024");

        for (const auto& alg : algs) {
            EVP_PKEY* privkey = nullptr;
            EVP_PKEY* pubkey = nullptr;
            binary_t keydata;
            binary_t capsulekey;
            binary_t sharedsecret_alice;
            binary_t sharedsecret_bob;

            // generate keypair
            // https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/

            ret = keychain.pkey_gen_byname(&privkey, nullptr, alg.c_str());
            // "ML-KEM-512"    1454    EVP_PKEY_ML_KEM_512
            // "ML-KEM-768"    1455    EVP_PKEY_ML_KEM_768
            // "ML-KEM-1024"   1456    EVP_PKEY_ML_KEM_1024
            // _logger->writeln([&](basic_stream& bs) -> void {
            //     // EVP_PKEY_id          -1
            //     // EVP_PKEY_get_base_id  0
            //     auto type = EVP_PKEY_id(privkey);
            //     bs.printf("type %i", type);
            // });
            _test_case.test(ret, __FUNCTION__, "keygen %s", alg.c_str());

            // key distribution
            {
                ret = keychain.pkey_encode(nullptr, privkey, keydata, key_encoding_pub_der);
                _test_case.test(ret, __FUNCTION__, "encode public key %s", alg.c_str());

                ret = keychain.pkey_decode(nullptr, &pubkey, keydata, key_encoding_pub_der);
                _test_case.test(ret, __FUNCTION__, "decode public key %s", alg.c_str());
            }
            // encapsule
            {
                ret = pqc.encapsule(nullptr, pubkey, capsulekey, sharedsecret_bob);
                _logger->write([&](basic_stream& bs) -> void {
                    bs << "capsule";
                    base16_encode(capsulekey, &bs, base16_notrunc);
                    bs << "\n";
                    bs << "shared secret";
                    base16_encode(sharedsecret_bob, &bs, base16_notrunc);
                    bs << "\n";
                });
                _test_case.test(ret, __FUNCTION__, "encapsule %s", alg.c_str());
            }
            // decapsule
            {
                ret = pqc.decapsule(nullptr, privkey, capsulekey, sharedsecret_alice);
                _logger->write([&](basic_stream& bs) -> void {
                    bs << "shared secret\n";
                    base16_encode(sharedsecret_alice, &bs, base16_notrunc);
                    bs << "\n";
                });
                _test_case.test(ret, __FUNCTION__, "decapsule %s", alg.c_str());
            }

            _logger->writeln([&](basic_stream& bs) -> void { base16_encode(sharedsecret_alice, &bs); });
            _test_case.assert(sharedsecret_alice == sharedsecret_bob, __FUNCTION__, "compare shared secret");

            EVP_PKEY_free(pubkey);
            EVP_PKEY_free(privkey);
        }
    }
    __finally2 {}
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}
