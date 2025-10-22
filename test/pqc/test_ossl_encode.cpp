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

void test_ossl_encode() {
    _test_case.begin("understanding ML-KEM Post-Quantum Key Agreement for TLS 1.3");

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
            EVP_PKEY* pubkey = nullptr;
            EVP_PKEY* privkey = nullptr;
            EVP_PKEY* privkey_decoded = nullptr;
            binary_t keydata;
            bool is_keypair = false;

            // generate keypair
            ret = keychain.pkey_keygen_byname(nullptr, &privkey, alg.c_str());
            _test_case.test(ret, __FUNCTION__, "keygen %s", alg.c_str());

            is_keypair = keychain.pkey_is_private(nullptr, privkey);
            _test_case.assert(true == is_keypair, __FUNCTION__, "keypair");

            // private
            {
                // encode
                ret = keychain.pkey_encode(nullptr, privkey, keydata, key_encoding_priv_raw);
                if (option.dump_keys) {
                    _logger->writeln([&](basic_stream& bs) -> void {
                        bs << "DER\n";
                        base16_encode(keydata, &bs);
                    });
                }
                _test_case.test(ret, __FUNCTION__, "encode private key %s", alg.c_str());

                // decode
                ret = keychain.pkey_decode(nullptr, alg.c_str(), &privkey_decoded, keydata, key_encoding_priv_raw);
                _test_case.test(ret, __FUNCTION__, "decode private key %s", alg.c_str());
            }
            // public
            {
                ret = keychain.pkey_encode(nullptr, privkey, keydata, key_encoding_pub_raw);
                _test_case.test(ret, __FUNCTION__, "encode public key %s", alg.c_str());
                // key distribution
                ret = keychain.pkey_decode(nullptr, alg.c_str(), &pubkey, keydata, key_encoding_pub_raw);
                _test_case.test(ret, __FUNCTION__, "decode public key %s", alg.c_str());

                is_keypair = keychain.pkey_is_private(nullptr, pubkey);
                _test_case.assert(false == is_keypair, __FUNCTION__, "public key");
            }

            EVP_PKEY_free(pubkey);
            EVP_PKEY_free(privkey);
            EVP_PKEY_free(privkey_decoded);
        }
    }
    __finally2 {}
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}
