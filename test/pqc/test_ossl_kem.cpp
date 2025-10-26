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
            EVP_PKEY* privkey = nullptr;
            EVP_PKEY* pubkey = nullptr;
            EVP_PKEY* pubkey_raw = nullptr;
            binary_t keydata;
            binary_t keycapsule;
            binary_t sharedsecret_alice;
            binary_t sharedsecret_bob;

            // alice : generate keypair
            // https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/

            ret = keychain.pkey_keygen_byname(nullptr, &privkey, alg.c_str());
            _logger->writeln([&](basic_stream& bs) -> void {
                // EVP_PKEY_id          -1
                // EVP_PKEY_get_base_id  0
                auto type = EVP_PKEY_id(privkey);
                if (EVP_PKEY_KEYMGMT == type) {
                    // provider-specific if -1 (check EVP_PKEY_get0_type_name or EVP_PKEY_is_a)
                    auto name = EVP_PKEY_get0_type_name(privkey);
                    bs << "type " << name << " " << OBJ_txt2nid(name);
                } else {
                    bs.printf("type %i", type);
                }
            });
            _test_case.test(ret, __FUNCTION__, "keygen %s", alg.c_str());

            // alice -> bob : key distribution (DER)
            {
                ret = keychain.pkey_encode(nullptr, privkey, keydata, key_encoding_pub_der);
                _test_case.test(ret, __FUNCTION__, "DER encode public key %s size %zi", alg.c_str(), keydata.size());

                ret = keychain.pkey_decode(nullptr, &pubkey, keydata, key_encoding_pub_der);
                _test_case.test(ret, __FUNCTION__, "DER decode public key %s size %zi", alg.c_str(), keydata.size());
            }
            // alice -> bob : key distribution (TLS 1.3)
            {
                ret = keychain.pkey_encode_raw(nullptr, privkey, keydata, key_encoding_pub_raw);
                _test_case.test(ret, __FUNCTION__, "RAW encode public key %s size %zi", alg.c_str(), keydata.size());

                ret = keychain.pkey_decode_raw(nullptr, alg.c_str(), &pubkey_raw, keydata, key_encoding_pub_raw);
                _test_case.test(ret, __FUNCTION__, "RAW decode public key %s size %zi", alg.c_str(), keydata.size());

                _test_case.assert(EVP_PKEY_eq(pubkey, pubkey_raw), __FUNCTION__, "EVP_PKEY_eq");
            }
            // bob : encapsule
            {
                ret = pqc.encapsule(nullptr, pubkey, keycapsule, sharedsecret_bob);
                _logger->write([&](basic_stream& bs) -> void {
                    bs << "capsule ";
                    base16_encode(keycapsule, &bs, base16_notrunc);
                    bs << "\n";
                    bs << "shared secret ";
                    base16_encode(sharedsecret_bob, &bs, base16_notrunc);
                    bs << "\n";
                });
                _test_case.test(ret, __FUNCTION__, "encapsule %s size %zi", alg.c_str(), keycapsule.size());
            }
            // alice : decapsule
            {
                ret = pqc.decapsule(nullptr, privkey, keycapsule, sharedsecret_alice);
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
            EVP_PKEY_free(pubkey_raw);
            EVP_PKEY_free(privkey);
        }
    }
    __finally2 {}
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}
