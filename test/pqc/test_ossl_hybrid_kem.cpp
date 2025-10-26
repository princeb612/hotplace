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

void test_ossl_hybrid_kem() {
    _test_case.begin("understanding Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3");

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    // Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3
    // https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/01/

    crypto_key key;
    crypto_keychain keychain;
    openssl_pqc pqc;

    binary_t keyshare_alice;
    binary_t keyshare_bob;
    EVP_PKEY* pubkey_mlkem768_alice = nullptr;
    EVP_PKEY* pubkey_x25519_alice = nullptr;
    EVP_PKEY* pubkey_x25519_bob = nullptr;
    /**
     * Key Share Entry: Group: X25519MLKEM768, Key Exchange length: 1216
     *     Group: X25519MLKEM768 (4588)
     *     Key Exchange Length: 1216
     *     Key Exchange […]: ...
     */

    __try2 {
        /**
         * 3.1.  Client share
         * client's ML-KEM-768 encapsulation key || the client's X25519 ephemeral share
         */

        // alice keygen, client hello
        {
            keychain.add_mlkem(&key, nid_mlkem768, keydesc("Alice MLKEM768"));
            keychain.add_ec2(&key, 1034, keydesc("Alice x25519"));
        }

        auto keypair_mlkem_alice = key.find("Alice MLKEM768");
        auto keypair_x25519_alice = key.find("Alice x25519");

        {
            binary_t keyenc_mlkem_alice;
            binary_t keyenc_x25519_alice;
            pqc.encode(nullptr, keypair_mlkem_alice, keyenc_mlkem_alice, key_encoding_pub_raw);
            pqc.encode(nullptr, keypair_x25519_alice, keyenc_x25519_alice, key_encoding_pub_raw);

            binary_append(keyshare_alice, keyenc_mlkem_alice);
            binary_append(keyshare_alice, keyenc_x25519_alice);
            _logger->hdump("keyshare", keyshare_alice);
            _test_case.assert(1184 + 32 == keyshare_alice.size(), __FUNCTION__, "alice keyshare");
        }

        /**
         * 3.2.  Server share
         * client's encapsulation key || server's ephemeral X25519 share
         */

        // bob server hello
        binary_t sharedsecret_x25519_bob;
        binary_t keyenc_x25519_bob;
        binary_t keycapsule;
        binary_t sharedsecret_mlkem_bob;
        binary_t sharedsecret_bob;
        {
            ret = pqc.decode(nullptr, "ML-KEM-768", &pubkey_mlkem768_alice, &keyshare_alice[0], 1184, key_encoding_pub_raw);
            _logger->write([&](basic_stream& dbs) -> void { dump_key(pubkey_mlkem768_alice, &dbs); });
            _test_case.test(ret, __FUNCTION__, "part of ML-KEM-768");

            ret = pqc.decode(nullptr, "x25519", &pubkey_x25519_alice, &keyshare_alice[1184], 32, key_encoding_pub_raw);
            _logger->write([&](basic_stream& dbs) -> void { dump_key(pubkey_x25519_alice, &dbs); });
            _test_case.test(ret, __FUNCTION__, "part of x25519");

            // keygen ephemeral
            keychain.add_ec2(&key, 1034, keydesc("Bob x25519"));
            auto keypairx_x25519_bob = key.find("Bob x25519");

            // ECDHE
            dh_key_agreement(keypairx_x25519_bob, pubkey_x25519_alice, sharedsecret_x25519_bob);
            binary_t temp;
            key.get_public_key(keypairx_x25519_bob, keyenc_x25519_bob, temp);

            // encaps
            pqc.encapsule(nullptr, pubkey_mlkem768_alice, keycapsule, sharedsecret_mlkem_bob);

            _logger->write([&](basic_stream& dbs) -> void {
                dbs.println("capsule key");
                dbs.println("%s", base16_encode(keycapsule).c_str());
                dbs.println("ephemeral share");
                dbs.println("%s", base16_encode(keyenc_x25519_bob).c_str());
                dbs.println("shared secret");
                dbs.println("%s", base16_encode(sharedsecret_mlkem_bob).c_str());
            });

            binary_append(keyshare_bob, keycapsule);
            binary_append(keyshare_bob, keyenc_x25519_bob);
            _test_case.assert(1088 + 32 == keyshare_bob.size(), __FUNCTION__, "bob keyshare");

            // 3.3.  Shared secret
            binary_append(sharedsecret_bob, sharedsecret_mlkem_bob);
            binary_append(sharedsecret_bob, sharedsecret_x25519_bob);
            _logger->writeln("bob's shared secret %s", base16_encode(sharedsecret_bob).c_str());
            _test_case.assert(32 + 32 == sharedsecret_bob.size(), __FUNCTION__, "shared secret");
        }

        // alice
        binary_t sharedsecret_mlkem_alice;
        binary_t sharedsecret_x25519_alice;
        binary_t sharedsecret_alice;
        {
            // decaps
            pqc.decapsule(nullptr, keypair_mlkem_alice, &keyshare_bob[0], 1088, sharedsecret_mlkem_alice);
            pqc.decode(nullptr, "x25519", &pubkey_x25519_bob, &keyshare_bob[1088], 32, key_encoding_pub_raw);
            dh_key_agreement(keypair_x25519_alice, pubkey_x25519_bob, sharedsecret_x25519_alice);

            // 3.3.  Shared secret
            binary_append(sharedsecret_alice, sharedsecret_mlkem_alice);
            binary_append(sharedsecret_alice, sharedsecret_x25519_alice);
            _logger->writeln("alice's shared secret %s", base16_encode(sharedsecret_alice).c_str());
            _test_case.assert(32 + 32 == sharedsecret_alice.size(), __FUNCTION__, "shared secret");
        }

        _test_case.assert(sharedsecret_alice == sharedsecret_bob, __FUNCTION__, "compare shared secret");
    }
    __finally2 {
        EVP_PKEY_free(pubkey_mlkem768_alice);
        EVP_PKEY_free(pubkey_x25519_alice);
        EVP_PKEY_free(pubkey_x25519_bob);
    }
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}
