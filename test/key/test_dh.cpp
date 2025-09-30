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

// ECDH
void test_dh_rfc7748() {
    _test_case.begin("RFC 7748 6.  Diffie-Hellman");
    return_t ret = success;

    crypto_key key;
    crypto_keychain keychain;

    auto dump_crypto_key = [&](crypto_key_object* item, void*) -> void {
        basic_stream bs;
        bs.println("\e[1;32m> kid \"%s\"\e[0m", item->get_desc().get_kid_cstr());
        dump_key(item->get_pkey(), &bs, 16, 3, dump_notrunc);
        _logger->write(bs);
    };

    /**
     * 6.1.  Curve25519
     * Alice's private key, a:
     *   77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
     * Alice's public key, X25519(a, 9):
     *   8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
     * Bob's private key, b:
     *   5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
     * Bob's public key, X25519(b, 9):
     *   de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
     * Their shared secret, K:
     *   4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
     */
    {
        binary_t shared_secret1;
        binary_t shared_secret2;
        binary_t shared_secret_expected;

        const char* alice_priv = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        const char* alice_pub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        const char* bob_priv = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        const char* bob_pub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        const char* expect_shared_secret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

        keychain.add_ec_b16(&key, ec_x25519, nullptr, nullptr, alice_priv, keydesc("alice priv x25519"));
        keychain.add_ec_b16(&key, ec_x25519, alice_pub, nullptr, nullptr, keydesc("alice pub x25519"));
        keychain.add_ec_b16(&key, ec_x25519, nullptr, nullptr, bob_priv, keydesc("bob priv x25519"));
        keychain.add_ec_b16(&key, ec_x25519, bob_pub, nullptr, nullptr, keydesc("bob pub x25519"));

        key.for_each(dump_crypto_key, nullptr);

        auto pkey_alice_priv = key.find("alice priv x25519");
        auto pkey_alice_pub = key.find("alice pub x25519");
        auto pkey_bob_priv = key.find("bob priv x25519");
        auto pkey_bob_pub = key.find("bob pub x25519");

        dh_key_agreement(pkey_alice_priv, pkey_bob_pub, shared_secret1);
        dh_key_agreement(pkey_bob_priv, pkey_alice_pub, shared_secret2);

        _logger->writeln("shared %s", base16_encode(shared_secret1).c_str());

        shared_secret_expected = base16_decode(expect_shared_secret);
        _test_case.assert((shared_secret1 == shared_secret_expected) && (shared_secret1 == shared_secret2), __FUNCTION__, "RFC 7748 6.1.  Curve25519");
    }
    /**
     * 6.2.  Curve448
     * Alice's private key, a:
     *   9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d
     *   d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b
     * Alice's public key, X448(a, 5):
     *   9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c
     *   22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0
     * Bob's private key, b:
     *   1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d
     *   6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d
     * Bob's public key, X448(b, 5):
     *   3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430
     *   27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609
     * Their shared secret, K:
     *   07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b
     *   b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d
     */
    {
        binary_t shared_secret1;
        binary_t shared_secret2;
        binary_t shared_secret_expected;

        const char* alice_priv =
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
        const char* alice_pub =
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
        const char* bob_priv =
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
        const char* bob_pub =
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
        const char* expect_shared_secret =
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
            "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

        keychain.add_ec_b16(&key, ec_x448, nullptr, nullptr, alice_priv, keydesc("alice priv x448"));
        keychain.add_ec_b16(&key, ec_x448, alice_pub, nullptr, nullptr, keydesc("alice pub x448"));
        keychain.add_ec_b16(&key, ec_x448, nullptr, nullptr, bob_priv, keydesc("bob priv x448"));
        keychain.add_ec_b16(&key, ec_x448, bob_pub, nullptr, nullptr, keydesc("bob pub x448"));

        key.for_each(dump_crypto_key, nullptr);

        auto pkey_alice_priv = key.find("alice priv x448");
        auto pkey_alice_pub = key.find("alice pub x448");
        auto pkey_bob_priv = key.find("bob priv x448");
        auto pkey_bob_pub = key.find("bob pub x448");

        dh_key_agreement(pkey_alice_priv, pkey_bob_pub, shared_secret1);
        dh_key_agreement(pkey_bob_priv, pkey_alice_pub, shared_secret2);

        _logger->writeln("shared %s", base16_encode(shared_secret1).c_str());

        shared_secret_expected = base16_decode(expect_shared_secret);
        _test_case.assert((shared_secret1 == shared_secret_expected) && (shared_secret1 == shared_secret2), __FUNCTION__, "RFC 7748 6.2.  Curve448");
    }
}
