/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_rfc7518_RSASSA_PSS() {
    print_text("RFC 7518 3.5");
    constexpr byte_t ps256_header[] = "{\"alg\":\"PS256\"}";
    constexpr char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    return_t ret = errorcode_t::success;
    crypto_key key;
    json_web_key jwk;
    jwk.load_file(&key, key_ownspec, "rfc7515.jwk");
    key.for_each(dump_crypto_key, nullptr);

    json_web_signature jws;
    std::string signature;
    bool result = false;

    jws.sign(&key, (char*)ps256_header, claim, signature);
    ret = jws.verify(&key, signature, result);
    dump("JWS compact", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7518 3.5.  Digital Signature with RSASSA-PSS (JWS compact)");

    jws.sign(&key, (char*)ps256_header, claim, signature, jose_serialization_t::jose_flatjson);
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON flattened", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7518 3.5.  Digital Signature with RSASSA-PSS (JWS JSON flattened)");

    jws.sign(&key, (char*)ps256_header, claim, signature, jose_serialization_t::jose_json);
    ret = jws.verify(&key, signature, result);
    dump("JWS JSON serialization", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 7518 3.5.  Digital Signature with RSASSA-PSS (JWS JSON serialization)");
}

int test_ecdh() {
    crypto_key keys;
    crypto_keychain keyset;

    binary_t x_alice;
    binary_t y_alice;
    binary_t d_alice;
    binary_t x_bob;
    binary_t y_bob;
    binary_t d_bob;
    binary_t secret_alice;
    binary_t secret_bob;

    keyset.add_ec2(&keys, NID_secp384r1, keydesc("alice"));
    keyset.add_ec2(&keys, NID_secp384r1, keydesc("bob"));

    const EVP_PKEY* alicePrivateKey = keys.find("alice", crypto_kty_t::kty_ec);
    const EVP_PKEY* bobPrivateKey = keys.find("bob", crypto_kty_t::kty_ec);

    const EVP_PKEY* alicePublicKey = get_public_key(alicePrivateKey);
    const EVP_PKEY* bobPublicKey = get_public_key(bobPrivateKey);

    keys.get_public_key(alicePrivateKey, x_alice, y_alice);
    keys.get_private_key(alicePrivateKey, d_alice);
    keys.get_public_key(bobPrivateKey, x_bob, y_bob);
    keys.get_private_key(bobPrivateKey, d_bob);

    dh_key_agreement(alicePrivateKey, bobPublicKey, secret_alice);
    dh_key_agreement(bobPrivateKey, alicePublicKey, secret_bob);

    EVP_PKEY_free((EVP_PKEY*)alicePublicKey);
    EVP_PKEY_free((EVP_PKEY*)bobPublicKey);

    const OPTION& option = _cmdline->value();
    if (option.verbose) {
        _logger->writeln([&](basic_stream& bs) -> void {
            bs << "alice public key  x : " << base16_encode(x_alice) << "\n"
               << "alice public key  y : " << base16_encode(y_alice) << "\n"
               << "alice private key d : " << base16_encode(d_alice) << "\n"
               << "bob   public key  x : " << base16_encode(x_bob) << "\n"
               << "bob   public key  y : " << base16_encode(y_bob) << "\n"
               << "bob   private key d : " << base16_encode(d_bob) << "\n"

               << "secret computed by alice : " << base16_encode(secret_alice) << "\n"
               << "secret computed by bob   : " << base16_encode(secret_bob);
        });
    }

    bool result = (secret_alice == secret_bob);
    _test_case.test(result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__, "ECDH");
    return 0;
}

void test_rfc7518_C() {
    print_text("RFC 7518 Appendix C.  Example ECDH-ES Key Agreement Computation");

    json_web_key jwk;
    crypto_key key_alice;
    crypto_key key_bob;

    jwk.load_file(&key_alice, key_ownspec, "rfc7518_C_alice.jwk");
    jwk.load_file(&key_bob, key_ownspec, "rfc7518_C_bob.jwk");

    key_alice.for_each(dump_crypto_key, nullptr);
    key_bob.for_each(dump_crypto_key, nullptr);

    const EVP_PKEY* pkey_alice = key_alice.select(crypto_use_t::use_enc);
    const EVP_PKEY* pkey_bob = key_bob.select(crypto_use_t::use_enc);

    binary_t secret_bob;
    dh_key_agreement(pkey_bob, pkey_alice, secret_bob);

    _logger->writeln([&](basic_stream& bs) -> void {
        bs << "Z (ECDH-ES key agreement output) : \n" << base16_encode(secret_bob) << "\n";
#if __cplusplus >= 201103L  // c++11
        for_each(secret_bob.begin(), secret_bob.end(), [&](byte_t c) { bs.printf("%i,", c); });
#else
        for (binary_t::iterator iter = secret_bob.begin(); iter != secret_bob.end(); iter++) {
            byte_t c = *iter;
            bs.printf("%i,", c);
        }
#endif
    });

    // apu Alice
    // apv Bob
    constexpr char alg[] = "A128GCM";
    constexpr char apu[] = "Alice";
    constexpr char apv[] = "Bob";
    binary_t otherinfo;

    compose_otherinfo(alg, apu, apv, 16 << 3, otherinfo);

    dump2("otherinfo", otherinfo);
    dump_elem(otherinfo);

    binary_t derived;
    concat_kdf(secret_bob, otherinfo, 16, derived);

    dump2("derived", derived);
    dump_elem(derived);

    std::string sample = "VqqN6vgjbSBcIijNcacQGg";
    std::string computation = std::move(base64_encode(derived, encoding_t::encoding_base64url));
    _logger->writeln(computation);

    bool result = (sample == computation);
    _test_case.test(result ? errorcode_t::success : errorcode_t::internal_error, __FUNCTION__,
                    "RFC 7518 Appendix C.  Example ECDH-ES Key Agreement Computation");

    ecdh_es(pkey_bob, pkey_alice, alg, apu, apv, 16, derived);

    dump2("derived", derived);
    dump_elem(derived);
}
