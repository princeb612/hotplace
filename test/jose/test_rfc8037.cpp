/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_rfc8037() {
    print_text("RFC 8037");
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    json_web_key jwk;
    json_web_signature jws;
    std::string sample;
    crypto_key key;

    jwk.load_file(&key, key_ownspec, "rfc8037_A_ed25519.jwk");
    key.for_each(dump_crypto_key, nullptr);

    binary_t pub1;
    binary_t pub2;
    binary_t priv;
    const EVP_PKEY* pkey = key.any();
    key.get_key(pkey, pub1, pub2, priv);

    if (option.verbose) {
        _logger->writeln("x : %s", base16_encode(pub1).c_str());
        _logger->writeln("d : %s", base16_encode(priv).c_str());
    }

    // {"alg":"EdDSA"}
    std::string claim = "Example of Ed25519 signing";
    std::string signature;
    bool result = false;

    ret = jws.sign(&key, jws_t::jws_eddsa, claim, signature);
    dump("signature", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 8037 A.4.  Ed25519 Signing");

    ret = jws.verify(&key, signature, result);
    _test_case.test(ret, __FUNCTION__, "RFC 8037 A.5.  Ed25519 Validation");

    std::string signature_rfc8037_a5 =
        "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCj"
        "P0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_Mu"
        "M0KAg";
    ret = jws.verify(&key, signature_rfc8037_a5, result);
    dump("signature", signature);
    _test_case.test(ret, __FUNCTION__, "RFC 8037 A.5.  Ed25519 Validation");

    jose_context_t* handle = nullptr;
    std::string encrypted;
    binary_t source;
    json_object_signing_encryption jose;

    crypto_key jwk_x25519;
    jwk.load_file(&jwk_x25519, key_ownspec, "rfc8037_A_X25519.jwk");
    jwk_x25519.for_each(dump_crypto_key, nullptr);
    jose.open(&handle, &jwk_x25519);
    ret = jose.encrypt(handle, jwe_t::jwe_a128gcm, jwa_t::jwa_ecdh_es_a128kw, str2bin(claim), encrypted, jose_serialization_t::jose_flatjson);
    if (errorcode_t::success == ret) {
        dump("RFC 8037 A.6.  ECDH-ES with X25519", encrypted);
    }
    jose.close(handle);
    _test_case.test(ret, __FUNCTION__, "RFC 8037 A.6.  ECDH-ES with X25519");

    crypto_key jwk_x448;
    jwk.load_file(&jwk_x448, key_ownspec, "rfc8037_A_X448.jwk");
    jwk_x448.for_each(dump_crypto_key, nullptr);
    jose.open(&handle, &jwk_x448);
    ret = jose.encrypt(handle, jwe_t::jwe_a256gcm, jwa_t::jwa_ecdh_es_a256kw, str2bin(claim), encrypted, jose_serialization_t::jose_flatjson);
    if (errorcode_t::success == ret) {
        dump("RFC 8037 A.7.  ECDH-ES with X448", encrypted);
    }
    jose.close(handle);
    _test_case.test(ret, __FUNCTION__, "RFC 8037 A.7.  ECDH-ES with X448");
}

void test_okp() {
    print_text("JWE with OKP");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    crypto_key key;
    crypto_keychain keychain;
    bool result = true;
    jose_context_t* handle = nullptr;

    basic_stream bs;
    std::string claim;
    std::string encrypted;
    binary_t source;
    std::string signature;

    keychain.add_ec(&key, ec_x25519, keydesc("test1", crypto_use_t::use_enc));
    keychain.add_ec(&key, ec_ed25519, keydesc("test2", crypto_use_t::use_sig));
    keychain.add_ec(&key, ec_x448, keydesc("test3", crypto_use_t::use_enc));
    keychain.add_ec(&key, ec_ed448, keydesc("test4", crypto_use_t::use_sig));
    key.for_each(dump_crypto_key, nullptr);

    jose.open(&handle, &key);

    jwe_t encs[] = {
        jwe_t::jwe_a128cbc_hs256, jwe_t::jwe_a192cbc_hs384, jwe_t::jwe_a256cbc_hs512, jwe_t::jwe_a128gcm, jwe_t::jwe_a192gcm, jwe_t::jwe_a256gcm,
    };
    jwa_t algs[] = {
        jwa_t::jwa_ecdh_es,
        jwa_t::jwa_ecdh_es_a128kw,
        jwa_t::jwa_ecdh_es_a192kw,
        jwa_t::jwa_ecdh_es_a256kw,
    };

    crypto_advisor* advisor = crypto_advisor::get_instance();

    for (size_t i = 0; i < RTL_NUMBER_OF(encs); i++) {
        const char* nameof_enc = advisor->nameof_jose_encryption(encs[i]);
        for (size_t j = 0; j < RTL_NUMBER_OF(algs); j++) {
            ret = errorcode_t::success;
            const char* nameof_alg = advisor->nameof_jose_algorithm(algs[j]);
            claim = format("JWE with OKP enc %s alg %s", nameof_enc, nameof_alg);

            ret = jose.encrypt(handle, encs[i], algs[j], str2bin(claim), encrypted, jose_serialization_t::jose_flatjson);
            if (errorcode_t::success == ret) {
                dump("encrypted", encrypted);
                ret = jose.decrypt(handle, encrypted, source, result);
                if (errorcode_t::success == ret) {
                    dump2("decrypted", source);
                }
            }
            _test_case.test(ret, __FUNCTION__, "RFC 8037 JWE with OKP enc %s alg %s", nameof_enc, nameof_alg);
        }
    }

    ret = jose.sign(handle, jws_t::jws_eddsa, claim, signature, jose_serialization_t::jose_flatjson);
    if (errorcode_t::success == ret) {
        dump("signature", signature);
        ret = jose.verify(handle, signature, result);
        _test_case.test(ret, __FUNCTION__, "RFC 8037 JWS with OKP");
    }
    jose.close(handle);
}
