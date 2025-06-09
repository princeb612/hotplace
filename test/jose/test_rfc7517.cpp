/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_rfc7517_C() {
    print_text("RFC 7517 C");

    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    json_web_key jwk;
    crypto_key key;
    crypto_keychain keygen;
    jose_context_t* context = nullptr;
    std::string output;
    binary_t plain;
    bool result = false;

    jwk.load_file(&key, key_ownspec, "rfc7517_C.jwk");
    key.for_each(dump_crypto_key, nullptr);

    std::string input = "The true sign of intelligence is not knowledge but imagination.";
    constexpr char passphrase[] = "Thus from my lips, by yours, my sin is purged.";
    keygen.add_oct(&key, jwa_t::jwa_pbes2_hs256_a128kw, str2bin(passphrase), keydesc(crypto_use_t::use_enc));

    jose.open(&context, &key);
    jose.encrypt(context, jwe_t::jwe_a128cbc_hs256, jwa_t::jwa_pbes2_hs256_a128kw, str2bin(input), output, jose_serialization_t::jose_compact);
    ret = jose.decrypt(context, output, plain, result);
    jose.close(context);

    dump("decrypted", output);
    _test_case.test(ret, __FUNCTION__, "RFC 7517 Appendix C. Encrypted RSA Private Key");
}
