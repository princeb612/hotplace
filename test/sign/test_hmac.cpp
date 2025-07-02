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

void test_hash_hmac_sign() {
    _test_case.begin("digest sign/verify");
    const OPTION& option = _cmdline->value();

    return_t ret = errorcode_t::success;
    crypto_key key;
    crypto_keychain keychain;
    constexpr char key_source[] = "000102030405060708090a0b0c0d0e0f";
    // Rhapsody - Emerald Sword
    constexpr char in_source[] = "I crossed the valleys the dust of midlands / To search for the third key to open the gates";
    binary_t bin_key = std::move(base16_decode(key_source));
    binary_t bin_in = std::move(str2bin(in_source));

    keychain.add_oct_b16(&key, key_source, keydesc());
    binary_t result_hash;
    binary_t result_digest;

    if (option.verbose) {
        // source
        _logger->hdump("source", bin_in);
    }

    // openssl_hash hash
    {
        openssl_hash hash;
        hash_context_t* hash_context = nullptr;
        hash.open(&hash_context, hash_algorithm_t::sha2_256);
        ret = hash.hash(hash_context, &bin_in[0], bin_in.size(), result_hash);
        hash.close(hash_context);

        if (option.verbose) {
            _logger->hdump("hash", result_hash);
        }
    }
    _test_case.test(ret, __FUNCTION__, "openssl_sign");

    // EVP_Digest (hash)
    {
        unsigned int size = 32;
        result_digest.resize(size);
        EVP_Digest(&bin_in[0], bin_in.size(), &result_digest[0], &size, EVP_sha256(), nullptr);
        result_digest.resize(size);

        if (option.verbose) {
            _logger->hdump("Digest", result_digest);
        }
    }
    _test_case.assert(result_hash == result_digest, __FUNCTION__, "EVP_Digest");

    // openssl_hash hmac
    {
        binary_t result_hmac;
        openssl_hash hash;
        hash_context_t* hmac_context = nullptr;
        hash.open(&hmac_context, hash_algorithm_t::sha2_256, &bin_key[0], bin_key.size());
        ret = hash.hash(hmac_context, &bin_in[0], bin_in.size(), result_hmac);
        hash.close(hmac_context);

        if (option.verbose) {
            _logger->hdump("HMAC", result_hmac);
        }
    }
    _test_case.test(ret, __FUNCTION__, "HMAC");

    // openssl_sign
    {
        openssl_sign sign;
        binary_t signature;
        auto pkey = key.any();
        ret = sign.sign_hmac(pkey, hash_algorithm_t::sha2_256, bin_in, signature);
        if (option.verbose) {
            _logger->hdump("Sign", signature);
        }
        _test_case.test(ret, __FUNCTION__, "sign");

        ret = sign.verify_hmac(pkey, hash_algorithm_t::sha2_256, bin_in, signature);
        _test_case.test(ret, __FUNCTION__, "verify");
    }

    // JOSE
    {
        json_object_signing_encryption jose;
        jose_context_t* jose_context = nullptr;
        jose.open(&jose_context, &key);

        std::string signature;
        bool res = false;
        ;
        ret = jose.sign(jose_context, jws_t::jws_hs256, in_source, signature);
        _logger->writeln(signature);
        _test_case.test(ret, __FUNCTION__, "HS256 - Sign");
        ret = jose.verify(jose_context, signature, res);
        _test_case.test(ret, __FUNCTION__, "HS256 - Verify");

        jose.close(jose_context);
    }
}
