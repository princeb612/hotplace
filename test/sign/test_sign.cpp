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
    const OPTION& option = _cmdline->value();

    crypto_key key;
    crypto_keychain keychain;
    constexpr char key_source[] = "000102030405060708090a0b0c0d0e0f";
    // Rhapsody - Emerald Sword
    constexpr char in_source[] = "I crossed the valleys the dust of midlands / To search for the third key to open the gates";
    binary_t bin_key = base16_decode(key_source);
    binary_t bin_in = str2bin(in_source);

    keychain.add_oct_b16(&key, key_source, keydesc());
    binary_t result;

    openssl_hash hash;
    openssl_sign sign;

    if (option.verbose) {
        // source
        _logger->hdump("source", bin_in);
    }

    // openssl_hash hash
    hash_context_t* hash_context = nullptr;
    hash.open(&hash_context, hash_algorithm_t::sha2_256);
    hash.hash(hash_context, &bin_in[0], bin_in.size(), result);
    hash.close(hash_context);

    if (option.verbose) {
        _logger->hdump("hash", result);
    }

    // EVP_Digest (hash)
    unsigned int size = 0;
    result.resize(0);
    EVP_Digest(&bin_in[0], bin_in.size(), &result[0], &size, EVP_sha256(), nullptr);
    result.resize(size);
    EVP_Digest(&bin_in[0], bin_in.size(), &result[0], &size, EVP_sha256(), nullptr);

    if (option.verbose) {
        _logger->hdump("Digest", result);
    }

    // openssl_hash hmac
    hash_context_t* hmac_context = nullptr;
    hash.open(&hmac_context, hash_algorithm_t::sha2_256, &bin_key[0], bin_key.size());
    hash.hash(hmac_context, &bin_in[0], bin_in.size(), result);
    hash.close(hmac_context);

    if (option.verbose) {
        _logger->hdump("HMAC", result);
    }

    // openssl_sign
    sign.sign_digest(key.any(), hash_algorithm_t::sha2_256, bin_key, result);

    if (option.verbose) {
        _logger->hdump("Sign", result);
    }
}
