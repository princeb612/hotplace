/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_mac.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2104 HMAC: Keyed-Hashing for Message Authentication
 *  RFC 4493 The AES-CMAC Algorithm
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

openssl_mac::openssl_mac() {}

return_t openssl_mac::hmac(const char* alg, const binary_t& key, const binary_t& input, binary_t& output) {
    return hmac(alg, key, input.data(), input.size(), output);
}

return_t openssl_mac::hmac(const char* alg, const binary_t& key, const byte_t* stream, size_t size, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;
    openssl_hash hash;

    __try2 {
        if (nullptr == alg || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = hash.open(&handle, alg, key.data(), key.size());
        if (errorcode_t::success == ret) {
            ret = hash.hash(handle, stream, size, output);
        }
        hash.close(handle);
    }
    __finally2 {}

    return ret;
}

return_t openssl_mac::hmac(hash_algorithm_t alg, const binary_t& key, const binary_t& input, binary_t& output) {
    return hmac(alg, key, input.data(), input.size(), output);
}

return_t openssl_mac::hmac(hash_algorithm_t alg, const binary_t& key, const byte_t* stream, size_t size, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;
    openssl_hash hash;

    __try2 {
        if (size && (nullptr == stream)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = hash.open(&handle, alg, key.data(), key.size());
        if (errorcode_t::success != ret) {
            __leave2;
        }
        hash.hash(handle, stream, size, output);
        hash.close(handle);
    }
    __finally2 {}

    return ret;
}

return_t openssl_mac::cmac(const char* alg, const binary_t& key, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == alg) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto hint = advisor->hintof_cipher(alg);
        if (nullptr == hint) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = cmac(hint->algorithm, key, input, output);
    }
    __finally2 {}

    return ret;
}

return_t openssl_mac::cmac(crypt_algorithm_t alg, const binary_t& key, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;

    /**
     * RFC 4615 Figure 1.  The AES-CMAC-PRF-128 Algorithm
     * Step 1.   If VKlen is equal to 16
     * Step 1a.  then
     *               K := VK;
     * Step 1b.  else
     *               K := AES-CMAC(0^128, VK, VKlen);
     * Step 2.   PRV := AES-CMAC(K, M, len);
     *           return PRV;
     *
     * PASSED
     *  RFC 4493 4.  Test Vectors
     *  RFC 4614 4.  Test Vectors
     */
    openssl_kdf kdf;
    ret = kdf.cmac_kdf_extract(output, alg, key, input);

    return ret;
}

return_t openssl_mac::cbc_mac(const char* alg, const binary_t& key, const binary_t& iv, const binary_t& input, binary_t& tag, size_t tagsize) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    __try2 {
        tag.resize(input.size() + EVP_MAX_BLOCK_LENGTH);

        if (nullptr == alg) {
            __leave2;
        }

        const EVP_CIPHER* cipher = advisor->find_evp_cipher(alg);
        if (nullptr == cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        const hint_blockcipher_t* hint_cipher = advisor->hintof_blockcipher(alg);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_CIPHER_CTX_ptr context(EVP_CIPHER_CTX_new());
        if (nullptr == context.get()) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        EVP_CipherInit_ex(context.get(), cipher, nullptr, key.data(), iv.data(), 1);
        EVP_CIPHER_CTX_set_padding(context.get(), 1);

        int size_update = 0;
        size_t size_input = input.size();
        uint16 blocksize = sizeof_block(hint_cipher);
        for (size_t i = 0; i < size_input; i += blocksize) {
            int remain = size_input - i;
            int size = (remain < blocksize) ? remain : blocksize;
            if (remain > blocksize) {
                EVP_CipherUpdate(context.get(), tag.data(), &size_update, &input[i], blocksize);
            } else {
                EVP_CipherUpdate(context.get(), tag.data(), &size_update, &input[i], remain);
                EVP_CipherUpdate(context.get(), tag.data(), &size_update, iv.data(), blocksize - remain);
            }
        }
        tag.resize(tagsize);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
