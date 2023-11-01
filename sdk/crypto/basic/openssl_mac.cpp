/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 2104 HMAC: Keyed-Hashing for Message Authentication
 *  RFC 4493 The AES-CMAC Algorithm
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

openssl_mac::openssl_mac() : openssl_hash() {}

return_t openssl_mac::hmac(const char* alg, binary_t const& key, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg, &key[0], key.size());
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, &input[0], input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }

    return ret;
}

return_t openssl_mac::hmac(hash_algorithm_t alg, binary_t const& key, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg, &key[0], key.size());
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, &input[0], input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }

    return ret;
}

return_t openssl_mac::cmac(const char* alg, binary_t const& key, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg, &key[0], key.size());
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, &input[0], input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }

    return ret;
}

return_t openssl_mac::cmac(crypt_algorithm_t alg, crypt_mode_t mode, binary_t const& key, binary_t const& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    hash_context_t* handle = nullptr;

    __try2 {
        ret = open(&handle, alg, mode, &key[0], key.size());
        if (errorcode_t::success != ret) {
            __leave2;
        }
        init(handle);
        update(handle, &input[0], input.size());
        finalize(handle, output);
    }
    __finally2 { close(handle); }

    return ret;
}

return_t openssl_mac::cbc_mac(const char* alg, binary_t const& key, binary_t const& iv, binary_t const& input, binary_t& tag, size_t tagsize) {
    return_t ret = errorcode_t::success;
    EVP_CIPHER_CTX* context = nullptr;
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

        context = EVP_CIPHER_CTX_new();
        if (nullptr == context) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        EVP_CipherInit_ex(context, cipher, nullptr, &key[0], &iv[0], 1);
        EVP_CIPHER_CTX_set_padding(context, 1);

        int size_update = 0;
        size_t size_input = input.size();
        uint16 blocksize = sizeof_block(hint_cipher);
        uint32 unitsize = ossl_get_unitsize();
        size_t size_process = 0;
        for (size_t i = 0; i < size_input; i += blocksize) {
            int remain = size_input - i;
            int size = (remain < blocksize) ? remain : blocksize;
            EVP_CipherUpdate(context, &tag[0], &size_update, &input[i], size);
            size_process += size_update;
        }
        tag.resize(tagsize);
    }
    __finally2 {
        if (context) {
            EVP_CIPHER_CTX_free(context);
        }
    }
    return ret;
}

return_t openssl_mac::cbc_mac_rfc8152(const char* alg, binary_t const& key, binary_t const& iv, binary_t const& input, binary_t& tag, size_t tagsize) {
    return_t ret = errorcode_t::success;
    EVP_CIPHER_CTX* context = nullptr;
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

        context = EVP_CIPHER_CTX_new();
        if (nullptr == context) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        EVP_CipherInit_ex(context, cipher, nullptr, &key[0], &iv[0], 1);
        EVP_CIPHER_CTX_set_padding(context, 1);

        int size_update = 0;
        size_t size_input = input.size();
        uint16 blocksize = sizeof_block(hint_cipher);
        for (size_t i = 0; i < size_input; i += blocksize) {
            int remain = size_input - i;
            int size = (remain < blocksize) ? remain : blocksize;
            if (remain > blocksize) {
                EVP_CipherUpdate(context, &tag[0], &size_update, &input[i], blocksize);
            } else {
                EVP_CipherUpdate(context, &tag[0], &size_update, &input[i], remain);
                EVP_CipherUpdate(context, &tag[0], &size_update, &iv[0], blocksize - remain);
            }
        }
        tag.resize(tagsize);
    }
    __finally2 {
        if (context) {
            EVP_CIPHER_CTX_free(context);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
