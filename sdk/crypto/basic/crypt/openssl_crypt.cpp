/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
 *  RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
 *  RFC 8017 PKCS #1: RSA Cryptography Specifications Version 2.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

openssl_crypt::openssl_crypt() {
    // do nothing
}

openssl_crypt::~openssl_crypt() {
    // do nothing
}

return_t openssl_crypt::open(crypt_context_t **handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv) {
    return open(handle, algorithm, mode, &key[0], key.size(), &iv[0], iv.size());
}

return_t openssl_crypt::open(crypt_context_t **handle, const char *cipher, const unsigned char *key, size_t size_key, const unsigned char *iv, size_t size_iv) {
    return_t ret = errorcode_t::success;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        const hint_cipher_t *hint = advisor->hintof_cipher(cipher);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
        } else {
            ret = open(handle, typeof_alg(hint), typeof_mode(hint), key, size_key, iv, size_iv);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_crypt::open(crypt_context_t **handle, const char *cipher, const binary_t &key, const binary_t &iv) {
    return_t ret = errorcode_t::success;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        const hint_cipher_t *hint = advisor->hintof_cipher(cipher);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
        } else {
            ret = open(handle, typeof_alg(hint), typeof_mode(hint), key, iv);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_crypt::encrypt(crypt_context_t *handle, const unsigned char *plaintext, size_t plainsize, unsigned char **ciphertext, size_t *ciphersize) {
    return_t ret = errorcode_t::success;
    byte_t *output_allocated = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == plaintext || nullptr == ciphertext || nullptr == ciphersize) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_out_allocated = plainsize + EVP_MAX_BLOCK_LENGTH;
        __try_new_catch(output_allocated, new byte_t[size_out_allocated + 1], ret, __leave2);

        ret = encrypt_internal(handle, plaintext, plainsize, output_allocated, &size_out_allocated, nullptr, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        output_allocated[size_out_allocated] = 0;

        *ciphertext = output_allocated;
        *ciphersize = size_out_allocated;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (output_allocated) {
                delete[] output_allocated;
            }
        }
    }

    return ret;
}

return_t openssl_crypt::encrypt(crypt_context_t *handle, const unsigned char *plaintext, size_t plainsize, binary_t &ciphertext) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_len = plainsize + EVP_MAX_BLOCK_LENGTH;
        ciphertext.resize(size_len);

        ret = encrypt_internal(handle, plaintext, plainsize, &ciphertext[0], &size_len);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ciphertext.resize(size_len);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            ciphertext.resize(0);
        }
    }

    return ret;
}

return_t openssl_crypt::encrypt(crypt_context_t *handle, const binary_t &plaintext, binary_t &ciphertext) {
    return encrypt(handle, &plaintext[0], plaintext.size(), ciphertext);
}

return_t openssl_crypt::encrypt(crypt_context_t *handle, const unsigned char *plaintext, size_t plainsize, binary_t &ciphertext, const binary_t &aad,
                                binary_t &tag) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_len = plainsize + EVP_MAX_BLOCK_LENGTH;
        ciphertext.resize(size_len);

        ret = encrypt_internal(handle, plaintext, plainsize, &ciphertext[0], &size_len, &aad, &tag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ciphertext.resize(size_len);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            ciphertext.resize(0);
        }
    }

    return ret;
}

return_t openssl_crypt::encrypt(crypt_context_t *handle, const binary_t &plaintext, binary_t &ciphertext, const binary_t &aad, binary_t &tag) {
    return encrypt(handle, &plaintext[0], plaintext.size(), ciphertext, aad, tag);
}

return_t openssl_crypt::decrypt(crypt_context_t *handle, const unsigned char *ciphertext, size_t ciphersize, unsigned char **plaintext, size_t *plainsize) {
    return_t ret = errorcode_t::success;
    byte_t *output_allocated = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == ciphertext || nullptr == plaintext || nullptr == plainsize) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_out_allocated = ciphersize + EVP_MAX_BLOCK_LENGTH;
        __try_new_catch(output_allocated, new byte_t[size_out_allocated + 1], ret, __leave2);

        ret = decrypt_internal(handle, ciphertext, ciphersize, output_allocated, &size_out_allocated, nullptr, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        output_allocated[size_out_allocated] = 0;

        *plaintext = output_allocated;
        *plainsize = size_out_allocated;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (output_allocated) {
                delete[] output_allocated;
            }
        }
    }

    return ret;
}

return_t openssl_crypt::decrypt(crypt_context_t *handle, const unsigned char *ciphertext, size_t ciphersize, binary_t &plaintext) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_len = ciphersize + EVP_MAX_BLOCK_LENGTH;
        plaintext.resize(size_len);

        ret = decrypt_internal(handle, ciphertext, ciphersize, &plaintext[0], &size_len);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        plaintext.resize(size_len);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            plaintext.resize(0);
        }
    }

    return ret;
}

return_t openssl_crypt::decrypt(crypt_context_t *handle, const binary_t &ciphertext, binary_t &plaintext) {
    return decrypt(handle, &ciphertext[0], ciphertext.size(), plaintext);
}

return_t openssl_crypt::decrypt(crypt_context_t *handle, const unsigned char *ciphertext, size_t ciphersize, binary_t &plaintext, const binary_t &aad,
                                const binary_t &tag) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_len = ciphersize + EVP_MAX_BLOCK_LENGTH;
        plaintext.resize(size_len);

        ret = decrypt_internal(handle, ciphertext, ciphersize, &plaintext[0], &size_len, &aad, &tag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        plaintext.resize(size_len);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            plaintext.resize(0);
        }
    }

    return ret;
}

return_t openssl_crypt::decrypt(crypt_context_t *handle, const binary_t &ciphertext, binary_t &plaintext, const binary_t &aad, const binary_t &tag) {
    return decrypt(handle, &ciphertext[0], ciphertext.size(), plaintext, aad, tag);
}

return_t openssl_crypt::free_data(unsigned char *data) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        delete[](data);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

crypt_poweredby_t openssl_crypt::get_type() { return crypt_poweredby_t::openssl; }

return_t openssl_crypt::encrypt(const char *alg, const binary_t &key, const binary_t &iv, const binary_t &plaintext, binary_t &ciphertext,
                                encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, alg, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = encrypt(crypt_handle, plaintext, ciphertext);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const binary_t &plaintext,
                                binary_t &ciphertext, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, algorithm, mode, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = encrypt(crypt_handle, plaintext, ciphertext);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::encrypt(const char *alg, const binary_t &key, const binary_t &iv, const binary_t &plaintext, binary_t &ciphertext, const binary_t &aad,
                                binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, alg, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = encrypt(crypt_handle, plaintext, ciphertext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::encrypt(const char *alg, const binary_t &key, const binary_t &iv, const unsigned char *plaintext, size_t plainsize,
                                binary_t &ciphertext, const binary_t &aad, binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, alg, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = encrypt(crypt_handle, plaintext, plainsize, ciphertext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const binary_t &plaintext,
                                binary_t &ciphertext, const binary_t &aad, binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, algorithm, mode, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = encrypt(crypt_handle, plaintext, ciphertext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}
return_t openssl_crypt::encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const unsigned char *plaintext,
                                size_t plainsize, binary_t &ciphertext, const binary_t &aad, binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, algorithm, mode, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = encrypt(crypt_handle, plaintext, plainsize, ciphertext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(const char *alg, const binary_t &key, const binary_t &iv, const binary_t &ciphertext, binary_t &plaintext,
                                encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, alg, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = decrypt(crypt_handle, ciphertext, plaintext);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const binary_t &ciphertext,
                                binary_t &plaintext, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, algorithm, mode, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = decrypt(crypt_handle, ciphertext, plaintext);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(const char *alg, const binary_t &key, const binary_t &iv, const binary_t &ciphertext, binary_t &plaintext, const binary_t &aad,
                                const binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, alg, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = decrypt(crypt_handle, ciphertext, plaintext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(const char *alg, const binary_t &key, const binary_t &iv, const unsigned char *ciphertext, size_t ciphersize,
                                binary_t &plaintext, const binary_t &aad, const binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, alg, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = decrypt(crypt_handle, ciphertext, ciphersize, plaintext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const binary_t &ciphertext,
                                binary_t &plaintext, const binary_t &aad, const binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, algorithm, mode, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = decrypt(crypt_handle, ciphertext, plaintext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const unsigned char *ciphertext,
                                size_t ciphersize, binary_t &plaintext, const binary_t &aad, const binary_t &tag, encrypt_option_t *options) {
    return_t ret = errorcode_t::success;
    crypt_context_t *crypt_handle = nullptr;

    __try2 {
        ret = open(&crypt_handle, algorithm, mode, key, iv);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (options) {
            for (encrypt_option_t *option = options; option->ctrl; option++) {
                set(crypt_handle, option->ctrl, option->value);
            }
        }

        ret = decrypt(crypt_handle, ciphertext, ciphersize, plaintext, aad, tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
