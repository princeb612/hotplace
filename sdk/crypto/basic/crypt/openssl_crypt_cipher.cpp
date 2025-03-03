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

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

#define CRYPT_MAX_KEYSIZE 512  // 2^9 << 3 = 4096
#define OPENSSL_CRYPT_CONTEXT_SIGNATURE 0x20090419

enum openssl_crypt_flag_t {
    crypt_blockcipher_padding = (1 << 0),
};

typedef struct _openssl_crypt_context_t : public crypt_context_t {
    uint32 signature;
    crypt_poweredby_t crypto_type;  // see crypt_poweredby_t
    crypt_algorithm_t algorithm;    // see crypt_algorithm_t
    crypt_mode_t mode;              // see crypt_mode_t
    EVP_CIPHER_CTX *encrypt_context;
    EVP_CIPHER_CTX *decrypt_context;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX encrypt_context2;
    EVP_CIPHER_CTX decrypt_context2;
#endif
    crypto_key *key;
    crypt_datamap_t datamap;
    crypt_variantmap_t variantmap;
    uint32 flag;
    uint16 lsize;
    uint16 tsize;
    binary_t mac;  // last block

    _openssl_crypt_context_t()
        : signature(0),
          crypto_type(crypt_poweredby_t::openssl),
          algorithm(crypt_algorithm_t::crypt_alg_unknown),
          mode(crypt_mode_t::mode_unknown),
          encrypt_context(nullptr),
          decrypt_context(nullptr),
          key(nullptr),
          flag(openssl_crypt_flag_t::crypt_blockcipher_padding),
          lsize(0),
          tsize(0) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        encrypt_context = EVP_CIPHER_CTX_new();
        decrypt_context = EVP_CIPHER_CTX_new();
#else
        memset(&encrypt_context2, 0, sizeof(EVP_CIPHER_CTX));
        memset(&decrypt_context2, 0, sizeof(EVP_CIPHER_CTX));
        encrypt_context = &encrypt_context2;
        decrypt_context = &decrypt_context2;
#endif
    }

    ~_openssl_crypt_context_t() {
        auto lambda_data = [](std::pair<const crypt_item_t, binary_t> &item) {
            binary_t &data = item.second;
            std::fill(data.begin(), data.end(), 0);
        };
        auto lambda_variant = [](std::pair<const crypt_item_t, variant_t> &item) { item.second.data.i64 = 0; };
        for_each(datamap.begin(), datamap.end(), lambda_data);
        for_each(variantmap.begin(), variantmap.end(), lambda_variant);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free(encrypt_context);
        EVP_CIPHER_CTX_free(decrypt_context);
#else
        memset(&encrypt_context2, 0, sizeof(EVP_CIPHER_CTX));
        memset(&decrypt_context2, 0, sizeof(EVP_CIPHER_CTX));
#endif
    }

} openssl_crypt_context_t;

return_t openssl_crypt::open(crypt_context_t **handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const unsigned char *key, unsigned size_key,
                             const unsigned char *iv, unsigned size_iv) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = nullptr;
    int ret_init = 0;
    binary_t temp_key;
    binary_t temp_iv;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const EVP_CIPHER *cipher = advisor->find_evp_cipher(algorithm, mode);
        if (nullptr == cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        __try_new_catch(context, new openssl_crypt_context_t, ret, __leave2);

        uint32 internal_size_key = 0;
        uint32 internal_size_iv = 0;

        context->signature = OPENSSL_CRYPT_CONTEXT_SIGNATURE;
        context->crypto_type = crypt_poweredby_t::openssl;
        context->algorithm = algorithm;
        context->mode = mode;

        EVP_CIPHER_CTX_init(context->encrypt_context);
        EVP_CIPHER_CTX_init(context->decrypt_context);

        if (crypt_mode_t::wrap == mode) { /* A128KW, A192KW, A256KW*/
            EVP_CIPHER_CTX_set_flags(context->encrypt_context, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            EVP_CIPHER_CTX_set_flags(context->decrypt_context, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        }

        /*
         * openssl-1.0.2k
         * EVP_CipherInit   (&context->encrypt_context, EVP_aes_128_wrap(),          nullptr, nullptr, 1); // error
         * EVP_CipherInit_ex(&context->encrypt_context, EVP_aes_128_wrap(), nullptr, nullptr, nullptr, 1); // success
         */

        ret_init = EVP_CipherInit_ex(context->encrypt_context, cipher, nullptr, nullptr, nullptr, 1);
        ret_init = EVP_CipherInit_ex(context->decrypt_context, cipher, nullptr, nullptr, nullptr, 0);

        /* EVP_CIPHER_CTX_key_length, EVP_CIPHER_CTX_iv_length
         * [openssl 3.0.3] compatibility problem
         * EVP_CIPHER_..._length return EVP_CTRL_RET_UNSUPPORTED(-1)
         */

        internal_size_key = EVP_CIPHER_CTX_key_length(context->encrypt_context);
        adjust_range(internal_size_key, 0, EVP_MAX_KEY_LENGTH);
        temp_key.resize(internal_size_key);
        memcpy(&temp_key[0], key, (size_key > internal_size_key ? internal_size_key : size_key));

        // EVP_CIPHER_get_iv_length { return cipher(nullptr)->iv_len; }
        internal_size_iv = EVP_MAX_IV_LENGTH;
        adjust_range(internal_size_iv, 0, EVP_MAX_IV_LENGTH);
        temp_iv.resize(internal_size_iv);
        memcpy(&temp_iv[0], iv, (size_iv > internal_size_iv ? internal_size_iv : size_iv));

        context->datamap.insert(std::make_pair(crypt_item_t::item_cek, temp_key));
        context->datamap.insert(std::make_pair(crypt_item_t::item_iv, temp_iv));

        /* key, iv */
        /* encrypt and decrypt re-initialize iv */
        ret_init = EVP_CipherInit_ex(context->encrypt_context, cipher, nullptr, &temp_key[0], nullptr, 1);
        if (1 != ret_init) {
            ret = errorcode_t::bad_request;
            __leave2_trace_openssl(ret);
        }
        ret_init = EVP_CipherInit_ex(context->decrypt_context, cipher, nullptr, &temp_key[0], nullptr, 0);
        if (1 != ret_init) {
            ret = errorcode_t::bad_request;
            __leave2_trace_openssl(ret);
        }

        /* ECB, CBC */
        EVP_CIPHER_CTX_set_padding(context->encrypt_context, 1);
        EVP_CIPHER_CTX_set_padding(context->decrypt_context, 1);

        if (ccm8 == mode) {
            context->tsize = 8;
        }

        *handle = context;
    }
    __finally2 {
        std::fill(temp_key.begin(), temp_key.end(), 0);
        std::fill(temp_iv.begin(), temp_iv.end(), 0);

        if (errorcode_t::success != ret) {
            if (nullptr != context) {
                EVP_CIPHER_CTX_cleanup(context->encrypt_context);
                EVP_CIPHER_CTX_cleanup(context->decrypt_context);
                context->signature = 0;
                delete context;
            }
        }
    }

    return ret;
}

return_t openssl_crypt::close(crypt_context_t *handle) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = static_cast<openssl_crypt_context_t *>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (OPENSSL_CRYPT_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (context->key) {
            context->key->release();
        }

        EVP_CIPHER_CTX_cleanup(context->encrypt_context);
        EVP_CIPHER_CTX_cleanup(context->decrypt_context);

        delete context;
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t openssl_crypt::set(crypt_context_t *handle, crypt_ctrl_t id, uint16 param) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = static_cast<openssl_crypt_context_t *>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (id) {
            case crypt_ctrl_t::crypt_ctrl_padding:
                if (param) {
                    context->flag |= openssl_crypt_flag_t::crypt_blockcipher_padding;
                } else {
                    context->flag &= ~openssl_crypt_flag_t::crypt_blockcipher_padding;
                }
                break;
            case crypt_ctrl_t::crypt_ctrl_lsize:
                context->lsize = param;
                break;
            case crypt_ctrl_t::crypt_ctrl_tsize:
                context->tsize = param;
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_crypt::encrypt_internal(crypt_context_t *handle, const unsigned char *plaintext, size_t plainsize, unsigned char *ciphertext,
                                         size_t *ciphersize, const binary_t *aad, binary_t *tag) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = static_cast<openssl_crypt_context_t *>(handle);

    __try2 {
        if (nullptr == handle || nullptr == ciphersize) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == plaintext) {
            if (plainsize) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }
        if (OPENSSL_CRYPT_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        size_t size_expect = plainsize + EVP_MAX_BLOCK_LENGTH;
        if (*ciphersize < size_expect) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }

        EVP_CIPHER_CTX_set_padding(context->encrypt_context, context->flag & openssl_crypt_flag_t::crypt_blockcipher_padding ? 1 : 0);

        int ret_cipher = 0;
        int size_update = 0;
        int size_final = 0;
        int tag_size = 0;
        binary_t &iv = context->datamap[crypt_item_t::item_iv];

        EVP_CipherInit(context->encrypt_context, nullptr, nullptr, &iv[0], 1);

        bool is_aead = false;
        switch (context->mode) {
            case crypt_mode_t::gcm:
            case crypt_mode_t::mode_poly1305:
                is_aead = true;
                break;
            case crypt_mode_t::ccm:
            case crypt_mode_t::ccm8:
                is_aead = true;
                /**
                 * word-around related to aes-128-ccm
                 *   aes-128-ccm-encrypt(nullptr, 0, ciphertext, aad, tag)   // fail
                 *      EVP_CipherUpdate success                             // success
                 *      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag) // fail
                 *   aes-128-ccm-encrypt("", 0, ciphertext, aad, tag)        // success
                 *      EVP_CipherUpdate success                             // success
                 *      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag) // success
                 */
                if ((nullptr == plaintext) && (0 == plainsize)) {
                    plaintext = (const byte_t *)"";
                }
                break;
            default:
                break;
        }

        if (is_aead) {
            if ((nullptr == aad) || (nullptr == tag)) {
                ret = errorcode_t::invalid_parameter;
                __leave2_trace(ret);
            }

            /*
             * https://www.openssl.org/docs/man1.1.1/man3/EVP_CIPHER_iv_length.html
             * EVP_CTRL_CCM_SET_L
             *      If not set a default is used (8 for AES CCM).
             * EVP_CTRL_AEAD_SET_IVLEN
             *      For GCM AES and OCB AES the default is 12 (i.e. 96 bits)
             *      The nonce length is given by 15 - L so it is 7 by default for AES CCM.
             *       If not called a default nonce length of 12 (i.e. 96 bits) is used. (ChaCha20-Poly1305)
             * EVP_CTRL_AEAD_SET_TAG
             *      If not set a default value is used (12 for AES CCM)
             *      For OCB AES, the default tag length is 16 (i.e. 128 bits).
             */

            if ((crypt_mode_t::gcm == context->mode) || (crypt_mode_t::mode_poly1305 == context->mode)) {
                /*
                 * 16bytes (128bits)
                 * RFC 7516
                 *      Perform authenticated encryption on the plaintext with the AES GCM
                 *      algorithm using the CEK as the encryption key, the JWE
                 *      Initialization Vector, and the Additional Authenticated Data
                 *      value, requesting a 128-bit Authentication Tag output.
                 *
                 *      B.7.  Truncate HMAC Value to Create Authentication Tag
                 *      Use the first half (128 bits) of the HMAC output M as the
                 *      Authentication Tag output T.
                 *
                 * RFC 7539 2.5.  The Poly1305 Algorithm
                 *      Poly1305 takes a 32-byte one-time key and a message and produces a 16-byte tag.
                 *
                 * RFC 8152 10.1.  AES GCM
                 * the size of the authentication tag is fixed at 128 bits
                 */
                tag_size = context->tsize ? context->tsize : 16;
            } else if ((crypt_mode_t::ccm == context->mode) || (crypt_mode_t::ccm8 == context->mode)) {
                tag_size = context->tsize ? context->tsize : 14;
                uint16 lsize = context->lsize ? context->lsize : 8;
                uint16 nonce_size = 15 - lsize;

                EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_CCM_SET_L, lsize, nullptr);
                // EVP_CTRL_CCM_SET_IVLEN for Nonce (15-L)
                EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_CCM_SET_IVLEN, nonce_size, nullptr);
                EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_AEAD_SET_TAG, tag_size, nullptr);

                binary_t &key = context->datamap[crypt_item_t::item_cek];
                EVP_CipherInit_ex(context->encrypt_context, nullptr, nullptr, &key[0], &iv[0], 1);

                ret_cipher = EVP_CipherUpdate(context->encrypt_context, nullptr, &size_update, nullptr, plainsize);
                if (1 > ret_cipher) {
                    ret = errorcode_t::internal_error;
                    __leave2_trace_openssl(ret);
                }
            }

            ret_cipher = EVP_CipherUpdate(context->encrypt_context, nullptr, &size_update, &(*aad)[0], aad->size());
            if (1 > ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        uint32 cooltime = ossl_get_cooltime();
        switch (context->mode) {
            case crypt_mode_t::ccm:
            case crypt_mode_t::wrap:
                cooltime = 0;
                break;
            default:
                break;
        }

        if (cooltime) {
            // stability

            /*
             * check hints for block ciphers
             * EVP_CIPHER_get_block_size, EVP_CIPHER_CTX_get_block_size works wrong (CFB, OFB)
             */
            crypto_advisor *advisor = crypto_advisor::get_instance();
            const hint_blockcipher_t *hint_cipher = advisor->hintof_blockcipher(context->algorithm);
            if (nullptr == hint_cipher) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            uint16 blocksize = sizeof_block(hint_cipher);
            uint32 unitsize = ossl_get_unitsize();
            size_t size_progress = 0;
            size_t size_process = 0;
            for (size_t i = 0; i < plainsize; i += blocksize) {
                int remain = plainsize - i;
                int size = (remain < blocksize) ? remain : blocksize;
                EVP_CipherUpdate(context->encrypt_context, ciphertext + size_progress, &size_update, plaintext + i, size);
                size_progress += size_update;
                size_process += size_update;
                if (size_process > unitsize) {
                    msleep(cooltime);
                    size_process = 0;
                }
            }
            size_update = size_progress;
        } else {
            // performance

            ret_cipher = EVP_CipherUpdate(context->encrypt_context, ciphertext, &size_update, plaintext, plainsize);
            if (1 > ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_cipher = EVP_CipherFinal(context->encrypt_context, ciphertext + size_update, &size_final);
        if (1 > ret_cipher) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        if (is_aead) {
            tag->resize(tag_size);
            ret_cipher = EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_AEAD_GET_TAG, tag->size(), &(*tag)[0]);
            if (1 > ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        *ciphersize = (size_update + size_final);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (ciphersize) {
                *ciphersize = 0;
            }
        }
    }

    return ret;
}

return_t openssl_crypt::decrypt_internal(crypt_context_t *handle, const unsigned char *ciphertext, size_t ciphersize, unsigned char *plaintext,
                                         size_t *plainsize, const binary_t *aad, const binary_t *tag) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = static_cast<openssl_crypt_context_t *>(handle);

    __try2 {
        if (nullptr == handle || nullptr == plainsize) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == ciphertext) {
            if (ciphersize) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
        }
        if (OPENSSL_CRYPT_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        size_t size_necessary = ciphersize + EVP_MAX_BLOCK_LENGTH;
        if (*plainsize < size_necessary) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }

        EVP_CIPHER_CTX_set_padding(context->decrypt_context, context->flag & openssl_crypt_flag_t::crypt_blockcipher_padding ? 1 : 0);

        int ret_cipher = 0;
        int size_update = 0;
        int size_final = 0;
        binary_t &iv = context->datamap[crypt_item_t::item_iv];

        EVP_CipherInit(context->decrypt_context, nullptr, nullptr, &iv[0], 0);

        bool is_aead = false;
        switch (context->mode) {
            case crypt_mode_t::gcm:
            case crypt_mode_t::ccm:
            case crypt_mode_t::ccm8:
            case crypt_mode_t::mode_poly1305:
                is_aead = true;
                break;
            default:
                break;
        }

        if (is_aead) {
            if ((nullptr == aad) || (nullptr == tag)) {
                ret = errorcode_t::invalid_parameter;
                __leave2_trace(ret);
            }

            if ((crypt_mode_t::ccm) == context->mode || (crypt_mode_t::ccm8 == context->mode)) {
                uint16 lsize = context->lsize ? context->lsize : 8;
                uint16 nonce_size = 15 - lsize;

                EVP_CIPHER_CTX_ctrl(context->decrypt_context, EVP_CTRL_CCM_SET_L, lsize, nullptr);
                // EVP_CTRL_CCM_SET_IVLEN for Nonce (15-L)
                EVP_CIPHER_CTX_ctrl(context->decrypt_context, EVP_CTRL_CCM_SET_IVLEN, nonce_size, nullptr);
                EVP_CIPHER_CTX_ctrl(context->decrypt_context, EVP_CTRL_AEAD_SET_TAG, tag->size(), (void *)&(*tag)[0]);

                binary_t &key = context->datamap[crypt_item_t::item_cek];
                EVP_CipherInit_ex(context->decrypt_context, nullptr, nullptr, &key[0], &iv[0], 0);

                ret_cipher = EVP_CipherUpdate(context->decrypt_context, nullptr, &size_update, nullptr, ciphersize);
            } else if (crypt_mode_t::gcm == context->mode || crypt_mode_t::mode_poly1305 == context->mode) {
                ret_cipher = EVP_CIPHER_CTX_ctrl(context->decrypt_context, EVP_CTRL_AEAD_SET_TAG, tag->size(), (void *)&(*tag)[0]);
                if (1 != ret_cipher) {
                    ret = errorcode_t::internal_error;
                    __leave2_trace_openssl(ret);
                }
            }

            ret_cipher = EVP_CipherUpdate(context->decrypt_context, nullptr, &size_update, &(*aad)[0], aad->size());
            if (1 != ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        uint32 cooltime = ossl_get_cooltime();
        switch (context->mode) {
            case crypt_mode_t::ccm:
            case crypt_mode_t::wrap:
                cooltime = 0;
                break;
        }

        if (cooltime) {
            // stability

            /*
             * check hints for block ciphers
             * EVP_CIPHER_get_block_size, EVP_CIPHER_CTX_get_block_size works wrong (CFB, OFB)
             */
            crypto_advisor *advisor = crypto_advisor::get_instance();
            const hint_blockcipher_t *hint_cipher = advisor->hintof_blockcipher(context->algorithm);
            if (nullptr == hint_cipher) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            uint16 blocksize = sizeof_block(hint_cipher);
            uint32 unitsize = ossl_get_unitsize();
            size_t size_progress = 0;
            size_t size_process = 0;
            for (size_t i = 0; i < ciphersize; i += blocksize) {
                int remain = ciphersize - i;
                int size = (remain < blocksize) ? remain : blocksize;
                EVP_CipherUpdate(context->decrypt_context, plaintext + size_progress, &size_update, ciphertext + i, size);
                size_progress += size_update;
                size_process += size_update;
                if (size_process > unitsize) {
                    msleep(cooltime);
                    size_process = 0;
                }
            }
            size_update = size_progress;
        } else {
            // performance

            ret_cipher = EVP_CipherUpdate(context->decrypt_context, plaintext, &size_update, ciphertext, ciphersize);
            if (1 != ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_cipher = EVP_CipherFinal(context->decrypt_context, plaintext + size_update, &size_final);
        if (1 != ret_cipher) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        *plainsize = size_update + size_final;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (plainsize) {
                *plainsize = 0;
            }
        }
    }

    return ret;
}

return_t openssl_crypt::query(crypt_context_t *handle, size_t cmd, size_t &value) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = static_cast<openssl_crypt_context_t *>(handle);

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (OPENSSL_CRYPT_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        /* EVP_CIPHER_CTX_key_length, EVP_CIPHER_CTX_iv_length
         * [openssl 3.0.3] compatibility problem
         * EVP_CIPHER_..._length return EVP_CTRL_RET_UNSUPPORTED(-1)
         */
        if (1 == cmd) {
            value = EVP_CIPHER_CTX_key_length(context->encrypt_context);
            adjust_range(value, 0, EVP_MAX_KEY_LENGTH);
        } else if (2 == cmd) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            value = EVP_MAX_IV_LENGTH;
#else
            value = EVP_CIPHER_CTX_iv_length(context->encrypt_context);
#endif
            adjust_range(value, 0, EVP_MAX_IV_LENGTH);
        } else {
            ret = errorcode_t::bad_request;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
