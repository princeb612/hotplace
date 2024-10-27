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

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/datetime.hpp>
#include <sdk/base/system/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
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
          mode(crypt_mode_t::crypt_mode_unknown),
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

openssl_crypt::openssl_crypt() {
    openssl_startup();
    // do nothing
}

openssl_crypt::~openssl_crypt() {
    openssl_cleanup();
    // do nothing
}

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

return_t openssl_crypt::open(crypt_context_t **handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv) {
    return open(handle, algorithm, mode, &key[0], key.size(), &iv[0], iv.size());
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

return_t openssl_crypt::encrypt(crypt_context_t *handle, const unsigned char *data_plain, size_t size_plain, unsigned char **data_encrypted,
                                size_t *size_encrypted) {
    return_t ret = errorcode_t::success;
    byte_t *output_allocated = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == data_plain || nullptr == data_encrypted || nullptr == size_encrypted) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_out_allocated = size_plain + EVP_MAX_BLOCK_LENGTH;
        __try_new_catch(output_allocated, new byte_t[size_out_allocated + 1], ret, __leave2);

        ret = encrypt2(handle, data_plain, size_plain, output_allocated, &size_out_allocated, nullptr, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        output_allocated[size_out_allocated] = 0;

        *data_encrypted = output_allocated;
        *size_encrypted = size_out_allocated;
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

return_t openssl_crypt::encrypt(crypt_context_t *handle, const unsigned char *data_plain, size_t size_plain, binary_t &out_encrypted) {
    return encrypt2(handle, data_plain, size_plain, out_encrypted);
}

return_t openssl_crypt::encrypt(crypt_context_t *handle, const binary_t &input, binary_t &out) { return encrypt(handle, &input[0], input.size(), out); }

return_t openssl_crypt::encrypt2(crypt_context_t *handle, const unsigned char *data_plain, size_t size_plain, binary_t &out_encrypted, const binary_t *aad,
                                 binary_t *tag) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_len = size_plain + EVP_MAX_BLOCK_LENGTH;
        out_encrypted.resize(size_len);

        ret = encrypt2(handle, data_plain, size_plain, &out_encrypted[0], &size_len, aad, tag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        out_encrypted.resize(size_len);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            out_encrypted.resize(0);
        }
    }

    return ret;
}

return_t openssl_crypt::encrypt2(crypt_context_t *handle, const binary_t &data_plain, binary_t &out_encrypted, const binary_t *aad, binary_t *tag) {
    return encrypt2(handle, &data_plain[0], data_plain.size(), out_encrypted, aad, tag);
}

return_t openssl_crypt::encrypt2(crypt_context_t *handle, const unsigned char *data_plain, size_t size_plain, unsigned char *out_encrypted,
                                 size_t *size_encrypted, const binary_t *aad, binary_t *tag) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = static_cast<openssl_crypt_context_t *>(handle);

    __try2 {
        if (nullptr == handle || nullptr == data_plain || nullptr == size_encrypted) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (OPENSSL_CRYPT_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        size_t size_expect = size_plain + EVP_MAX_BLOCK_LENGTH;
        if (*size_encrypted < size_expect) {
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

        if ((crypt_mode_t::gcm == context->mode) || (crypt_mode_t::ccm == context->mode)) {
            if ((nullptr == aad) || (nullptr == tag)) {
                ret = errorcode_t::invalid_parameter;
                __leave2_trace(ret);
            }

            // https://www.openssl.org/docs/man1.1.1/man3/EVP_CIPHER_iv_length.html
            // EVP_CTRL_CCM_SET_L
            //      If not set a default is used (8 for AES CCM).
            // EVP_CTRL_AEAD_SET_IVLEN
            //      For GCM AES and OCB AES the default is 12 (i.e. 96 bits)
            //      The nonce length is given by 15 - L so it is 7 by default for AES CCM.
            //       If not called a default nonce length of 12 (i.e. 96 bits) is used. (ChaCha20-Poly1305)
            // EVP_CTRL_AEAD_SET_TAG
            //      If not set a default value is used (12 for AES CCM)
            //      For OCB AES, the default tag length is 16 (i.e. 128 bits).

            if (crypt_mode_t::gcm == context->mode) {
                // 16bytes (128bits)
                // RFC 7516
                //      Perform authenticated encryption on the plaintext with the AES GCM
                //      algorithm using the CEK as the encryption key, the JWE
                //      Initialization Vector, and the Additional Authenticated Data
                //      value, requesting a 128-bit Authentication Tag output.
                //
                //      B.7.  Truncate HMAC Value to Create Authentication Tag
                //      Use the first half (128 bits) of the HMAC output M as the
                //      Authentication Tag output T.
                //
                // RFC 7539 2.5.  The Poly1305 Algorithm
                //      Poly1305 takes a 32-byte one-time key and a message and produces a 16-byte tag.
                //
                // RFC 8152 10.1.  AES GCM
                // the size of the authentication tag is fixed at 128 bits
                tag_size = context->tsize ? context->tsize : 16;
            } else if (crypt_mode_t::ccm == context->mode) {
                tag_size = context->tsize ? context->tsize : 14;
                uint16 lsize = context->lsize ? context->lsize : 8;
                uint16 nonce_size = 15 - lsize;

                EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_CCM_SET_L, lsize, nullptr);
                // EVP_CTRL_CCM_SET_IVLEN for Nonce (15-L)
                EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_CCM_SET_IVLEN, nonce_size, nullptr);
                EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_AEAD_SET_TAG, tag_size, nullptr);

                binary_t &key = context->datamap[crypt_item_t::item_cek];
                EVP_CipherInit_ex(context->encrypt_context, nullptr, nullptr, &key[0], &iv[0], 1);

                ret_cipher = EVP_CipherUpdate(context->encrypt_context, nullptr, &size_update, nullptr, size_plain);
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
            // stability oriented

            // check hints for block ciphers
            // EVP_CIPHER_get_block_size, EVP_CIPHER_CTX_get_block_size works wrong (CFB, OFB)
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
            for (size_t i = 0; i < size_plain; i += blocksize) {
                int remain = size_plain - i;
                int size = (remain < blocksize) ? remain : blocksize;
                EVP_CipherUpdate(context->encrypt_context, out_encrypted + size_progress, &size_update, data_plain + i, size);
                size_progress += size_update;
                size_process += size_update;
                if (size_process > unitsize) {
                    msleep(cooltime);
                    size_process = 0;
                }
            }
            size_update = size_progress;
        } else {
            // performance oriented

            ret_cipher = EVP_CipherUpdate(context->encrypt_context, out_encrypted, &size_update, data_plain, size_plain);
            if (1 > ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_cipher = EVP_CipherFinal(context->encrypt_context, out_encrypted + size_update, &size_final);
        if (1 > ret_cipher) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        if ((crypt_mode_t::gcm == context->mode) || (crypt_mode_t::ccm == context->mode)) {
            tag->resize(tag_size);
            ret_cipher = EVP_CIPHER_CTX_ctrl(context->encrypt_context, EVP_CTRL_AEAD_GET_TAG, tag->size(), &(*tag)[0]);
            if (1 > ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        *size_encrypted = (size_update + size_final);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (size_encrypted) {
                *size_encrypted = 0;
            }
        }
    }

    return ret;
}

return_t openssl_crypt::decrypt(crypt_context_t *handle, const unsigned char *data_encrypted, size_t size_encrypted, unsigned char **data_plain,
                                size_t *size_plain) {
    return_t ret = errorcode_t::success;
    byte_t *output_allocated = nullptr;

    __try2 {
        if (nullptr == handle || nullptr == data_encrypted || nullptr == data_plain || nullptr == size_plain) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_out_allocated = size_encrypted + EVP_MAX_BLOCK_LENGTH;
        __try_new_catch(output_allocated, new byte_t[size_out_allocated + 1], ret, __leave2);

        ret = decrypt2(handle, data_encrypted, size_encrypted, output_allocated, &size_out_allocated, nullptr, nullptr);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        output_allocated[size_out_allocated] = 0;

        *data_plain = output_allocated;
        *size_plain = size_out_allocated;
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

return_t openssl_crypt::decrypt(crypt_context_t *handle, const unsigned char *data_encrypted, size_t size_encrypted, binary_t &out_decrypted) {
    return decrypt2(handle, data_encrypted, size_encrypted, out_decrypted);
}

return_t openssl_crypt::decrypt(crypt_context_t *handle, const binary_t &input, binary_t &out_decrypted) {
    return decrypt2(handle, &input[0], input.size(), out_decrypted);
}

return_t openssl_crypt::decrypt2(crypt_context_t *handle, const unsigned char *data_encrypted, size_t size_encrypted, binary_t &out_decrypted,
                                 const binary_t *aad, const binary_t *tag) {
    return_t ret = errorcode_t::success;

    __try2 {
        size_t size_len = size_encrypted + EVP_MAX_BLOCK_LENGTH;
        out_decrypted.resize(size_len);

        ret = decrypt2(handle, data_encrypted, size_encrypted, &out_decrypted[0], &size_len, aad, tag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        out_decrypted.resize(size_len);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            out_decrypted.resize(0);
        }
    }

    return ret;
}

return_t openssl_crypt::decrypt2(crypt_context_t *handle, const binary_t &data_encrypted, binary_t &out_decrypted, const binary_t *aad, const binary_t *tag) {
    return decrypt2(handle, &data_encrypted[0], data_encrypted.size(), out_decrypted, aad, tag);
}

return_t openssl_crypt::decrypt2(crypt_context_t *handle, const unsigned char *data_encrypted, size_t size_encrypted, unsigned char *out_decrypted,
                                 size_t *size_decrypted, const binary_t *aad, const binary_t *tag) {
    return_t ret = errorcode_t::success;
    openssl_crypt_context_t *context = static_cast<openssl_crypt_context_t *>(handle);

    __try2 {
        if (nullptr == handle || nullptr == data_encrypted || 0 == size_encrypted || nullptr == size_decrypted) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (OPENSSL_CRYPT_CONTEXT_SIGNATURE != context->signature) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        size_t size_necessary = size_encrypted + EVP_MAX_BLOCK_LENGTH;
        if (*size_decrypted < size_necessary) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }

        EVP_CIPHER_CTX_set_padding(context->decrypt_context, context->flag & openssl_crypt_flag_t::crypt_blockcipher_padding ? 1 : 0);

        int ret_cipher = 0;
        int size_update = 0;
        int size_final = 0;
        binary_t &iv = context->datamap[crypt_item_t::item_iv];

        EVP_CipherInit(context->decrypt_context, nullptr, nullptr, &iv[0], 0);

        if ((crypt_mode_t::gcm == context->mode) || (crypt_mode_t::ccm == context->mode)) {
            if ((nullptr == aad) || (nullptr == tag)) {
                ret = errorcode_t::invalid_parameter;
                __leave2_trace(ret);
            }

            if (crypt_mode_t::ccm == context->mode) {
                uint16 lsize = context->lsize ? context->lsize : 8;
                uint16 nonce_size = 15 - lsize;

                EVP_CIPHER_CTX_ctrl(context->decrypt_context, EVP_CTRL_CCM_SET_L, lsize, nullptr);
                // EVP_CTRL_CCM_SET_IVLEN for Nonce (15-L)
                EVP_CIPHER_CTX_ctrl(context->decrypt_context, EVP_CTRL_CCM_SET_IVLEN, nonce_size, nullptr);
                EVP_CIPHER_CTX_ctrl(context->decrypt_context, EVP_CTRL_AEAD_SET_TAG, tag->size(), (void *)&(*tag)[0]);

                binary_t &key = context->datamap[crypt_item_t::item_cek];
                EVP_CipherInit_ex(context->decrypt_context, nullptr, nullptr, &key[0], &iv[0], 0);

                ret_cipher = EVP_CipherUpdate(context->decrypt_context, nullptr, &size_update, nullptr, size_encrypted);
            } else if (crypt_mode_t::gcm == context->mode) {
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
            // stability oriented

            // check hints for block ciphers
            // EVP_CIPHER_get_block_size, EVP_CIPHER_CTX_get_block_size works wrong (CFB, OFB)
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
            for (size_t i = 0; i < size_encrypted; i += blocksize) {
                int remain = size_encrypted - i;
                int size = (remain < blocksize) ? remain : blocksize;
                EVP_CipherUpdate(context->decrypt_context, out_decrypted + size_progress, &size_update, data_encrypted + i, size);
                size_progress += size_update;
                size_process += size_update;
                if (size_process > unitsize) {
                    msleep(cooltime);
                    size_process = 0;
                }
            }
            size_update = size_progress;
        } else {
            // performance oriented

            ret_cipher = EVP_CipherUpdate(context->decrypt_context, out_decrypted, &size_update, data_encrypted, size_encrypted);
            if (1 != ret_cipher) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_cipher = EVP_CipherFinal(context->decrypt_context, out_decrypted + size_update, &size_final);
        if (1 != ret_cipher) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        *size_decrypted = size_update + size_final;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (size_decrypted) {
                *size_decrypted = 0;
            }
        }
    }

    return ret;
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

return_t openssl_crypt::encrypt(const EVP_PKEY *pkey, const binary_t &input, binary_t &output, crypt_enc_t mode) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX *pkey_context = nullptr;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        int ret_openssl = 1;

        output.resize(0);

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_context = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, nullptr);

        if (nullptr == pkey_context) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_encrypt_init(pkey_context);

        int id = EVP_PKEY_id(pkey);
        if (EVP_PKEY_RSA == id) {
            // OAEP
            hash_algorithm_t alg = hash_algorithm_t::sha1;
            const EVP_MD *md = nullptr;

            // padding
            switch (mode) {
                case crypt_enc_t::rsa_1_5:
                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PADDING);
                    break;
                case crypt_enc_t::rsa_oaep:
                case crypt_enc_t::rsa_oaep256:
                case crypt_enc_t::rsa_oaep384:
                case crypt_enc_t::rsa_oaep512:

                    switch (mode) {
                        case crypt_enc_t::rsa_oaep:
                            alg = hash_algorithm_t::sha1;
                            break;
                        case crypt_enc_t::rsa_oaep256:
                            alg = hash_algorithm_t::sha2_256;
                            break;
                        case crypt_enc_t::rsa_oaep384:
                            alg = hash_algorithm_t::sha2_384;
                            break;
                        case crypt_enc_t::rsa_oaep512:
                            alg = hash_algorithm_t::sha2_512;
                            break;
                        default:
                            break;
                    }
                    md = advisor->find_evp_md(alg);

                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_OAEP_PADDING);
                    EVP_PKEY_CTX_set_rsa_oaep_md(pkey_context, md);
                    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context, md);
                    break;
                default:
                    break;
            }
        }

        size_t size = 0;
        ret_openssl = EVP_PKEY_encrypt(pkey_context, nullptr, &size, &input[0], input.size());
        if (-2 == ret_openssl) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        output.resize(size);
        ret_openssl = EVP_PKEY_encrypt(pkey_context, &output[0], &size, &input[0], input.size());
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
    }
    __finally2 {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free(pkey_context);
        }
    }
    return ret;
}

return_t openssl_crypt::decrypt(const EVP_PKEY *pkey, const binary_t &input, binary_t &output, crypt_enc_t mode) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX *pkey_context = nullptr;
    crypto_advisor *advisor = crypto_advisor::get_instance();

    __try2 {
        int ret_openssl = 1;

        output.resize(0);

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bool is_private = false;
        ret = is_private_key(pkey, is_private);
        if (false == is_private) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_context = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, nullptr);

        if (nullptr == pkey_context) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_decrypt_init(pkey_context);

        if (EVP_PKEY_RSA == EVP_PKEY_id(pkey)) {
            // OAEP
            hash_algorithm_t alg = hash_algorithm_t::sha1;
            const EVP_MD *md = nullptr;

            // padding
            switch (mode) {
                case crypt_enc_t::rsa_1_5:
                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PADDING);
                    break;
                case crypt_enc_t::rsa_oaep:
                case crypt_enc_t::rsa_oaep256:
                case crypt_enc_t::rsa_oaep384:
                case crypt_enc_t::rsa_oaep512:

                    switch (mode) {
                        case crypt_enc_t::rsa_oaep:
                            alg = hash_algorithm_t::sha1;
                            break;
                        case crypt_enc_t::rsa_oaep256:
                            alg = hash_algorithm_t::sha2_256;
                            break;
                        case crypt_enc_t::rsa_oaep384:
                            alg = hash_algorithm_t::sha2_384;
                            break;
                        case crypt_enc_t::rsa_oaep512:
                            alg = hash_algorithm_t::sha2_512;
                            break;
                        default:
                            break;
                    }
                    md = advisor->find_evp_md(alg);

                    EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_OAEP_PADDING);
                    EVP_PKEY_CTX_set_rsa_oaep_md(pkey_context, md);
                    EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_context, md);
                    break;
                default:
                    break;
            }
        }

        size_t size = 0;
        ret_openssl = EVP_PKEY_decrypt(pkey_context, nullptr, &size, &input[0], input.size());
        if (-2 == ret_openssl) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        output.resize(size);
        ret_openssl = EVP_PKEY_decrypt(pkey_context, &output[0], &size, &input[0], input.size());
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        output.resize(size);
    }
    __finally2 {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free(pkey_context);
        }
    }
    return ret;
}

crypt_poweredby_t openssl_crypt::get_type() { return crypt_poweredby_t::openssl; }

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

        ret = encrypt2(crypt_handle, plaintext, ciphertext, &aad, &tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::encrypt(const char *alg, const binary_t &key, const binary_t &iv, const unsigned char *plaintext, size_t size_plaintext,
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

        ret = encrypt2(crypt_handle, plaintext, size_plaintext, ciphertext, &aad, &tag);
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

        ret = encrypt2(crypt_handle, plaintext, ciphertext, &aad, &tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}
return_t openssl_crypt::encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const unsigned char *plaintext,
                                size_t size_plaintext, binary_t &ciphertext, const binary_t &aad, binary_t &tag, encrypt_option_t *options) {
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

        ret = encrypt2(crypt_handle, plaintext, size_plaintext, ciphertext, &aad, &tag);
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

        ret = decrypt2(crypt_handle, ciphertext, plaintext, &aad, &tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(const char *alg, const binary_t &key, const binary_t &iv, const unsigned char *ciphertext, size_t size_ciphertext,
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

        ret = decrypt2(crypt_handle, ciphertext, size_ciphertext, plaintext, &aad, &tag);
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

        ret = decrypt2(crypt_handle, ciphertext, plaintext, &aad, &tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_crypt::decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t &key, const binary_t &iv, const unsigned char *ciphertext,
                                size_t size_ciphertext, binary_t &plaintext, const binary_t &aad, const binary_t &tag, encrypt_option_t *options) {
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

        ret = decrypt2(crypt_handle, ciphertext, size_ciphertext, plaintext, &aad, &tag);
    }
    __finally2 { close(crypt_handle); }
    return ret;
}

return_t openssl_chacha20_iv(binary_t &iv, uint32 counter, const binary_t &nonce) { return openssl_chacha20_iv(iv, counter, &nonce[0], nonce.size()); }

return_t openssl_chacha20_iv(binary_t &iv, uint32 counter, const byte_t *nonce, size_t nonce_size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == nonce) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // nonce = constant | iv
        // constant to little-endian
        uint32 constant = 0;
        if (is_little_endian()) {
            constant = counter;
        } else {
            constant = convert_endian(counter);
        }

        if (nonce_size > 12) {
            nonce_size = 12;
        }

        iv.resize(4);
        memcpy(&iv[0], (byte_t *)&constant, sizeof(counter));
        iv.insert(iv.end(), nonce, nonce + nonce_size);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
