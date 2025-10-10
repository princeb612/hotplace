/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::pkey_gen_byname(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const char* name) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey || nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int rc = 0;
        auto pkey_ctx = EVP_PKEY_CTX_new_from_name(libctx, name, nullptr);
        if (pkey_ctx) {
            rc = EVP_PKEY_keygen_init(pkey_ctx);
            // OSSL_PARAM* params;
            // ...
            // EVP_PKEY_CTX_set_params(pkey_ctx, params);
            EVP_PKEY_keygen(pkey_ctx, pkey);

            EVP_PKEY_CTX_free(pkey_ctx);
        } else {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_encode(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_ENCODER_CTX* encoder_context = nullptr;
    BIO* mem = nullptr;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // https://docs.openssl.org/3.5/man3/OSSL_ENCODER_CTX_new_for_pkey/
        // https://docs.openssl.org/3.5/man3/OSSL_ENCODER_to_bio/

        crypto_advisor* advisor = crypto_advisor::get_instance();

        key_encoding_params_t params;
        advisor->get_encoding_params(encoding, params);
        if (params.use_pass && (nullptr == passphrase)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        encoder_context = OSSL_ENCODER_CTX_new_for_pkey(pkey, params.selection, params.format, params.structure, nullptr);
        if (encoder_context) {
            if (passphrase) {
                OSSL_ENCODER_CTX_set_passphrase(encoder_context, (const unsigned char*)passphrase, strlen(passphrase));
                OSSL_ENCODER_CTX_set_cipher(encoder_context, "AES-256-CBC", nullptr);
            }

            unsigned char* pub = nullptr;
            size_t publen = 0;
            BUF_MEM* buf = nullptr;
            int rc = 0;

            mem = BIO_new(BIO_s_mem());
            rc = OSSL_ENCODER_to_bio(encoder_context, mem);
            if (rc < 1) {
                ret = errorcode_t::internal_error;
                __leave2;
            }

            BIO_get_mem_ptr(mem, &buf);
            if (nullptr == buf || 0 == buf->length) {
                ret = errorcode_t::internal_error;
                __leave2;
            }

            keydata.resize(buf->length);
            memcpy(&keydata[0], buf->data, buf->length);
        } else {
            ret = failed;
        }
    }
    __finally2 {
        BIO_free(mem);
        OSSL_ENCODER_CTX_free(encoder_context);
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIO* buf = nullptr;
    OSSL_DECODER_CTX* decoder_context = nullptr;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (keydata.empty()) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();

        key_encoding_params_t params;
        advisor->get_encoding_params(encoding, params);

        if (params.use_pass && (nullptr == passphrase)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        buf = BIO_new_mem_buf(&keydata[0], keydata.size());
        if (nullptr == buf) {
            ret = failed;
            __leave2;
        }

        decoder_context = OSSL_DECODER_CTX_new_for_pkey(pkey, params.format, params.structure, nullptr, params.selection, libctx, nullptr);
        if (decoder_context) {
            if (passphrase) {
                OSSL_DECODER_CTX_set_passphrase(decoder_context, (const unsigned char*)passphrase, strlen(passphrase));
            }

            OSSL_DECODER_from_bio(decoder_context, buf);
        } else {
            ret = failed;
            __leave2;
        }
    }
    __finally2 {
        BIO_free(buf);
        OSSL_DECODER_CTX_free(decoder_context);
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

bool crypto_keychain::pkey_is_private(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey) {
    bool ret_value = false;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    OSSL_ENCODER_CTX* encoder_context = nullptr;
    BIO* mem = nullptr;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();

        key_encoding_params_t params;
        advisor->get_encoding_params(key_encoding_priv_der, params);

        encoder_context = OSSL_ENCODER_CTX_new_for_pkey(pkey, params.selection, params.format, params.structure, nullptr);
        if (encoder_context) {
            unsigned char* pub = nullptr;
            size_t publen = 0;
            BUF_MEM* buf = nullptr;
            int rc = 0;

            mem = BIO_new(BIO_s_mem());
            rc = OSSL_ENCODER_to_bio(encoder_context, mem);
            if (rc < 1) {
                __leave2;
            }

            BIO_get_mem_ptr(mem, &buf);
            if (nullptr == buf || 0 == buf->length) {
                __leave2;
            }

            ret_value = true;
        } else {
            ret = failed;
        }
    }
    __finally2 {
        BIO_free(mem);
        OSSL_ENCODER_CTX_free(encoder_context);
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
