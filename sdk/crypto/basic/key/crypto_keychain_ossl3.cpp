/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_ossl3.cpp
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

return_t crypto_keychain::pkey_keygen_byname(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const char* name) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey || nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int rc = 0;
        EVP_PKEY_CTX_ptr pkey_ctx(EVP_PKEY_CTX_new_from_name(libctx, name, nullptr));
        if (pkey_ctx.get()) {
            rc = EVP_PKEY_keygen_init(pkey_ctx.get());
            // OSSL_PARAM* params;
            // ...
            // EVP_PKEY_CTX_set_params(pkey_ctx, params);
            EVP_PKEY_keygen(pkey_ctx.get(), pkey);
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

return_t crypto_keychain::pkey_encode_format(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
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

        OSSL_ENCODER_CTX_ptr encoder_context(OSSL_ENCODER_CTX_new_for_pkey(pkey, params.selection, params.format, params.structure, nullptr));
        if (encoder_context.get()) {
            if (passphrase) {
                OSSL_ENCODER_CTX_set_passphrase(encoder_context.get(), (const unsigned char*)passphrase, strlen(passphrase));
                OSSL_ENCODER_CTX_set_cipher(encoder_context.get(), "AES-256-CBC", nullptr);
            }

            unsigned char* pub = nullptr;
            size_t publen = 0;
            BUF_MEM* buf = nullptr;
            int rc = 0;

            BIO_ptr mem(BIO_new(BIO_s_mem()));
            rc = OSSL_ENCODER_to_bio(encoder_context.get(), mem.get());
            if (rc < 1) {
                ret = errorcode_t::internal_error;
                __leave2;
            }

            BIO_get_mem_ptr(mem.get(), &buf);
            if (nullptr == buf || 0 == buf->length) {
                ret = errorcode_t::internal_error;
                __leave2;
            }

            keydata.resize(buf->length);
            memcpy(keydata.data(), buf->data, buf->length);
        } else {
            ret = failed;
        }
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode_format(libctx, pkey, keydata.data(), keydata.size(), encoding, passphrase);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                             const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    int rc = 0;
    __try2 {
        if (nullptr == pkey || nullptr == keystream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();

        key_encoding_params_t params;
        advisor->get_encoding_params(encoding, params);

        if (params.use_pass && (nullptr == passphrase)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        BIO_ptr buf(BIO_new_mem_buf(keystream, keysize));
        if (nullptr == buf.get()) {
            ret = failed;
            __leave2;
        }

        OSSL_DECODER_CTX_ptr decoder_context(OSSL_DECODER_CTX_new_for_pkey(pkey, params.format, params.structure, nullptr, params.selection, libctx, nullptr));
        if (decoder_context.get()) {
            if (passphrase) {
                OSSL_DECODER_CTX_set_passphrase(decoder_context.get(), (const unsigned char*)passphrase, strlen(passphrase));
            }

            rc = OSSL_DECODER_from_bio(decoder_context.get(), buf.get());
            if (rc < 1) {
                ret = failed;
                __leave2_trace_openssl(ret);
            }
        } else {
            ret = failed;
            __leave2;
        }
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keychain::pkey_encode_raw(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        size_t len = 0;
        switch (encoding) {
            case key_encoding_priv_pem:
            case key_encoding_encrypted_priv_pem:
            case key_encoding_pub_pem:
            case key_encoding_priv_der:
            case key_encoding_encrypted_priv_der:
            case key_encoding_pub_der: {
                ret = not_supported;
            } break;
            case key_encoding_priv_raw: {
                EVP_PKEY_get_raw_private_key(pkey, nullptr, &len);
                keydata.resize(len);
                EVP_PKEY_get_raw_private_key(pkey, keydata.data(), &len);
                keydata.resize(len);
            } break;
            case key_encoding_pub_raw: {
                EVP_PKEY_get_raw_public_key(pkey, nullptr, &len);
                keydata.resize(len);
                EVP_PKEY_get_raw_public_key(pkey, keydata.data(), &len);
                keydata.resize(len);
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding,
                                      const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode(libctx, name, pkey, keydata.data(), keydata.size(), encoding, passphrase);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                      const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == keystream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (encoding) {
            case key_encoding_priv_pem:
            case key_encoding_encrypted_priv_pem:
            case key_encoding_pub_pem:
            case key_encoding_priv_der:
            case key_encoding_encrypted_priv_der:
            case key_encoding_pub_der: {
                ret = pkey_decode_format(libctx, pkey, keystream, keysize, encoding, passphrase);
            } break;
            case key_encoding_priv_raw:
            case key_encoding_pub_raw: {
                ret = pkey_decode_raw(libctx, name, pkey, keystream, keysize, encoding);
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::pkey_decode_raw(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode_raw(libctx, name, pkey, keydata.data(), keydata.size(), encoding);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::pkey_decode_raw(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize,
                                          key_encoding_t encoding) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM params[3];
    int rc = 0;
    __try2 {
        if (nullptr == name || nullptr == pkey || nullptr == keystream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        const char* param = nullptr;
        int selection = 0;
        switch (encoding) {
            case key_encoding_priv_raw: {
                param = OSSL_PKEY_PARAM_PRIV_KEY;
                selection = EVP_PKEY_PRIVATE_KEY;
            } break;
            case key_encoding_pub_raw: {
                param = OSSL_PKEY_PARAM_PUB_KEY;
                selection = EVP_PKEY_PUBLIC_KEY;
            } break;
            default: {
                ret = not_supported;
            } break;
        }
        if (success != ret) {
            __leave2;
        }

        EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_from_name(NULL, name, NULL));
        if (nullptr == pctx.get()) {
            ret = failed;
            __leave2_trace_openssl(ret);
        }
        rc = EVP_PKEY_fromdata_init(pctx.get());
        if (rc <= 0) {
            ret = failed;
            __leave2_trace_openssl(ret);
        }

        params[0] = OSSL_PARAM_construct_octet_string(param, (void*)keystream, keysize);
        params[1] = OSSL_PARAM_construct_end();

        rc = EVP_PKEY_fromdata(pctx.get(), pkey, selection, params);
        if (rc <= 0) {
            ret = failed;
            __leave2_trace_openssl(ret);
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
    switch (encoding) {
        case key_encoding_priv_pem:
        case key_encoding_encrypted_priv_pem:
        case key_encoding_pub_pem:
        case key_encoding_priv_der:
        case key_encoding_encrypted_priv_der:
        case key_encoding_pub_der: {
            ret = pkey_encode_format(libctx, pkey, keydata, encoding, passphrase);
        } break;
        case key_encoding_priv_raw:
        case key_encoding_pub_raw: {
            ret = pkey_encode_raw(libctx, pkey, keydata, encoding);
        } break;
    }
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode(libctx, pkey, keydata.data(), keydata.size(), encoding, passphrase);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::pkey_decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                      const char* passphrase) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case key_encoding_priv_pem:
        case key_encoding_encrypted_priv_pem:
        case key_encoding_pub_pem:
        case key_encoding_priv_der:
        case key_encoding_encrypted_priv_der:
        case key_encoding_pub_der: {
            ret = pkey_decode_format(libctx, pkey, keystream, keysize, encoding, passphrase);
        } break;
        case key_encoding_priv_raw:
        case key_encoding_pub_raw: {
            ret = not_supported;
        } break;
    }
    return ret;
}

bool crypto_keychain::pkey_is_private(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey) {
    bool ret_value = false;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();

        key_encoding_params_t params;
        advisor->get_encoding_params(key_encoding_priv_der, params);

        OSSL_ENCODER_CTX_ptr encoder_context(OSSL_ENCODER_CTX_new_for_pkey(pkey, params.selection, params.format, params.structure, nullptr));
        if (encoder_context.get()) {
            unsigned char* pub = nullptr;
            size_t publen = 0;
            BUF_MEM* buf = nullptr;
            int rc = 0;

            BIO_ptr mem(BIO_new(BIO_s_mem()));
            rc = OSSL_ENCODER_to_bio(encoder_context.get(), mem.get());
            if (rc < 1) {
                __leave2;
            }

            BIO_get_mem_ptr(mem.get(), &buf);
            if (nullptr == buf || 0 == buf->length) {
                __leave2;
            }

            ret_value = true;
        } else {
            ret = failed;
        }
    }
    __finally2 {}
#else
    // ret = errorcode_t::not_supported;
#endif
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
