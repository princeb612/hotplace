/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_ossl3.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keygen::pkey_keygen_byname(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const char* name) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX_ptr pkey_ctx;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != name); })
        .run_pipe([&]() -> int {
            pkey_ctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_from_name(libctx, name, nullptr)));
            return pkey_ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_keygen_init(pkey_ctx.get()); })
        .run_pipe([&]() -> int { return EVP_PKEY_keygen(pkey_ctx.get(), pkey); });
    return pipeline.result_to_return_t();
#else
    return errorcode_t::not_supported;
#endif
}

return_t crypto_keygen::pkey_encode_format(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // https://docs.openssl.org/3.5/man3/OSSL_ENCODER_CTX_new_for_pkey/
    // https://docs.openssl.org/3.5/man3/OSSL_ENCODER_to_bio/

    BIO_ptr mem;
    BUF_MEM* buf = nullptr;
    OSSL_ENCODER_CTX_ptr encoder_context;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    key_encoding_params_t params;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey); })
        .run_pipe([&]() -> int {
            advisor->get_encoding_params(encoding, params);
            return (params.use_pass && (nullptr == passphrase)) ? 0 : 1;
        })
        .run_pipe([&]() -> int {
            encoder_context = std::move(OSSL_ENCODER_CTX_ptr(OSSL_ENCODER_CTX_new_for_pkey(pkey, params.selection, params.format, params.structure, nullptr)));
            return encoder_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            if (passphrase) {
                return OSSL_ENCODER_CTX_set_passphrase(encoder_context.get(), (const unsigned char*)passphrase, strlen(passphrase));
            } else {
                return 1;
            }
        })
        .run_pipe([&]() -> int {
            if (passphrase) {
                return OSSL_ENCODER_CTX_set_cipher(encoder_context.get(), "AES-256-CBC", nullptr);
            } else {
                return 1;
            }
        })
        .run_pipe([&]() -> int {
            mem = std::move(BIO_ptr(BIO_new(BIO_s_mem())));
            return OSSL_ENCODER_to_bio(encoder_context.get(), mem.get());
        })
        .run_pipe([&]() -> int {
            BIO_get_mem_ptr(mem.get(), &buf);
            return (nullptr == buf || 0 == buf->length) ? 0 : 1;
        })
        .walk([&]() -> void {
            keydata.resize(buf->length);
            memcpy(keydata.data(), buf->data, buf->length);
        });
    return pipeline.result_to_return_t();
#else
    return errorcode_t::not_supported;
#endif
}

return_t crypto_keygen::pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = pkey_decode_format(libctx, pkey, keydata.data(), keydata.size(), encoding, passphrase);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keygen::pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                           const char* passphrase) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIO_ptr buf;
    OSSL_DECODER_CTX_ptr decoder_context;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    key_encoding_params_t params;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != keystream); })
        .run_pipe([&]() -> int {
            advisor->get_encoding_params(encoding, params);
            return (params.use_pass && (nullptr == passphrase)) ? 0 : 1;
        })
        .run_pipe([&]() -> int {
            buf = std::move(BIO_ptr(BIO_new_mem_buf(keystream, t_narrow_cast(keysize))));
            return buf.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            decoder_context =
                std::move(OSSL_DECODER_CTX_ptr(OSSL_DECODER_CTX_new_for_pkey(pkey, params.format, params.structure, nullptr, params.selection, libctx, nullptr)));
            return decoder_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            if (passphrase) {
                return OSSL_DECODER_CTX_set_passphrase(decoder_context.get(), (const unsigned char*)passphrase, strlen(passphrase));
            } else {
                return 1;
            }
        })
        .run_pipe([&]() -> int { return OSSL_DECODER_from_bio(decoder_context.get(), buf.get()); });
    return pipeline.result_to_return_t();
#else
    return errorcode_t::not_supported;
#endif
}

return_t crypto_keygen::pkey_encode_raw(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
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
                ret = errorcode_t::not_supported;
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
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keygen::pkey_decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                    const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
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
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keygen::pkey_decode_raw(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX_ptr pctx;
    OSSL_PARAM params[3];
    const char* param = nullptr;
    int selection = 0;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != name && nullptr != pkey && nullptr != keystream); })
        .run_pipe([&]() -> return_t {
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
                    return errorcode_t::not_supported;
                } break;
            }
            return errorcode_t::success;
        })
        .run_pipe([&]() -> int {
            pctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_from_name(NULL, name, NULL)));
            return pctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_fromdata_init(pctx.get()); })
        .run_pipe([&]() -> int {
            params[0] = OSSL_PARAM_construct_octet_string(param, (void*)keystream, keysize);
            params[1] = OSSL_PARAM_construct_end();

            return EVP_PKEY_fromdata(pctx.get(), pkey, selection, params);
        });

    return pipeline.result_to_return_t();
#else
    return errorcode_t::not_supported;
#endif
}

bool crypto_keygen::pkey_is_private(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIO_ptr mem;
    BUF_MEM* buf = nullptr;
    OSSL_ENCODER_CTX_ptr encoder_context;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    key_encoding_params_t params;

    function_pipeline<int> pipeline;
    pipeline  //
        .test_parameter([&]() -> bool { return (nullptr != pkey); })
        .walk([&]() -> void { advisor->get_encoding_params(key_encoding_priv_der, params); })
        .run_pipe([&]() -> int {
            encoder_context = std::move(OSSL_ENCODER_CTX_ptr(OSSL_ENCODER_CTX_new_for_pkey(pkey, params.selection, params.format, params.structure, nullptr)));
            return encoder_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            mem = std::move(BIO_ptr(BIO_new(BIO_s_mem())));
            return mem.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return OSSL_ENCODER_to_bio(encoder_context.get(), mem.get()); })
        .run_pipe([&]() -> int {
            BIO_get_mem_ptr(mem.get(), &buf);
            return (nullptr == buf || 0 == buf->length) ? 0 : 1;
        });

    return (false == pipeline.failed());
#else
    return false;
#endif
}

return_t crypto_keygen::add_ossl3(crypto_key* cryptokey, uint32 nid, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto sn = OBJ_nid2ln(nid);
        if (nullptr == sn) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        EVP_PKEY* pk = nullptr;
        ret = pkey_keygen_byname(nullptr, &pk, sn);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);
        crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
        ret = cryptokey->add(std::move(key));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keygen::add_ossl3(crypto_key* cryptokey, const char* name, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY* pk = nullptr;
        ret = pkey_keygen_byname(nullptr, &pk, name);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);
        crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
        ret = cryptokey->add(std::move(key));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t crypto_keygen::add_ossl3(crypto_key* cryptokey, const char* name, const byte_t* keydata, size_t keysize, key_encoding_t encoding, keydesc&& desc) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    __try2 {
        if (nullptr == cryptokey || nullptr == name || nullptr == keydata) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY* pk = nullptr;
        ret = pkey_decode(nullptr, name, &pk, keydata, keysize, encoding);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);

        crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
        ret = cryptokey->add(std::move(key));
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
