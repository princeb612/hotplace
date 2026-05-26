/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_pqc.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_pqc.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

openssl_pqc::openssl_pqc() {}

openssl_pqc::~openssl_pqc() {}

return_t openssl_pqc::encode(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_keychain keychain;
        ret = keychain.pkey_encode(libctx, pkey, keydata, encoding, passphrase);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t openssl_pqc::decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_keychain keychain;
        ret = keychain.pkey_decode(libctx, pkey, keydata, encoding, passphrase);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t openssl_pqc::decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_keychain keychain;
        ret = keychain.pkey_decode(libctx, pkey, keystream, keysize, encoding, passphrase);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t openssl_pqc::decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || keydata.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = decode(libctx, name, pkey, keydata.data(), keydata.size(), encoding, passphrase);
    }
    __finally2 {}
    return ret;
}

return_t openssl_pqc::decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                             const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        crypto_keychain keychain;
        switch (encoding) {
            case key_encoding_priv_pem:
            case key_encoding_encrypted_priv_pem:
            case key_encoding_pub_pem:
            case key_encoding_priv_der:
            case key_encoding_encrypted_priv_der:
            case key_encoding_pub_der: {
                ret = keychain.pkey_decode_format(libctx, pkey, keystream, keysize, encoding, passphrase);
            } break;
            case key_encoding_priv_raw:
            case key_encoding_pub_raw: {
                ret = keychain.pkey_decode_raw(libctx, name, pkey, keystream, keysize, encoding);
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_pqc::encapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keycapsule, binary_t& sharedsecret) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX_ptr pkey_ctx;
    size_t keycapsule_len = 0;
    size_t sharedsecret_len = 0;

    // oqs-provider/test/oqs_test_kems.c
    // $ ./oqs_test_kems oqsprovider path/oqs.cnf

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return nullptr != pkey; })
        .run_pipe([&]() -> int {
            pkey_ctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_from_pkey(nullptr, (EVP_PKEY*)pkey, nullptr)));
            return pkey_ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_encapsulate_init(pkey_ctx.get(), nullptr); })
        .run_pipe([&]() -> int { return EVP_PKEY_encapsulate(pkey_ctx.get(), nullptr, &keycapsule_len, nullptr, &sharedsecret_len); })
        .run_pipe([&]() -> int {
            keycapsule.resize(keycapsule_len);
            sharedsecret.resize(sharedsecret_len);
            return EVP_PKEY_encapsulate(pkey_ctx.get(), keycapsule.data(), &keycapsule_len, sharedsecret.data(), &sharedsecret_len);
        });
    return pipeline.result_to_return_t();
#else
    return errorcode_t::not_supported;
#endif
}

return_t openssl_pqc::decapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, const binary_t& keycapsule, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || keycapsule.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = decapsule(libctx, pkey, keycapsule.data(), keycapsule.size(), sharedsecret);
    }
    __finally2 {}
    return ret;
}

return_t openssl_pqc::decapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, const byte_t* capsulekeystream, size_t capsulekeysize, binary_t& sharedsecret) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    size_t sharedsecret_len = 0;
    EVP_PKEY_CTX_ptr pkey_ctx;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return nullptr != pkey && nullptr != capsulekeystream; })
        .run_pipe([&]() -> int {
            pkey_ctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_from_pkey(nullptr, (EVP_PKEY*)pkey, nullptr)));
            return pkey_ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_decapsulate_init(pkey_ctx.get(), nullptr); })
        .run_pipe([&]() -> int { return EVP_PKEY_decapsulate(pkey_ctx.get(), nullptr, &sharedsecret_len, capsulekeystream, capsulekeysize); })
        .run_pipe([&]() -> int {
            sharedsecret.resize(sharedsecret_len);
            return EVP_PKEY_decapsulate(pkey_ctx.get(), sharedsecret.data(), &sharedsecret_len, capsulekeystream, capsulekeysize);
        });
    return pipeline.result_to_return_t();
#else
    return errorcode_t::not_supported;
#endif
}

return_t openssl_pqc::sign(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    signature.resize(0);
    size_t dgstsize = 0;

    EVP_MD_CTX_ptr md_context;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey && nullptr != stream); })
        .run_pipe([&]() -> int {
            md_context = std::move(EVP_MD_CTX_ptr(EVP_MD_CTX_new()));
            return md_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_DigestSignInit_ex(md_context.get(), nullptr, nullptr, libctx, nullptr, pkey, nullptr); })
        .run_pipe([&]() -> int { return EVP_DigestSignUpdate(md_context.get(), stream, size); })
        .run_pipe([&]() -> int { return EVP_DigestSignFinal(md_context.get(), nullptr, &dgstsize); })
        .walk([&]() -> void {
            signature.resize(dgstsize);
            EVP_DigestSignFinal(md_context.get(), signature.data(), &dgstsize);
            signature.resize(dgstsize);
        });
    return pipeline.failed() ? errorcode_t::verification_failure : errorcode_t::success;
#else
    return errorcode_t::not_supported;
#endif
}

return_t openssl_pqc::verify(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX_ptr md_context;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != pkey) && (nullptr != stream) && (false == signature.empty()); })
        .run_pipe([&]() -> int {
            md_context = std::move(EVP_MD_CTX_ptr(EVP_MD_CTX_new()));
            return md_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_DigestVerifyInit_ex(md_context.get(), nullptr, nullptr, libctx, nullptr, pkey, nullptr); })
        .run_pipe([&]() -> int { return EVP_DigestVerifyUpdate(md_context.get(), stream, size); })
        .run_pipe([&]() -> int { return EVP_DigestVerifyFinal(md_context.get(), signature.data(), signature.size()); });
    return pipeline.failed() ? errorcode_t::verification_failure : errorcode_t::success;
#else
    return errorcode_t::not_supported;
#endif
}

}  // namespace crypto
}  // namespace hotplace
