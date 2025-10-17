/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

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

return_t openssl_pqc::encapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& capsulekey, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    size_t keycapsule_len = 0;
    size_t sharedsecret_len = 0;
    int test = 0;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, (EVP_PKEY*)pkey, nullptr);
        if (nullptr == pkey_ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        // oqs-provider/test/oqs_test_kems.c
        // $ ./oqs_test_kems oqsprovider path/oqs.cnf

        test = EVP_PKEY_encapsulate_init(pkey_ctx, nullptr);
        if (test <= 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        test = EVP_PKEY_encapsulate(pkey_ctx, nullptr, &keycapsule_len, nullptr, &sharedsecret_len);
        if (test <= 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        capsulekey.resize(keycapsule_len);
        sharedsecret.resize(sharedsecret_len);

        test = EVP_PKEY_encapsulate(pkey_ctx, &capsulekey[0], &keycapsule_len, &sharedsecret[0], &sharedsecret_len);
        if (test <= 0) {
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

return_t openssl_pqc::decapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, const binary_t& capsulekey, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    size_t sharedsecret_len = 0;
    int test = 0;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (capsulekey.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, (EVP_PKEY*)pkey, nullptr);
        if (nullptr == pkey_ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        test = EVP_PKEY_decapsulate_init(pkey_ctx, nullptr);
        if (test <= 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        test = EVP_PKEY_decapsulate(pkey_ctx, nullptr, &sharedsecret_len, &capsulekey[0], capsulekey.size());
        if (test <= 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        sharedsecret.resize(sharedsecret_len);

        test = EVP_PKEY_decapsulate(pkey_ctx, &sharedsecret[0], &sharedsecret_len, &capsulekey[0], capsulekey.size());
        if (test <= 0) {
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

return_t openssl_pqc::sign(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX* md_context = nullptr;
    int rc = 1;
    size_t dgstsize = 0;
    __try2 {
        signature.resize(0);
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        md_context = EVP_MD_CTX_new();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        rc = EVP_DigestSignInit_ex(md_context, nullptr, nullptr, libctx, nullptr, pkey, nullptr);
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        rc = EVP_DigestSignUpdate(md_context, stream, size);
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        rc = EVP_DigestSignFinal(md_context, nullptr, &dgstsize);
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        signature.resize(dgstsize);
        EVP_DigestSignFinal(md_context, &signature[0], &dgstsize);

        signature.resize(dgstsize);
    }
    __finally2 {}
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

return_t openssl_pqc::verify(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_MD_CTX* md_context = nullptr;
    int rc = 1;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        ret = errorcode_t::error_verify;
        if (signature.empty()) {
            __leave2;
        }

        md_context = EVP_MD_CTX_new();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        rc = EVP_DigestVerifyInit_ex(md_context, nullptr, nullptr, libctx, nullptr, pkey, nullptr);
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        rc = EVP_DigestVerifyUpdate(md_context, stream, size);
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        rc = EVP_DigestVerifyFinal(md_context, &signature[0], signature.size());
        if (rc < 1) {
            ret = errorcode_t::error_verify;
            __leave2_trace_openssl(ret);
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        if (nullptr != md_context) {
            EVP_MD_CTX_destroy(md_context);
        }
    }
#else
    ret = errorcode_t::not_supported;
#endif
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
