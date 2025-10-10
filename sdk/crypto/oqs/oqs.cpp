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
#include <hotplace/sdk/crypto/basic/openssl_pqc.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/oqs/oqs.hpp>

namespace hotplace {
namespace crypto {

pqc_oqs::pqc_oqs() {}

pqc_oqs::~pqc_oqs() {}

return_t pqc_oqs::open(oqs_context** context) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    oqs_context* handle = nullptr;
    OSSL_LIB_CTX* libctx = nullptr;
    OSSL_PROVIDER* default_provider = nullptr;
    OSSL_PROVIDER* oqs_provider = nullptr;

    __try2 {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
        }

        __try_new_catch(handle, new oqs_context, ret, __leave2);

        libctx = OSSL_LIB_CTX_new();

        default_provider = OSSL_PROVIDER_load(libctx, "default");
        oqs_provider = OSSL_PROVIDER_load(libctx, "oqsprovider");
        if (nullptr == oqs_provider) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        auto lambda = [&](oqs_context* ctx, OSSL_PROVIDER* provider, int opid) -> void {
            int query_nocache = 0;
            auto algs = OSSL_PROVIDER_query_operation(provider, opid, &query_nocache);
            if (algs) {
                for (; algs->algorithm_names; algs++) {
                    auto alg = algs->algorithm_names;
                    int flags = 0;
                    flags |= OBJ_sn2nid(alg) ? oqs_alg_oid_registered : 0;
                    // encode/decode supported
                    // - p256_mlkem512
                    // - x25519_mlkem512
                    ctx->algs.insert({alg, opid});
                    if (OSSL_OP_KEM == opid) {
                        ctx->kemalgs.push_back({alg, flags});
                    } else if (OSSL_OP_SIGNATURE == opid) {
                        ctx->sigalgs.push_back({alg, flags});
                    }
                }
            }
        };
        lambda(handle, oqs_provider, OSSL_OP_KEM);
        lambda(handle, oqs_provider, OSSL_OP_SIGNATURE);

        handle->libctx = libctx;
        handle->default_provider = default_provider;
        handle->oqs_provider = oqs_provider;

        *context = handle;
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            OSSL_PROVIDER_unload(default_provider);
            OSSL_PROVIDER_unload(oqs_provider);
            OSSL_LIB_CTX_free(libctx);
        }
    }
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::close(oqs_context* context) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        OSSL_PROVIDER_unload(context->default_provider);
        OSSL_PROVIDER_unload(context->oqs_provider);
        OSSL_LIB_CTX_free(context->libctx);

        delete context;
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::for_each(oqs_context* context, int opid, std::function<void(const std::string&, int)> func) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (OSSL_OP_KEM == opid) {
            for (const auto& item : context->kemalgs) {
                const auto& alg = item.first;
                int flags = item.second;
                func(alg, flags);
            }
        } else if (OSSL_OP_SIGNATURE == opid) {
            for (const auto& item : context->sigalgs) {
                const auto& alg = item.first;
                int flags = item.second;
                func(alg, flags);
            }
        } else {
            ret = not_supported;
        }
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::keygen(EVP_PKEY** pkey, oqs_context* context, const std::string& alg) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto iter = context->algs.find(alg);
        if (context->algs.end() == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        crypto_keychain keychain;
        ret = keychain.pkey_gen_byname(pkey, context->libctx, alg.c_str());
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::encode(oqs_context* context, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // provider serialization
        // oqs-provider/test/oqs_test_endecode.c
        // $ ./oqs_test_endecode oqsprovider path/oqs.cnf

        crypto_keychain keychain;
        ret = keychain.pkey_encode(context->libctx, pkey, keydata, encoding, passphrase);
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::decode(oqs_context* context, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_keychain keychain;
        ret = keychain.pkey_decode(context->libctx, pkey, keydata, encoding, passphrase);
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::encapsule(oqs_context* context, EVP_PKEY* pkey, binary_t& capsulekey, binary_t& sharedsecret) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_pqc pqc;
        ret = pqc.encapsule(context->libctx, pkey, capsulekey, sharedsecret);
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::decapsule(oqs_context* context, EVP_PKEY* pkey, const binary_t& capsulekey, binary_t& sharedsecret) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_pqc pqc;
        ret = pqc.decapsule(context->libctx, pkey, capsulekey, sharedsecret);
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::sign(oqs_context* context, EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_pqc pqc;
        ret = pqc.sign(context->libctx, pkey, stream, size, signature);
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

return_t pqc_oqs::verify(oqs_context* context, EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_pqc pqc;
        ret = pqc.verify(context->libctx, pkey, stream, size, signature);
    }
    __finally2 {}
    return ret;
#else
    return not_supported;
#endif
}

}  // namespace crypto
}  // namespace hotplace
