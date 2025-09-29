/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/pqc/oqs.hpp>

namespace hotplace {
namespace crypto {

pqc_oqs::pqc_oqs() {}

pqc_oqs::~pqc_oqs() {}

return_t pqc_oqs::open(oqs_context** context) {
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
                    if (OBJ_sn2nid(alg)) {
                        // encode/decode supported
                        // - p256_mlkem512
                        // - x25519_mlkem512
                        ctx->algs.insert({alg, opid});
                        if (OSSL_OP_KEM == opid) {
                            ctx->kemalgs.push_back(alg);
                        } else if (OSSL_OP_SIGNATURE == opid) {
                            ctx->sigalgs.push_back(alg);
                        }
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
}

return_t pqc_oqs::close(oqs_context* context) {
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
}

return_t pqc_oqs::for_each(oqs_context* context, int opid, std::function<void(const std::string&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (OSSL_OP_KEM == opid) {
            for (auto alg : context->kemalgs) {
                func(alg);
            }
        } else if (OSSL_OP_SIGNATURE == opid) {
            for (auto alg : context->sigalgs) {
                func(alg);
            }
        } else {
            ret = not_supported;
        }
    }
    __finally2 {}
    return ret;
}

return_t pqc_oqs::keygen(oqs_context* context, const std::string& alg, EVP_PKEY** pkey) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto iter = context->algs.find(alg);
        if (context->algs.end() == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        int rc = 0;
        auto pkey_ctx = EVP_PKEY_CTX_new_from_name(context->libctx, alg.c_str(), nullptr);
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
    return ret;
}

constexpr char constexpr_pem[] = "PEM";
constexpr char constexpr_der[] = "DER";
constexpr char constexpr_privkeyinfo[] = "PrivateKeyInfo";
constexpr char constexpr_encryptedprivkeyinfo[] = "EncryptedPrivateKeyInfo";
constexpr char constexpr_pubkeyinfo[] = "SubjectPublicKeyInfo";

return_t pqc_oqs::get_params(oqs_key_encoding_t encoding, oqs_key_encparams_t& params) {
    return_t ret = errorcode_t::success;
    __try2 {
        const char* format = nullptr;
        const char* structure = nullptr;
        int selection = 0;
        bool use_pass = false;
        switch (encoding) {
            case oqs_key_encoding_priv_pem: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_pem;
                params.structure = constexpr_privkeyinfo;
                params.use_pass = false;
            } break;
            case oqs_key_encoding_encrypted_priv_pem: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
                params.format = constexpr_pem;
                params.structure = constexpr_encryptedprivkeyinfo;
                params.use_pass = true;
            } break;
            case oqs_key_encoding_pub_pem: {
                params.selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_pem;
                params.structure = constexpr_pubkeyinfo;
                params.use_pass = false;
            } break;
            case oqs_key_encoding_priv_der: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_der;
                params.structure = constexpr_privkeyinfo;
                params.use_pass = false;
            } break;
            case oqs_key_encoding_encrypted_priv_der: {
                params.selection = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
                params.format = constexpr_der;
                params.structure = constexpr_encryptedprivkeyinfo;
                params.use_pass = true;
            } break;
            case oqs_key_encoding_pub_der: {
                params.selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
                params.format = constexpr_der;
                params.structure = constexpr_pubkeyinfo;
                params.use_pass = false;
            } break;
            default: {
                ret = errorcode_t::not_supported;
            }
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t pqc_oqs::encode_key(oqs_context* context, EVP_PKEY* pkey, binary_t& pubkey, oqs_key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // https://docs.openssl.org/3.5/man3/OSSL_ENCODER_CTX_new_for_pkey/
        // https://docs.openssl.org/3.5/man3/OSSL_ENCODER_to_bio/

        // provider serialization
        // oqs-provider/test/oqs_test_endecode.c
        // $ ./oqs_test_endecode oqsprovider path/oqs.cnf

        oqs_key_encparams_t params;
        get_params(encoding, params);
        if (params.use_pass && (nullptr == passphrase)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        OSSL_ENCODER_CTX* encoder_context = nullptr;
        encoder_context = OSSL_ENCODER_CTX_new_for_pkey(pkey, params.selection, params.format, params.structure, nullptr);
        if (passphrase) {
            OSSL_ENCODER_CTX_set_passphrase(encoder_context, (const unsigned char*)passphrase, strlen(passphrase));
            OSSL_ENCODER_CTX_set_cipher(encoder_context, "AES-256-CBC", nullptr);
        }

        unsigned char* pub = nullptr;
        size_t publen = 0;
        BUF_MEM* buf = nullptr;
        BIO* mem = nullptr;
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

        pubkey.resize(buf->length);
        memcpy(&pubkey[0], buf->data, buf->length);

        BIO_free(mem);
        OSSL_ENCODER_CTX_free(encoder_context);
    }
    __finally2 {}
    return ret;
}

return_t pqc_oqs::decode_key(oqs_context* context, EVP_PKEY** pkey, const binary_t& pubkey, oqs_key_encoding_t encoding, const char* passphrase) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (pubkey.empty()) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        oqs_key_encparams_t params;
        get_params(encoding, params);

        if (params.use_pass && (nullptr == passphrase)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        BIO* buf = BIO_new_mem_buf(&pubkey[0], pubkey.size());

        OSSL_DECODER_CTX* decoder_context = nullptr;
        decoder_context = OSSL_DECODER_CTX_new_for_pkey(pkey, params.format, params.structure, nullptr, params.selection, context->libctx, nullptr);
        if (passphrase) {
            OSSL_DECODER_CTX_set_passphrase(decoder_context, (const unsigned char*)passphrase, strlen(passphrase));
        }

        OSSL_DECODER_from_bio(decoder_context, buf);

        OSSL_DECODER_CTX_free(decoder_context);
    }
    __finally2 {}
    return ret;
}

return_t pqc_oqs::encapsule(oqs_context* context, EVP_PKEY* pkey, binary_t& capsulekey, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    size_t keycapsule_len = 0;
    size_t sharedsecret_len = 0;
    int test = 0;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
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
    return ret;
}

return_t pqc_oqs::decapsule(oqs_context* context, EVP_PKEY* pkey, const binary_t& capsulekey, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    EVP_PKEY_CTX* pkey_ctx = nullptr;
    size_t sharedsecret_len = 0;
    int test = 0;
    __try2 {
        if (nullptr == context || nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (capsulekey.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);
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
    return ret;
}

std::string pqc_oqs::nameof_encoding(oqs_key_encoding_t encoding) {
    std::string value;
    switch (encoding) {
        case oqs_key_encoding_priv_pem: {
            value = "PEM private key";
        } break;
        case oqs_key_encoding_encrypted_priv_pem: {
            value = "PEM encrypted private key";
        } break;
        case oqs_key_encoding_pub_pem: {
            value = "PEM public key";
        } break;
        case oqs_key_encoding_priv_der: {
            value = "DER private key";
        } break;
        case oqs_key_encoding_encrypted_priv_der: {
            value = "DER encrypted private key";
        } break;
        case oqs_key_encoding_pub_der: {
            value = "DER public key";
        } break;
    }
    return value;
}

}  // namespace crypto
}  // namespace hotplace
