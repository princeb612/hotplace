/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   json_object_signing_encryption.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7515 JSON Web Signature (JWS)
 *  RFC 7516 JSON Web Encryption (JWE)
 *  RFC 7517 JSON Web Key (JWK)
 *  RFC 7518 JSON Web Algorithms (JWA)
 *  RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 *  RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/memory.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/crypto/jose/json_object_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_web_key.hpp>

namespace hotplace {
namespace crypto {

json_object_signing_encryption::json_object_signing_encryption() {}

json_object_signing_encryption::~json_object_signing_encryption() {}

return_t json_object_signing_encryption::open(jose_context_t** handle, crypto_key* crypto_key) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle || nullptr == crypto_key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto context = custom::make_unique<jose_context_t>();
        context->key = crypto_key;

        crypto_key->addref();

        *handle = context.get();

        context.release();
    }
    __finally2 {}
    return ret;
}

return_t json_object_signing_encryption::close(jose_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        clear_context(handle);

        if (handle->key) {
            handle->key->release();
        }
        delete handle;
    }
    __finally2 {}
    return ret;
}

return_t json_object_signing_encryption::setoption(jose_context_t* handle, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        handle->flags = flags;
    }
    __finally2 {}
    return ret;
}

return_t json_object_signing_encryption::encrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, const binary_t& input, std::string& output, jose_serialization_t type) {
    json_object_encryption jwe;

    return jwe.encrypt(handle, enc, alg, input, output, type);
}

return_t json_object_signing_encryption::encrypt(jose_context_t* handle, jwe_t enc, jwa_t alg, const std::string& input, std::string& output, jose_serialization_t type) {
    return encrypt(handle, enc, alg, to_binary(input), output, type);
}

return_t json_object_signing_encryption::encrypt2(jose_context_t* handle, const std::string& enc, const std::string& alg, const binary_t& input, std::string& output,
                                                  jose_serialization_t type) {
    auto advisor = crypto_advisor::get_instance();
    auto hint_alg = advisor->hintof_jose_algorithm(alg.c_str());
    auto hint_enc = advisor->hintof_jose_encryption(enc.c_str());
    if (hint_alg && hint_enc) {
        return encrypt(handle, hint_enc->u.enc.type, hint_alg->u.alg.type, input, output, type);
    } else {
        return errorcode_t::invalid_parameter;
    }
}

return_t json_object_signing_encryption::encrypt2(jose_context_t* handle, const std::string& enc, const std::string& alg, const std::string& input, std::string& output,
                                                  jose_serialization_t type) {
    auto advisor = crypto_advisor::get_instance();
    auto hint_alg = advisor->hintof_jose_algorithm(alg.c_str());
    auto hint_enc = advisor->hintof_jose_encryption(enc.c_str());
    if (hint_alg && hint_enc) {
        return encrypt(handle, hint_enc->u.enc.type, hint_alg->u.alg.type, input, output, type);
    } else {
        return errorcode_t::invalid_parameter;
    }
}

return_t json_object_signing_encryption::encrypt(jose_context_t* handle, jwe_t enc, const std::list<jwa_t>& algs, const binary_t& input, std::string& output,
                                                 jose_serialization_t type) {
    json_object_encryption jwe;

    return jwe.encrypt(handle, enc, algs, input, output, type);
}

return_t json_object_signing_encryption::encrypt(jose_context_t* handle, jwe_t enc, const std::list<jwa_t>& algs, const std::string& input, std::string& output,
                                                 jose_serialization_t type) {
    return encrypt(handle, enc, algs, to_binary(input), output, type);
}

return_t json_object_signing_encryption::encrypt2(jose_context_t* handle, const std::string& enc, const std::list<std::string>& algs, const binary_t& input,
                                                  std::string& output, jose_serialization_t type) {
    auto advisor = crypto_advisor::get_instance();
    auto hint_enc = advisor->hintof_jose_encryption(enc.c_str());
    if (hint_enc) {
        std::list<jwa_t> algorithms;
        for (const auto& item : algs) {
            auto hint_alg = advisor->hintof_jose_algorithm(item.c_str());
            if (hint_alg) {
                algorithms.push_back(hint_alg->u.alg.type);
            }
        }
        return encrypt(handle, hint_enc->u.enc.type, algorithms, input, output, type);
    } else {
        return errorcode_t::invalid_parameter;
    }
}

return_t json_object_signing_encryption::encrypt2(jose_context_t* handle, const std::string& enc, const std::list<std::string>& algs, const std::string& input,
                                                  std::string& output, jose_serialization_t type) {
    return encrypt2(handle, enc, algs, to_binary(input), output, type);
}

return_t json_object_signing_encryption::decrypt(jose_context_t* handle, const std::string& input, binary_t& output, bool& result) {
    json_object_encryption jwe;

    return jwe.decrypt(handle, input, output, result);
}

return_t json_object_signing_encryption::sign(jose_context_t* context, jws_t method, const std::string& input, std::string& output, jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, method, input, output, type);
}

return_t json_object_signing_encryption::sign2(jose_context_t* context, const std::string& method, const std::string& input, std::string& output,
                                               jose_serialization_t type) {
    auto advisor = crypto_advisor::get_instance();
    auto hint_sig = advisor->hintof_jose_signature(method.c_str());
    if (hint_sig) {
        return sign(context, hint_sig->jws_type, input, output, type);
    } else {
        return errorcode_t::invalid_parameter;
    }
}

return_t json_object_signing_encryption::sign(jose_context_t* context, std::list<jws_t> const& methods, const std::string& input, std::string& output,
                                              jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, methods, input, output, type);
}

return_t json_object_signing_encryption::sign2(jose_context_t* context, std::list<std::string> const& methods, const std::string& input, std::string& output,
                                               jose_serialization_t type) {
    auto advisor = crypto_advisor::get_instance();
    std::list<jws_t> algs;
    for (const auto& item : methods) {
        auto hint_sig = advisor->hintof_jose_signature(item.c_str());
        if (hint_sig) {
            algs.push_back(hint_sig->jws_type);
        }
    }
    return sign(context, algs, input, output, type);
}

return_t json_object_signing_encryption::sign(jose_context_t* context, const std::string& protected_header, const std::string& input, std::string& output,
                                              jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, protected_header, input, output, type);
}

return_t json_object_signing_encryption::sign(jose_context_t* context, std::list<std::string> const& headers, const std::string& input, std::string& output,
                                              jose_serialization_t type) {
    json_object_signing jws;

    return jws.sign(context, headers, input, output, type);
}

return_t json_object_signing_encryption::verify(jose_context_t* context, const std::string& input, bool& result) {
    json_object_signing jws;

    return jws.verify(context, input, result);
}

return_t json_object_signing_encryption::clear_context(jose_context_t* handle) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (auto& epair : handle->encryptions) {
            jose_encryption_t& encryption = epair.second;
            for (auto& rpair : encryption.recipients) {
                jose_recipient_t& recipient = rpair.second;
                EVP_PKEY_free((EVP_PKEY*)recipient.epk);
            }
        }

        handle->protected_header.clear();
        handle->encryptions.clear();
        handle->signs.clear();
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
