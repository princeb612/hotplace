/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7515 JSON Web Signature (JWS)
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <hotplace/sdk/crypto/jose/json_web_signature.hpp>

namespace hotplace {
namespace crypto {

json_web_signature::json_web_signature() {}

json_web_signature::~json_web_signature() {}

return_t json_web_signature::sign(crypto_key* crypto_key, const std::string& header, const std::string& claims, std::string& signature,
                                  jose_serialization_t mode) {
    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    jose_context_t* jose_context = nullptr;

    __try2 {
        ret = jose.open(&jose_context, crypto_key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = jose.sign(jose_context, header, claims, signature, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 { jose.close(jose_context); }
    return ret;
}

return_t json_web_signature::sign(crypto_key* crypto_key, std::list<std::string> const& headers, const std::string& claims, std::string& signature,
                                  jose_serialization_t mode) {
    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    jose_context_t* jose_context = nullptr;

    __try2 {
        ret = jose.open(&jose_context, crypto_key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = jose.sign(jose_context, headers, claims, signature, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 { jose.close(jose_context); }
    return ret;
}

return_t json_web_signature::sign(crypto_key* crypto_key, jws_t alg, const std::string& claims, std::string& signature, jose_serialization_t mode) {
    std::list<jws_t> algs;

    algs.push_back(alg);
    return sign(crypto_key, algs, claims, signature, mode);
}

return_t json_web_signature::sign(crypto_key* crypto_key, std::list<jws_t> const& algs, const std::string& claims, std::string& signature,
                                  jose_serialization_t mode) {
    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    jose_context_t* jose_context = nullptr;

    __try2 {
        ret = jose.open(&jose_context, crypto_key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = jose.sign(jose_context, algs, claims, signature, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 { jose.close(jose_context); }
    return ret;
}

return_t json_web_signature::verify(crypto_key* crypto_key, const std::string& signature, bool& result) {
    return_t ret = errorcode_t::success;
    json_object_signing_encryption jose;
    jose_context_t* jose_context = nullptr;

    __try2 {
        ret = jose.open(&jose_context, crypto_key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = jose.verify(jose_context, signature, result);
    }
    __finally2 { jose.close(jose_context); }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
