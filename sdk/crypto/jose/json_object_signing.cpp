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

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
namespace crypto {

json_object_signing::json_object_signing() { openssl_startup(); }

json_object_signing::~json_object_signing() { openssl_cleanup(); }

return_t json_object_signing::sign(jose_context_t* handle, jws_t sig, const std::string& input, std::string& output, jose_serialization_t type) {
    std::list<jws_t> methods;

    methods.push_back(sig);
    return sign(handle, methods, input, output, type);
}

return_t json_object_signing::sign(jose_context_t* handle, std::list<jws_t> const& methods, const std::string& input, std::string& output,
                                   jose_serialization_t type) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    output.clear();
    std::list<std::string> headers;

    for (const jws_t& sig : methods) {
        const hint_signature_t* hint = advisor->hintof_jose_signature(sig);

        if (hint) {
            json_t* json = json_object();
            if (json) {
                json_object_set_new(json, "alg", json_string(hint->jws_name));

                char* contents = json_dumps(json, JOSE_JSON_FORMAT);
                if (contents) {
                    headers.push_back(contents);
                    free(contents);
                }

                json_decref(json);
            }
        }
    }
    ret = sign(handle, headers, input, output, type);
    return ret;
}

return_t json_object_signing::sign(jose_context_t* handle, const std::string& protected_header, const std::string& input, std::string& output,
                                   jose_serialization_t type) {
    std::list<std::string> headers;

    headers.push_back(protected_header);
    return sign(handle, headers, input, output, type);
}

return_t json_object_signing::sign(jose_context_t* handle, std::list<std::string> const& headers, const std::string& input, std::string& output,
                                   jose_serialization_t type) {
    return_t ret = errorcode_t::success;
    json_object_signing::composer composer;

    __try2 {
        json_object_signing_encryption::clear_context(handle);

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        for (const auto& header : headers) {
            jws_t sig = jws_t::jws_unknown;
            std::string kid;

            composer.parse_signature_protected_header(handle, header.c_str(), sig, kid);
            if (jws_t::jws_unknown == sig) {
                size_t header_size = headers.size();
                if (header_size > 1) {
                    continue;
                } else if (header_size == 1) {
                    ret = errorcode_t::low_security;
                    break;
                }
            }

            std::string header_encoded = std::move(base64_encode((byte_t*)header.c_str(), header.size(), encoding_t::encoding_base64url));
            std::string claims_encoded = std::move(base64_encode((byte_t*)input.c_str(), input.size(), encoding_t::encoding_base64url));

            binary_t header_claims;

            header_claims.insert(header_claims.end(), header_encoded.begin(), header_encoded.end());
            header_claims.insert(header_claims.end(), '.');
            header_claims.insert(header_claims.end(), claims_encoded.begin(), claims_encoded.end());

            binary_t signature;

            return_t check = dosign(handle->key, sig, header_claims, signature, kid);
            if (errorcode_t::success != check) {
                continue;
            }

            jose_sign_t item;

            item.header = header_encoded;
            item.payload = claims_encoded;
            item.signature = std::move(base64_encode(&signature[0], signature.size(), encoding_t::encoding_base64url));

            item.kid = kid;
            item.sig = sig;
            handle->signs.push_back(item);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = composer.compose_signature(handle, output, type);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 { json_object_signing_encryption::clear_context(handle); }
    return ret;
}

return_t json_object_signing::verify(jose_context_t* handle, const std::string& input, bool& result) {
    return_t ret = errorcode_t::success;
    json_object_signing::composer composer;

    __try2 {
        json_object_signing_encryption::clear_context(handle);
        result = false;

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = composer.parse_signature(handle, input.c_str());
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::list<bool> list_result;
        for (const auto& item : handle->signs) {
            bool result_per_signature = false;

            std::string protected_header = std::move(base64_decode_careful(item.header, encoding_t::encoding_base64url));
            jws_t sig;
            std::string header_kid;

            composer.parse_signature_protected_header(handle, protected_header.c_str(), sig, header_kid);
            if (jws_t::jws_unknown == sig) {
                // RFC 7520 4.7. Protecting Content Only
                if (jws_t::jws_unknown == item.sig) {
                    continue;
                } else {
                    sig = item.sig;
                }
            }

            binary_t header_claims;

            header_claims.insert(header_claims.end(), item.header.begin(), item.header.end());
            header_claims.insert(header_claims.end(), '.');
            header_claims.insert(header_claims.end(), item.payload.begin(), item.payload.end());

            const char* kid = nullptr;  // use the key named kid

            if (item.kid.size()) {
                kid = item.kid.c_str();  // per-signature header kid
            } else if (header_kid.size()) {
                kid = header_kid.c_str();  // protected_header shared kid
            }
            binary_t signature_decoded;

            base64_decode(item.signature, signature_decoded, encoding_t::encoding_base64url);
            ret = doverify(handle->key, kid, sig, header_claims, signature_decoded, result_per_signature);
            if (errorcode_t::success != ret) {
                break;
            }
            list_result.push_back(result_per_signature);
        }

        if (handle->signs.size() == list_result.size()) {
            list_result.unique();
            if (1 == list_result.size()) {
                if (true == list_result.front()) {
                    result = true;
                }
            }
        }

        if (false == result) {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 { json_object_signing_encryption::clear_context(handle); }
    return ret;
}

return_t json_object_signing::dosign(crypto_key* key, jws_t sig, const binary_t& input, binary_t& output) {
    return_t ret = errorcode_t::success;
    std::string kid;

    ret = dosign(key, sig, input, output, kid);
    return ret;
}

return_t json_object_signing::dosign(crypto_key* key, jws_t sig, const binary_t& input, binary_t& output, std::string& kid) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const EVP_PKEY* pkey = nullptr;
        pkey = key->select(kid, sig, crypto_use_t::use_sig);
        if (nullptr == pkey) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        ret = check_constraints(sig, pkey);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // RFC 7515 A.1.  Example JWS Using HMAC SHA-256
        // RFC 7520 4.4.  HMAC-SHA2 Integrity Protection
        // jws_group_t::jws_group_hmac,

        // RFC 7515 A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
        // RFC 7520 4.1.  RSA v1.5 Signature
        // jws_group_t::jws_group_rsassa_pkcs15,

        // RFC 7515 A.3.  Example JWS Using ECDSA P-256 SHA-256
        // RFC 7515 A.4.  Example JWS Using ECDSA P-521 SHA-512
        // RFC 7520 4.3.  ECDSA Signature
        // jws_group_t::jws_group_ecdsa,

        // RFC 7520 4.2.  RSA-PSS Signature
        // jws_group_t::jws_group_rsassa_pss,

        // RFC 8037 A.4.  Ed25519 Signing
        // RFC 8037 A.5.  Ed25519 Validation
        // jws_group_t::jws_group_eddsa,

        crypto_sign_builder builder;
        auto sign = builder.set_scheme(sig).build();
        if (sign) {
            ret = sign->sign(pkey, input, output);
            sign->release();
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t json_object_signing::doverify(crypto_key* key, jws_t sig, const binary_t& input, const binary_t& output, bool& result) {
    return doverify(key, nullptr, sig, input, output, result);
}

return_t json_object_signing::doverify(crypto_key* key, const char* kid, jws_t sig, const binary_t& input, const binary_t& output, bool& result) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        result = false;

        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const EVP_PKEY* pkey = nullptr;
        pkey = key->find(kid, sig, crypto_use_t::use_sig);
        if (nullptr == pkey) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        ret = check_constraints(sig, pkey);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // RFC 7515 A.1.  Example JWS Using HMAC SHA-256
        // RFC 7520 4.4.  HMAC-SHA2 Integrity Protection
        // jws_group_t::jws_group_hmac,

        // RFC 7515 A.2.  Example JWS Using RSASSA-PKCS1-v1_5 SHA-256
        // RFC 7520 4.1.  RSA v1.5 Signature
        // jws_group_t::jws_group_rsassa_pkcs15,

        // RFC 7515 A.3.  Example JWS Using ECDSA P-256 SHA-256
        // RFC 7515 A.4.  Example JWS Using ECDSA P-521 SHA-512
        // RFC 7520 4.3.  ECDSA Signature
        // jws_group_t::jws_group_ecdsa,

        // RFC 7520 4.2.  RSA-PSS Signature
        // jws_group_t::jws_group_rsassa_pss,

        // RFC 8037 A.4.  Ed25519 Signing
        // RFC 8037 A.5.  Ed25519 Validation
        // jws_group_t::jws_group_eddsa,

        crypto_sign_builder builder;
        auto sign = builder.set_scheme(sig).build();
        if (sign) {
            ret = sign->verify(pkey, input, output);
            sign->release();
        }

        if (errorcode_t::success == ret) {
            result = true;
        }
    }
    __finally2 {}
    return ret;
}

return_t json_object_signing::check_constraints(jws_t sig, const EVP_PKEY* pkey) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        /*
         * RFC 7518 3.3.  Digital Signature with RSASSA-PKCS1-v1_5
         * RFC 7518 3.5.  Digital Signature with RSASSA-PSS
         * A key of size 2048 bits or larger MUST be used with these algorithms.
         */
        const hint_signature_t* hint = advisor->hintof_jose_signature(sig);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        int group = hint->group;
        switch (group) {
            case jws_group_t::jws_group_rsassa_pkcs15:
            case jws_group_t::jws_group_rsassa_pss: {
                int bits = EVP_PKEY_bits(pkey);
                if (bits < 2048) {
                    ret = errorcode_t::low_security;
                    __leave2;
                }
            } break;
            default:
                break;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
