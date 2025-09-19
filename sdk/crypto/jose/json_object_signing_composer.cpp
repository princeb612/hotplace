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
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing_encryption.hpp>
#include <hotplace/sdk/io/basic/json.hpp>
#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
namespace crypto {

json_object_signing::composer::composer() {}

return_t json_object_signing::composer::parse_signature(jose_context_t* handle, const char* signature) {
    return_t ret = errorcode_t::success;
    json_t* json_root = nullptr;
    split_context_t* split_handle = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == signature) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        json_object_signing_encryption::clear_context(handle);

        return_t ret_test = json_open_stream(&json_root, signature, true);
        if (errorcode_t::success == ret_test) {
            const char* payload_value = nullptr; /* payload:base64_url_encode(claims) */
            json_unpack(json_root, "{s:s}", "payload", &payload_value);
            if (nullptr == payload_value) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            json_t* json_signatures = nullptr;
            json_unpack(json_root, "{s:o}", "signatures", &json_signatures);
            if (json_signatures) {
                // 7.2.1.  General JWS JSON Serialization Syntax

                if (json_is_array(json_signatures)) {
                    size_t array_size = json_array_size(json_signatures);
                    if (0 == array_size) {
                        ret = errorcode_t::bad_data;
                        __leave2;
                    }

                    for (size_t index = 0; index < array_size; index++) {
                        json_t* json_signature = json_array_get(json_signatures, index);

                        jws_t sig = jws_t::jws_unknown;
                        const char* protected_value = nullptr; /* protected:base64_url_encode(header) */
                        const char* kid_value = nullptr;       /* header:{kid:kid_value} */
                        const char* alg_value = nullptr;       /* header:{alg:alg_value} */
                        const char* signature_value = nullptr; /* signature:base64_url_encode(signature) */
                        json_unpack(json_signature, "{s:s}", "protected", &protected_value);
                        json_unpack(json_signature, "{s:s}", "signature", &signature_value);
                        json_unpack(json_signature, "{s:{s:s}}", "header", "kid", &kid_value);
                        if (nullptr == signature_value) {
                            ret = errorcode_t::bad_data;
                            break;
                        }
                        if (nullptr == protected_value) {
                            // RFC 7520 4.7. Protecting Content Only
                            json_unpack(json_signature, "{s:{s:s}}", "header", "alg", &alg_value);
                            if (nullptr == alg_value) {
                                ret = errorcode_t::bad_data;
                                break;
                            } else {
                                advisor->typeof_jose_signature(alg_value, sig);
                            }
                        }

                        jose_sign_t item;
                        if (protected_value) {
                            item.header = protected_value;
                        }
                        item.payload = payload_value;
                        item.signature = signature_value;
                        if (kid_value) {
                            item.kid = kid_value;
                        }
                        item.sig = sig;
                        handle->signs.push_back(item);
                    }
                } else {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {
                // 7.2.2.  Flattened JWS JSON Serialization Syntax

                jws_t sig = jws_t::jws_unknown;
                const char* protected_value = nullptr; /* protected:base64_url_encode(header) */
                const char* kid_value = nullptr;       /* header:{kid:kid_value} */
                const char* alg_value = nullptr;       /* header:{alg:alg_value} */
                const char* signature_value = nullptr; /* signature:base64_url_encode(signature) */
                json_unpack(json_root, "{s:s}", "protected", &protected_value);
                json_unpack(json_root, "{s:s}", "signature", &signature_value);
                json_unpack(json_root, "{s:{s:s}}", "header", "kid", &kid_value);
                if (nullptr == signature_value) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
                if (nullptr == protected_value) {
                    json_unpack(json_root, "{s:{s:s}}", "header", "alg", &alg_value);
                    if (nullptr == kid_value) {
                        ret = errorcode_t::bad_data;
                        break;
                    } else {
                        advisor->typeof_jose_signature(alg_value, sig);
                    }
                }

                jose_sign_t item;
                if (protected_value) {
                    item.header = protected_value;
                }
                item.payload = payload_value;
                item.signature = signature_value;
                if (kid_value) {
                    item.kid = kid_value;
                }
                item.sig = sig;
                handle->signs.push_back(item);
            }
        } else {
            size_t count = 0;
            split_begin(&split_handle, signature, ".");
            split_count(split_handle, count);
            switch (count) {
                case 3:
                    break;
                case 2:
                    ret = errorcode_t::low_security;
                    break;  // not support low security reason - "alg":"none"
                default:
                    ret = errorcode_t::bad_data;
                    break;
            }
            jose_sign_t item;
            split_get(split_handle, 0, item.header);
            split_get(split_handle, 1, item.payload);
            split_get(split_handle, 2, item.signature);
            handle->signs.push_back(item);
        }

        if (handle->signs.empty()) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
    }
    __finally2 {
        if (json_root) {
            json_decref(json_root);
        }
        if (split_handle) {
            split_end(split_handle);
        }
    }
    return ret;
}

return_t json_object_signing::composer::parse_signature_protected_header(jose_context_t* handle, const char* header, jws_t& sig, std::string& keyid) {
    return_t ret = errorcode_t::success;
    json_t* json_root = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        sig = jws_t::jws_unknown;
        keyid.clear();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = json_open_stream(&json_root, header, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        const char* alg = nullptr;
        const char* kid = nullptr;
        json_unpack(json_root, "{s:s}", "alg", &alg);
        json_unpack(json_root, "{s:s}", "kid", &kid);

        advisor->typeof_jose_signature(alg, sig);
        if (kid) {
            keyid = kid;
        }
    }
    __finally2 {
        if (json_root) {
            json_decref(json_root);
        }
    }
    return ret;
}

return_t json_object_signing::composer::compose_signature(jose_context_t* handle, std::string& signature, jose_serialization_t type) {
    return_t ret = errorcode_t::success;

    __try2 {
        signature.clear();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (handle->signs.empty()) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        jose_sign_t item = handle->signs.front();

        if (jose_serialization_t::jose_compact == type) {
            // 7.1.  JWS Compact Serialization
            signature = format("%s.%s.%s", item.header.c_str(), item.payload.c_str(), item.signature.c_str());
        } else if (jose_serialization_t::jose_flatjson == type) {
            // 7.2.2.  Flattened JWS JSON Serialization Syntax
            json_t* json_serialization = nullptr;
            __try2 {
                json_serialization = json_object();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_object_set_new(json_serialization, "payload", json_string(item.payload.c_str()));
                json_object_set_new(json_serialization, "protected", json_string(item.header.c_str()));
                if (false == item.kid.empty()) {
                    json_object_set_new(json_serialization, "header", json_pack("{s,s}", "kid", item.kid.c_str()));
                }
                json_object_set_new(json_serialization, "signature", json_string(item.signature.c_str()));
                char* contents = json_dumps(json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    signature = contents;
                    free(contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2 {
                if (json_serialization) {
                    json_decref(json_serialization);
                }
            }
        } else if (jose_serialization_t::jose_json == type) {
            // 7.2.1.  General JWS JSON Serialization Syntax
            json_t* json_serialization = nullptr;
            json_t* json_signatures = nullptr;
            json_t* json_signature = nullptr;
            __try2 {
                json_serialization = json_object();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_signatures = json_array();
                if (nullptr == json_signatures) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }

                json_object_set_new(json_serialization, "payload", json_string(item.payload.c_str()));
                for (jose_signs_t::iterator iter = handle->signs.begin(); iter != handle->signs.end(); iter++) {
                    jose_sign_t item = *iter;

                    json_signature = json_object();
                    if (json_signature) {
                        json_object_set_new(json_signature, "protected", json_string(item.header.c_str()));
                        if (false == item.kid.empty()) {
                            json_object_set_new(json_signature, "header", json_pack("{s,s}", "kid", item.kid.c_str()));
                        }
                        json_object_set_new(json_signature, "signature", json_string(item.signature.c_str()));
                        json_array_append_new(json_signatures, json_signature);
                    }
                }
                json_object_set_new(json_serialization, "signatures", json_signatures);
                char* contents = json_dumps(json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    signature = contents;
                    free(contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2 {
                if (json_serialization) {
                    json_decref(json_serialization);
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
