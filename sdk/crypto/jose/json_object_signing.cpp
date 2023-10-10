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

json_object_signing::json_object_signing ()
{
    openssl_startup ();
}

json_object_signing::~json_object_signing ()
{
    openssl_cleanup ();
}

return_t json_object_signing::sign (jose_context_t* handle, jws_t sig, std::string const& input, std::string& output, jose_serialization_t type)
{
    std::list <jws_t> methods;

    methods.push_back (sig);
    return sign (handle, methods, input, output, type);
}

return_t json_object_signing::sign (jose_context_t* handle, std::list <jws_t> const& methods, std::string const& input, std::string& output, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    output.clear ();
    std::list<std::string> headers;

    for (std::list <jws_t>::const_iterator method_iter = methods.begin (); method_iter != methods.end (); method_iter++) {
        jws_t sig = *method_iter;

        const hint_signature_t* hint = advisor->hintof_jose_signature (sig);

        if (hint) {
            json_t* json = json_object ();
            if (json) {
                json_object_set_new (json, "alg", json_string (hint->jws_name));

                char* contents = json_dumps (json, JOSE_JSON_FORMAT);
                if (contents) {
                    headers.push_back (contents);
                    free (contents);
                }

                json_decref (json);
            }
        }
    }
    ret = sign (handle, headers, input, output, type);
    return ret;
}

return_t json_object_signing::sign (jose_context_t* handle, std::string const& protected_header, std::string const& input, std::string& output, jose_serialization_t type)
{
    std::list <std::string> headers;

    headers.push_back (protected_header);
    return sign (handle, headers, input, output, type);
}

return_t json_object_signing::sign (jose_context_t* handle, std::list<std::string> const& headers, std::string const& input, std::string& output, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;
    json_object_signing sign;

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        json_object_signing_encryption::clear_context (handle);

        for (std::list<std::string>::const_iterator iter = headers.begin (); iter != headers.end (); iter++) {
            std::string header = *iter;

            jws_t sig = jws_t::jws_unknown;
            std::string kid;

            parse_signature_header (handle, header.c_str (), sig, kid);
            if (jws_t::jws_unknown == sig) {
                size_t header_size = headers.size ();
                if (header_size > 1) {
                    continue;
                } else if (header_size == 1) {
                    ret = errorcode_t::low_security;
                    break;
                }
            }

            std::string header_encoded = base64_encode ((byte_t*) header.c_str (), header.size (), base64_encoding_t::base64url_encoding);
            std::string claims_encoded = base64_encode ((byte_t*) input.c_str (), input.size (), base64_encoding_t::base64url_encoding);

            binary_t header_claims;

            header_claims.insert (header_claims.end (), header_encoded.begin (), header_encoded.end ());
            header_claims.insert (header_claims.end (), '.');
            header_claims.insert (header_claims.end (), claims_encoded.begin (), claims_encoded.end ());

            binary_t signature;

            return_t check = sign.sign (handle->key, sig, header_claims, signature, kid);
            if (errorcode_t::success != check) {
                continue;
            }

            jose_sign_t item;

            item.header = header_encoded;
            item.payload = claims_encoded;
            item.signature = base64_encode (&signature[0], signature.size (), base64_encoding_t::base64url_encoding);

            item.kid = kid;
            item.sig = sig;
            handle->signs.push_back (item);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = write_signature (handle, output, type);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::verify (jose_context_t* handle, std::string const& input, bool& result)
{
    return_t ret = errorcode_t::success;
    json_object_signing sign;

    __try2
    {
        result = false;
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = read_signature (handle, input.c_str ());
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::list <bool> list_result;
        for (jose_signs_t::iterator iter = handle->signs.begin (); iter != handle->signs.end (); iter++) {
            jose_sign_t item = *iter;

            bool result_per_signature = false;

            std::string protected_header = base64_decode_careful (item.header, base64_encoding_t::base64url_encoding);
            jws_t sig;
            std::string header_kid;

            parse_signature_header (handle, protected_header.c_str (), sig, header_kid);
            if (jws_t::jws_unknown == sig) {
                // RFC 7520 4.7. Protecting Content Only
                if (jws_t::jws_unknown == item.sig) {
                    continue;
                } else {
                    sig = item.sig;
                }
            }

            binary_t header_claims;

            header_claims.insert (header_claims.end (), item.header.begin (), item.header.end ());
            header_claims.insert (header_claims.end (), '.');
            header_claims.insert (header_claims.end (), item.payload.begin (), item.payload.end ());

            const char* kid = nullptr;         // use the key named kid

            if (item.kid.size ()) {
                kid = item.kid.c_str ();    // per-signature header kid
            } else if (header_kid.size ()) {
                kid = header_kid.c_str ();  // protected_header shared kid

            }
            binary_t signature_decoded;

            base64_decode (item.signature, signature_decoded, base64_encoding_t::base64url_encoding);
            ret = sign.verify (handle->key, kid, sig, header_claims, signature_decoded, result_per_signature);
            if (errorcode_t::success != ret) {
                break;
            }
            list_result.push_back (result_per_signature);
        }

        if (handle->signs.size () == list_result.size ()) {
            list_result.unique ();
            if (1 == list_result.size ()) {
                if (true == list_result.front ()) {
                    result = true;
                }
            }
        }

        if (false == result) {
            ret = errorcode_t::verify;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

typedef return_t (openssl_sign::*sign_function_t) (EVP_PKEY* pkey, hash_algorithm_t sig, binary_t const& input, binary_t& output);
typedef return_t (openssl_sign::*verify_function_t) (EVP_PKEY* pkey, hash_algorithm_t sig, binary_t const& input, binary_t const& output);

return_t json_object_signing::sign (crypto_key* key, jws_t sig, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    std::string kid;

    ret = sign (key, sig, input, output, kid);
    return ret;
}

return_t json_object_signing::sign (crypto_key* key, jws_t sig, binary_t const& input, binary_t& output, std::string& kid)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        typedef struct _SIGN_TABLE {
            int sig_type;
            sign_function_t signer;
        } SIGN_TABLE;

        SIGN_TABLE sign_table [] = {
            { jws_type_t::jws_type_hmac,           &openssl_sign::sign_hmac, },
            { jws_type_t::jws_type_rsassa_pkcs15,  &openssl_sign::sign_rsassa_pkcs15, },
            { jws_type_t::jws_type_ecdsa,          &openssl_sign::sign_ecdsa, },
            { jws_type_t::jws_type_rsassa_pss,     &openssl_sign::sign_rsassa_pss, },
            { jws_type_t::jws_type_eddsa,          &openssl_sign::sign_eddsa, },
        };

        sign_function_t signer = nullptr;
        int sig_type = CRYPT_SIG_TYPE (sig);

#if __cplusplus >= 201103L    // c++11
        const SIGN_TABLE * item = std::find_if (
            std::begin (sign_table), std::end (sign_table), [sig_type] (const SIGN_TABLE& item) {
                    return item.sig_type == sig_type;
                } );
        if (std::end (sign_table) != item) {
            signer = item->signer;
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#else
        for (size_t k = 0; k < RTL_NUMBER_OF (sign_table); k++) {
            SIGN_TABLE* item = sign_table + k;
            if (item->sig_type == sig_type) {
                signer = item->signer;
                break;
            }
        }
        if (nullptr == signer) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif

        EVP_PKEY* pkey = nullptr;
        pkey = key->select (kid, sig, crypto_use_t::use_sig);
        if (nullptr == pkey) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        ret = check_constraints (sig, pkey);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance ();
        hash_algorithm_t alg = advisor->get_algorithm (sig);
        openssl_sign signprocessor;

        ret = (signprocessor.*signer)(pkey, alg, input, output);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::verify (crypto_key* key, jws_t sig, binary_t const& input, binary_t const& output, bool& result)
{
    return verify (key, nullptr, sig, input, output, result);
}

return_t json_object_signing::verify (crypto_key* key, const char* kid, jws_t sig, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        result = false;

        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        typedef struct _SIGN_TABLE {
            int sig_type;
            verify_function_t verifier;
        } SIGN_TABLE;

        SIGN_TABLE sign_table [] = {
            { jws_type_t::jws_type_hmac,           &openssl_sign::verify_hmac, },
            { jws_type_t::jws_type_rsassa_pkcs15,  &openssl_sign::verify_digest, },
            { jws_type_t::jws_type_ecdsa,          &openssl_sign::verify_ecdsa, },
            { jws_type_t::jws_type_rsassa_pss,     &openssl_sign::verify_rsassa_pss, },
            { jws_type_t::jws_type_eddsa,          &openssl_sign::verify_eddsa, },
        };

        verify_function_t verifier = nullptr;
        int sig_type = CRYPT_SIG_TYPE (sig);

#if __cplusplus >= 201103L    // c++11
        const SIGN_TABLE * item = std::find_if (
            std::begin (sign_table), std::end (sign_table), [sig_type] (const SIGN_TABLE& item) {
                    return item.sig_type == sig_type;
                } );
        if (std::end (sign_table) != item) {
            verifier = item->verifier;
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#else
        for (size_t k = 0; k < RTL_NUMBER_OF (sign_table); k++) {
            SIGN_TABLE* item = sign_table + k;
            if (item->sig_type == sig_type) {
                verifier = item->verifier;
                break;
            }
        }
        if (nullptr == verifier) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif

        EVP_PKEY* pkey = nullptr;
        pkey = key->find (kid, sig, crypto_use_t::use_sig);
        if (nullptr == pkey) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        ret = check_constraints (sig, pkey);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance ();
        hash_algorithm_t alg = advisor->get_algorithm (sig);
        openssl_sign signprocessor;

        ret = (signprocessor.*verifier)(pkey, alg, input, output);
        if (errorcode_t::success == ret) {
            result = true;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::check_constraints (jws_t sig, EVP_PKEY* pkey)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        /*
         * RFC 7518 3.3.  Digital Signature with RSASSA-PKCS1-v1_5
         * RFC 7518 3.5.  Digital Signature with RSASSA-PSS
         * A key of size 2048 bits or larger MUST be used with these algorithms.
         */
        int sig_type = CRYPT_SIG_TYPE (sig);
        switch (sig_type) {
            case jws_type_t::jws_type_rsassa_pkcs15:
            case jws_type_t::jws_type_rsassa_pss:
            {
                int bits = EVP_PKEY_bits ((EVP_PKEY*) pkey);
                if (bits < 2048) {
                    ret = errorcode_t::low_security;
                    __leave2;
                }
            }
            break;
            default:
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::read_signature (jose_context_t* handle, const char* signature)
{
    return_t ret = errorcode_t::success;
    json_t* json_root = nullptr;
    split_context_t* split_handle = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == signature) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        json_object_signing_encryption::clear_context (handle);

        return_t ret_test = json_open_stream (&json_root, signature, true);
        if (errorcode_t::success == ret_test) {
            const char* payload_value = nullptr; /* payload:base64_url_encode(claims) */
            json_unpack (json_root, "{s:s}", "payload", &payload_value);
            if (nullptr == payload_value) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            json_t* json_signatures = nullptr;
            json_unpack (json_root, "{s:o}", "signatures", &json_signatures);
            if (json_signatures) {
                // 7.2.1.  General JWS JSON Serialization Syntax

                if (json_is_array (json_signatures)) {
                    size_t array_size = json_array_size (json_signatures);
                    if (0 == array_size) {
                        ret = errorcode_t::bad_data;
                        __leave2;
                    }

                    for (size_t index = 0; index < array_size; index++) {
                        json_t* json_signature = json_array_get (json_signatures, index);

                        jws_t sig = jws_t::jws_unknown;
                        const char* protected_value = nullptr;  /* protected:base64_url_encode(header) */
                        const char* kid_value = nullptr;        /* header:{kid:kid_value} */
                        const char* alg_value = nullptr;        /* header:{alg:alg_value} */
                        const char* signature_value = nullptr;  /* signature:base64_url_encode(signature) */
                        json_unpack (json_signature, "{s:s}", "protected", &protected_value);
                        json_unpack (json_signature, "{s:s}", "signature", &signature_value);
                        json_unpack (json_signature, "{s:{s:s}}", "header", "kid", &kid_value);
                        if (nullptr == signature_value) {
                            ret = errorcode_t::bad_data;
                            break;
                        }
                        if (nullptr == protected_value) {
                            // RFC 7520 4.7. Protecting Content Only
                            json_unpack (json_signature, "{s:{s:s}}", "header", "alg", &alg_value);
                            if (nullptr == alg_value) {
                                ret = errorcode_t::bad_data;
                                break;
                            } else {
                                advisor->typeof_jose_signature (alg_value, sig);
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
                        handle->signs.push_back (item);

                    }
                } else {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {
                // 7.2.2.  Flattened JWS JSON Serialization Syntax

                jws_t sig = jws_t::jws_unknown;
                const char* protected_value = nullptr;  /* protected:base64_url_encode(header) */
                const char* kid_value = nullptr;        /* header:{kid:kid_value} */
                const char* alg_value = nullptr;        /* header:{alg:alg_value} */
                const char* signature_value = nullptr;  /* signature:base64_url_encode(signature) */
                json_unpack (json_root, "{s:s}", "protected", &protected_value);
                json_unpack (json_root, "{s:s}", "signature", &signature_value);
                json_unpack (json_root, "{s:{s:s}}", "header", "kid", &kid_value);
                if (nullptr == signature_value) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
                if (nullptr == protected_value) {
                    json_unpack (json_root, "{s:{s:s}}", "header", "alg", &alg_value);
                    if (nullptr == kid_value) {
                        ret = errorcode_t::bad_data;
                        break;
                    } else {
                        advisor->typeof_jose_signature (alg_value, sig);
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
                handle->signs.push_back (item);

            }
        } else {
            size_t count = 0;
            split_begin (&split_handle, signature, ".");
            split_count (split_handle, count);
            switch (count) {
                case 3: break;
                case 2: ret = errorcode_t::low_security; break;  // not support low security reason - "alg":"none"
                default: ret = errorcode_t::bad_data; break;
            }
            jose_sign_t item;
            split_get (split_handle, 0, item.header);
            split_get (split_handle, 1, item.payload);
            split_get (split_handle, 2, item.signature);
            handle->signs.push_back (item);
        }

        if (handle->signs.empty ()) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
    }
    __finally2
    {
        if (json_root) {
            json_decref (json_root);
        }
        if (split_handle) {
            split_end (split_handle);
        }
    }
    return ret;
}

return_t json_object_signing::write_signature (jose_context_t* handle, std::string& signature, jose_serialization_t type)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        signature.clear ();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (handle->signs.empty ()) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        jose_sign_t item = handle->signs.front ();

        if (jose_serialization_t::jose_compact == type) {
            signature = format ("%s.%s.%s", item.header.c_str (), item.payload.c_str (), item.signature.c_str ());
        } else if (jose_serialization_t::jose_flatjson == type) {
            json_t* json_serialization = nullptr;
            __try2
            {
                json_serialization = json_object ();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_object_set_new (json_serialization, "payload", json_string (item.payload.c_str ()));
                json_object_set_new (json_serialization, "protected", json_string (item.header.c_str ()));
                if (false == item.kid.empty ()) {
                    json_object_set_new (json_serialization, "header", json_pack ("{s,s}", "kid", item.kid.c_str ()));
                }
                json_object_set_new (json_serialization, "signature", json_string (item.signature.c_str ()));
                char* contents = json_dumps (json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    signature = contents;
                    free (contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2
            {
                if (json_serialization) {
                    json_decref (json_serialization);
                }
            }
        } else if (jose_serialization_t::jose_json == type) {
            json_t* json_serialization = nullptr;
            json_t* json_signatures = nullptr;
            json_t* json_signature = nullptr;
            __try2
            {
                json_serialization = json_object ();
                if (nullptr == json_serialization) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
                json_signatures = json_array ();
                if (nullptr == json_signatures) {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }

                json_object_set_new (json_serialization, "payload", json_string (item.payload.c_str ()));
                for (jose_signs_t::iterator iter = handle->signs.begin (); iter != handle->signs.end (); iter++) {
                    jose_sign_t item = *iter;

                    json_signature = json_object ();
                    if (json_signature) {
                        json_object_set_new (json_signature, "protected", json_string (item.header.c_str ()));
                        if (false == item.kid.empty ()) {
                            json_object_set_new (json_signature, "header", json_pack ("{s,s}", "kid", item.kid.c_str ()));
                        }
                        json_object_set_new (json_signature, "signature", json_string (item.signature.c_str ()));
                        json_array_append_new (json_signatures, json_signature);
                    }
                }
                json_object_set_new (json_serialization, "signatures", json_signatures);
                char* contents = json_dumps (json_serialization, JOSE_JSON_FORMAT);
                if (nullptr != contents) {
                    signature = contents;
                    free (contents);
                } else {
                    ret = errorcode_t::internal_error;
                    __leave2;
                }
            }
            __finally2
            {
                if (json_serialization) {
                    json_decref (json_serialization);
                }
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::parse_signature_header (jose_context_t* handle, const char* header, jws_t& sig, std::string& keyid)
{
    return_t ret = errorcode_t::success;
    json_t* json_root = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        sig = jws_t::jws_unknown;
        keyid.clear ();

        if (nullptr == handle) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = json_open_stream (&json_root, header, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        const char* alg = nullptr;
        const char* kid = nullptr;
        json_unpack (json_root, "{s:s}", "alg", &alg);
        json_unpack (json_root, "{s:s}", "kid", &kid);

        advisor->typeof_jose_signature (alg, sig);
        if (kid) {
            keyid = kid;
        }
    }
    __finally2
    {
        if (json_root) {
            json_decref (json_root);
        }
    }
    return ret;
}

}
}  // namespace
