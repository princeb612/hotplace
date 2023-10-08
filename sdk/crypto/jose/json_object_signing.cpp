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

namespace hotplace {
namespace crypto {

typedef return_t (json_object_signing::*sign_function_t) (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t& output);
typedef return_t (json_object_signing::*verify_function_t) (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t const& output, bool& result);

json_object_signing::json_object_signing ()
{
    openssl_startup ();
}

json_object_signing::~json_object_signing ()
{
    openssl_cleanup ();
}

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
            { jws_type_t::jws_type_hmac,           &json_object_signing::sign_hmac, },
            { jws_type_t::jws_type_rsassa_pkcs15,  &json_object_signing::sign_rsassa_pkcs15, },
            { jws_type_t::jws_type_ecdsa,          &json_object_signing::sign_ecdsa, },
            { jws_type_t::jws_type_rsassa_pss,     &json_object_signing::sign_rsassa_pss, },
            { jws_type_t::jws_type_eddsa,          &json_object_signing::sign_eddsa, },
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

        ret = (this->*signer)(pkey, sig, input, output);
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
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        typedef struct _SIGN_TABLE {
            int sig_type;
            verify_function_t verifier;
        } SIGN_TABLE;

        SIGN_TABLE sign_table [] = {
            { jws_type_t::jws_type_hmac,           &json_object_signing::verify_hmac, },
            { jws_type_t::jws_type_rsassa_pkcs15,  &json_object_signing::verify_rsassa_pkcs1_v1_5, },
            { jws_type_t::jws_type_ecdsa,          &json_object_signing::verify_ecdsa, },
            { jws_type_t::jws_type_rsassa_pss,     &json_object_signing::verify_rsassa_pss, },
            { jws_type_t::jws_type_eddsa,          &json_object_signing::verify_eddsa, },
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

        ret = (this->*verifier)(pkey, sig, input, output, result);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::sign_hmac (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);
    openssl_sign sign;

    ret = sign.sign_hmac (pkey, alg, input, output);
    return ret;
}

return_t json_object_signing::sign_rsassa_pkcs15 (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);
    openssl_sign sign;

    ret = sign.sign_rsassa_pkcs15 (pkey, alg, input, output);
    return ret;
}

return_t json_object_signing::sign_ecdsa (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);
    openssl_sign sign;

    ret = sign.sign_ecdsa (pkey, alg, input, output);
    return ret;
}

return_t json_object_signing::sign_eddsa (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);
    openssl_sign sign;

    ret = sign.sign_eddsa (pkey, alg, input, output);
    return ret;
}

return_t json_object_signing::sign_rsassa_pss (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);
    openssl_sign sign;

    ret = sign.sign_rsassa_pss (pkey, alg, input, output);
    return ret;
}

return_t json_object_signing::verify_hmac (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);

    result = false;

    openssl_sign sign;
    ret = sign.verify_hmac (pkey, alg, input, output);
    if (errorcode_t::success == ret) {
        result = true;
    }
    return ret;
}

return_t json_object_signing::verify_rsassa_pkcs1_v1_5 (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);

    result = false;

    openssl_sign sign;
    ret = sign.verify_digest (pkey, alg, input, output);
    if (errorcode_t::success == ret) {
        result = true;
    }
    return ret;
}

return_t json_object_signing::verify_ecdsa (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);

    result = false;

    openssl_sign sign;
    ret = sign.verify_ecdsa (pkey, alg, input, output);
    if (errorcode_t::success == ret) {
        result = true;
    }
    return ret;
}

return_t json_object_signing::verify_eddsa (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);

    result = false;

    openssl_sign sign;
    ret = sign.verify_eddsa (pkey, alg, input, output);
    if (errorcode_t::success == ret) {
        result = true;
    }
    return ret;
}

return_t json_object_signing::verify_rsassa_pss (EVP_PKEY* pkey, jws_t sig, binary_t const& input, binary_t const& output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    hash_algorithm_t alg = advisor->get_algorithm (sig);

    result = false;

    openssl_sign sign;
    ret = sign.verify_rsassa_pss (pkey, alg, input, output);
    if (errorcode_t::success == ret) {
        result = true;
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

}
}  // namespace
