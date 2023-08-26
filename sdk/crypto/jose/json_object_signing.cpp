/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/jose/json_object_signing.hpp>

namespace hotplace {
namespace crypto {

typedef return_t (json_object_signing::*sign_function_t) (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t& output);
typedef return_t (json_object_signing::*verify_function_t) (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t output, bool& result);

json_object_signing::json_object_signing ()
{
    openssl_startup ();
}

json_object_signing::~json_object_signing ()
{
    openssl_cleanup ();
}

return_t json_object_signing::sign (crypto_key* key, jws_t sig, binary_t input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    std::string kid;

    ret = sign (key, sig, input, output, kid);
    return ret;
}

return_t json_object_signing::sign (crypto_key* key, jws_t sig, binary_t input, binary_t& output, std::string& kid)
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
            { jws_type_t::jws_type_hmac,           &json_object_signing::sign_general, },
            { jws_type_t::jws_type_rsassa_pkcs15,  &json_object_signing::sign_general, },
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
            __leave2_trace (ret);
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
            __leave2_trace (ret);
        }
#endif

        EVP_PKEY* pkey = nullptr;
        pkey = key->select (kid, sig, crypto_use_t::use_sig);
        if (nullptr == pkey) {
            ret = errorcode_t::not_found;
            __leave2_trace (ret);
        }

        ret = check_constraints (sig, pkey);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = (this->*signer)(pkey, sig, input, output);
        if (errorcode_t::success != ret) {
            __leave2_trace (ret);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::verify (crypto_key* key, jws_t sig, binary_t input, binary_t output, bool& result)
{
    return verify (key, nullptr, sig, input, output, result);
}

return_t json_object_signing::verify (crypto_key* key, const char* kid, jws_t sig, binary_t input, binary_t output, bool& result)
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
            __leave2_trace (ret);
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

return_t json_object_signing::sign_general (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    EVP_MD_CTX* md_context = nullptr;
    int ret_openssl = 1;
    size_t size = 0;

    __try2
    {
        output.resize (0);
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_MD* evp_md = (EVP_MD*) advisor->find_evp_md (sig);

        md_context = EVP_MD_CTX_create ();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_openssl = EVP_DigestInit_ex (md_context, evp_md, nullptr);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }
        ret_openssl = EVP_DigestSignInit (md_context, nullptr, evp_md, nullptr, (EVP_PKEY *) pkey);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }
        ret_openssl = EVP_DigestSignUpdate (md_context, &input[0], input.size ());
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }
        ret_openssl = EVP_DigestSignFinal (md_context, nullptr, &size);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        output.resize (size);
        EVP_DigestSignFinal (md_context, &output[0], &size);
    }
    __finally2
    {
        if (nullptr != md_context) {
            EVP_MD_CTX_destroy (md_context);
        }
    }
    return ret;
}

return_t json_object_signing::sign_ecdsa (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    ECDSA_SIG* ecdsa_sig = nullptr;

    __try2
    {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        hash_algorithm_t hash_algorithm = advisor->get_algorithm (sig);
        hash.open (&hash_handle, hash_algorithm);
        hash.hash (hash_handle, &input[0], input.size (), hash_value);
        hash.close (hash_handle);

        int unitsize = 0;
        //EC_KEY* ec = EVP_PKEY_get1_EC_KEY ((EVP_PKEY*)pkey);
        //const EC_GROUP* group = EC_KEY_get0_group (ec);
        //int nid = EC_GROUP_get_curve_name (group);
        //NID_X9_62_prime256v1
        //NID_secp384r1
        //NID_secp521r1
        //EC_KEY_free (ec);

        int alg = advisor->get_algorithm (sig);
        switch (alg) {
            case hash_algorithm_t::sha2_256: unitsize = 32; break;
            case hash_algorithm_t::sha2_384: unitsize = 48; break;
            case hash_algorithm_t::sha2_512: unitsize = 66; break;
        }

        output.resize (unitsize * 2);

        /*
         * Computes the ECDSA signature of the given hash value using
         * the supplied private key and returns the created signature.
         */
        ecdsa_sig = ECDSA_do_sign (&hash_value[0], hash_value.size (), (EC_KEY*) EVP_PKEY_get0_EC_KEY ((EVP_PKEY*) pkey)); // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        if (nullptr == ecdsa_sig) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        const BIGNUM *pr = nullptr;
        const BIGNUM *ps = nullptr;

        ECDSA_SIG_get0 (ecdsa_sig, &pr, &ps);

        int rlen = BN_num_bytes (pr);
        int slen = BN_num_bytes (ps);
        /*
         * if unitsize is 4 and r is 12, s is 34
         *  r(4 bytes)  + s(4 bytes)
         *  00 00 00 12 | 00 00 00 34 -> valid
         *  12 00 00 00 | 34 00 00 00 -> invalid
         */
        BN_bn2bin (pr, &output[unitsize - rlen]);
        BN_bn2bin (ps, &output[unitsize + (unitsize - slen)]);
    }
    __finally2
    {
        if (nullptr != ecdsa_sig) {
            ECDSA_SIG_free (ecdsa_sig);
        }
    }
    return ret;
}

return_t json_object_signing::sign_eddsa (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    EVP_MD_CTX* ctx = nullptr;
    int ret_test = 0;

    __try2
    {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ctx = EVP_MD_CTX_new ();
        ret_test = EVP_DigestSignInit (ctx, nullptr, nullptr, nullptr, (EVP_PKEY*) pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        size_t size = 256;
        output.resize (size);
        ret_test = EVP_DigestSign (ctx, &output[0], &size, (byte_t*) &input[0], input.size ());
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }
        output.resize (size);
    }
    __finally2
    {
        if (ctx) {
            EVP_MD_CTX_destroy (ctx);
        }
    }
    return ret;
}

return_t json_object_signing::sign_rsassa_pss (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t& output)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    int ret_openssl = 0;

    __try2
    {
        output.resize (0);

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        hash_algorithm_t hash_algorithm = advisor->get_algorithm (sig);
        hash.open (&hash_handle, hash_algorithm);
        hash.hash (hash_handle, &input[0], input.size (), hash_value);
        hash.close (hash_handle);

        EVP_MD* evp_md = (EVP_MD*) advisor->find_evp_md (sig);

        binary_t buf;
        EVP_PKEY* key = (EVP_PKEY *) pkey;
        RSA* rsa = (RSA*) EVP_PKEY_get0_RSA (key); // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        int bufsize = RSA_size (rsa);
        buf.resize (bufsize);

        ret_openssl = RSA_padding_add_PKCS1_PSS (rsa, &buf[0], &hash_value[0], evp_md, -1);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }

        output.resize (bufsize);
        ret_openssl = RSA_private_encrypt (bufsize, &buf[0], &output[0], rsa, RSA_NO_PADDING);
        if (ret_openssl != bufsize) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::verify_hmac (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t output, bool& result)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        result = false;
        binary_t ds;
        ret = sign_general (pkey, sig, input, ds);
        if (ds == output) {
            result = true;
        } else {
            ret = errorcode_t::verify;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

return_t json_object_signing::verify_rsassa_pkcs1_v1_5 (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    EVP_MD_CTX* md_context = nullptr;
    int ret_openssl = 1;

    __try2
    {
        result = false;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = errorcode_t::verify;

        EVP_MD* evp_md = (EVP_MD*) advisor->find_evp_md (sig);

        md_context = EVP_MD_CTX_create ();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_openssl = EVP_DigestInit_ex (md_context, evp_md, nullptr);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_openssl = EVP_DigestVerifyInit (md_context, nullptr, evp_md, nullptr, (EVP_PKEY *) pkey);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_openssl = EVP_DigestVerifyUpdate (md_context, &input[0], input.size ());
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_openssl = EVP_DigestVerifyFinal (md_context, &output[0], output.size ());
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        result = true;
        ret = errorcode_t::success;
    }
    __finally2
    {
        if (nullptr != md_context) {
            EVP_MD_CTX_destroy (md_context);
        }
    }
    return ret;
}

return_t json_object_signing::verify_ecdsa (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    ECDSA_SIG* ecdsa_sig = nullptr;
    int ret_openssl = 1;

    __try2
    {
        result = false;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = errorcode_t::verify;
#if 0
        crypto_key crypto_key;
        binary_t pub1, pub2, priv;
        crypto_key.add (pkey, nullptr, true);
        crypto_key.get_key (pkey, pub1, pub2, priv);
#endif

        hash_algorithm_t hash_algorithm = advisor->get_algorithm (sig);
        hash.open (&hash_handle, hash_algorithm);
        hash.hash (hash_handle, &input[0], input.size (), hash_value);
        hash.close (hash_handle);

        uint32 unitsize = 0;
        //EC_KEY* ec = EVP_PKEY_get1_EC_KEY ((EVP_PKEY*)pkey);
        //const EC_GROUP* group = EC_KEY_get0_group (ec);
        //int nid = EC_GROUP_get_curve_name (group);
        //NID_X9_62_prime256v1
        //NID_secp384r1
        //NID_secp521r1
        //EC_KEY_free (ec);

        int alg = advisor->get_algorithm (sig);
        switch (alg) {
            case hash_algorithm_t::sha2_256: unitsize = 32; break;
            case hash_algorithm_t::sha2_384: unitsize = 48; break;
            case hash_algorithm_t::sha2_512: unitsize = 66; break;
        }

        if (output.size () < (unitsize * 2)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ecdsa_sig = ECDSA_SIG_new ();
        if (nullptr == ecdsa_sig) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        BIGNUM* bn_r = nullptr;
        BIGNUM* bn_s = nullptr;
        bn_r = BN_bin2bn (&output[0], unitsize, nullptr);
        bn_s = BN_bin2bn (&output[unitsize], unitsize, nullptr);

        ECDSA_SIG_set0 (ecdsa_sig, bn_r, bn_s);

        /* Verifies that the supplied signature is a valid ECDSA
         * signature of the supplied hash value using the supplied public key.
         */
        ret_openssl = ECDSA_do_verify (&hash_value[0], hash_value.size (), ecdsa_sig, (EC_KEY*) EVP_PKEY_get0_EC_KEY ((EVP_PKEY*) pkey)); // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        if (1 != ret_openssl) {
            ret = errorcode_t::verify;
            __leave2_trace_openssl (ret);
        }

        result = true;
        ret = errorcode_t::success;
    }
    __finally2
    {
        if (nullptr != ecdsa_sig) {
            ECDSA_SIG_free (ecdsa_sig);
        }
    }
    return ret;
}

return_t json_object_signing::verify_eddsa (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t output, bool& result)
{
    return_t ret = errorcode_t::success;
    EVP_MD_CTX* ctx = nullptr;
    int ret_test = 0;

    __try2
    {
        result = false;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = errorcode_t::verify;

        ctx = EVP_MD_CTX_new ();
        ret_test = EVP_DigestVerifyInit (ctx, nullptr, nullptr, nullptr, (EVP_PKEY*) pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_test = EVP_DigestVerify (ctx, &output[0], output.size (), &input[0], input.size ());
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        result = true;
        ret = errorcode_t::success;
    }
    __finally2
    {
        if (ctx) {
            EVP_MD_CTX_destroy (ctx);
        }
    }
    return ret;
}

return_t json_object_signing::verify_rsassa_pss (EVP_PKEY* pkey, jws_t sig, binary_t input, binary_t output, bool& result)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    int ret_openssl = 0;

    __try2
    {
        result = false;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = errorcode_t::verify;

        hash_algorithm_t hash_algorithm = advisor->get_algorithm (sig);
        hash.open (&hash_handle, hash_algorithm);
        hash.hash (hash_handle, &input[0], input.size (), hash_value);
        hash.close (hash_handle);

        EVP_MD* evp_md = (EVP_MD*) advisor->find_evp_md (sig);

        binary_t buf;
        EVP_PKEY* key = (EVP_PKEY *) pkey;
        RSA* rsa = (RSA*) EVP_PKEY_get0_RSA (key); // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        int bufsize = RSA_size (rsa);
        buf.resize (bufsize);

        RSA_public_decrypt (bufsize, &output[0], &buf[0], rsa, RSA_NO_PADDING);
        ret_openssl = RSA_verify_PKCS1_PSS (rsa, &hash_value[0], evp_md, &buf[0], -1);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace (ret);
        }

        result = true;
        ret = errorcode_t::success;
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
                    __leave2_trace (ret);
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
