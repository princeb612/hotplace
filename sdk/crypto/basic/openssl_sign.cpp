/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

openssl_sign::openssl_sign() {
    // do nothing
}

openssl_sign::~openssl_sign() {
    // do nothing
}

return_t openssl_sign::sign(const EVP_PKEY* pkey, crypt_sig_t mode, const binary_t& input, binary_t& signature) {
    return sign(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::sign(const EVP_PKEY* pkey, crypt_sig_t mode, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        int type = EVP_PKEY_id(pkey);
        const hint_signature_t* hint = advisor->hintof_signature(mode);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        int group = hint->group;
        hash_algorithm_t hash_alg = hint->alg;
        switch (type) {
            case EVP_PKEY_HMAC:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_dgst:
                        ret = sign_digest(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_hmac:
                        ret = sign_hmac(pkey, hash_alg, stream, size, signature);
                        break;
                }
                break;
            case EVP_PKEY_RSA:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_rsassa_pkcs15:
                        ret = sign_rsassa_pkcs15(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_rsassa_pss:
                        ret = sign_rsassa_pss(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case EVP_PKEY_EC:
                ret = sign_ecdsa(pkey, hash_alg, stream, size, signature);
                break;
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
                ret = sign_eddsa(pkey, hash_alg, stream, size, signature);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify(const EVP_PKEY* pkey, crypt_sig_t mode, const binary_t& input, const binary_t& signature) {
    return verify(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::verify(const EVP_PKEY* pkey, crypt_sig_t mode, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        int type = EVP_PKEY_id(pkey);
        const hint_signature_t* hint = advisor->hintof_signature(mode);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        int group = hint->group;
        hash_algorithm_t hash_alg = hint->alg;
        switch (type) {
            case EVP_PKEY_HMAC:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_dgst:
                        ret = verify_digest(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_hmac:
                        ret = verify_hmac(pkey, hash_alg, stream, size, signature);
                        break;
                }
                break;
            case EVP_PKEY_RSA:
                switch (group) {
                    case crypt_sig_type_t::crypt_sig_rsassa_pkcs15:
                        ret = verify_rsassa_pkcs15(pkey, hash_alg, stream, size, signature);
                        break;
                    case crypt_sig_type_t::crypt_sig_rsassa_pss:
                        ret = verify_rsassa_pss(pkey, hash_alg, stream, size, signature);
                        break;
                    default:
                        ret = errorcode_t::bad_request;
                        break;
                }
                break;
            case EVP_PKEY_EC:
                ret = verify_ecdsa(pkey, hash_alg, stream, size, signature);
                break;
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
                ret = verify_eddsa(pkey, hash_alg, stream, size, signature);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_sign::sign_digest(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, binary_t& signature) {
    return sign_digest(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_digest(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_MD_CTX* md_context = nullptr;
    int ret_openssl = 1;
    size_t dgstsize = 0;

    __try2 {
        signature.resize(0);
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(mode);

        md_context = EVP_MD_CTX_create();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestInit_ex(md_context, evp_md, nullptr);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        ret_openssl = EVP_DigestSignInit(md_context, nullptr, evp_md, nullptr, (EVP_PKEY*)pkey);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        ret_openssl = EVP_DigestSignUpdate(md_context, stream, size);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        ret_openssl = EVP_DigestSignFinal(md_context, nullptr, &dgstsize);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        signature.resize(dgstsize);
        EVP_DigestSignFinal(md_context, &signature[0], &dgstsize);
    }
    __finally2 {
        if (nullptr != md_context) {
            EVP_MD_CTX_destroy(md_context);
        }
    }
    return ret;
}

return_t openssl_sign::sign_hmac(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, binary_t& signature) {
    return sign_digest(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_hmac(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, binary_t& signature) {
    return sign_digest(pkey, mode, stream, size, signature);
}

return_t openssl_sign::sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, binary_t& signature) {
    return sign_digest(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, binary_t& signature) {
    return sign_digest(pkey, mode, stream, size, signature);
}

return_t openssl_sign::sign_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, binary_t& signature) {
    return sign_ecdsa(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    ECDSA_SIG* ecdsa_sig = nullptr;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if (kty_ec != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        EC_KEY* ec_key = (EC_KEY*)EVP_PKEY_get0_EC_KEY((EVP_PKEY*)pkey);

        hash.open(&hash_handle, mode);
        hash.hash(hash_handle, stream, size, hash_value);
        hash.close(hash_handle);

        int unitsize = 0;
        // EC_KEY* ec = EVP_PKEY_get1_EC_KEY (pkey);
        // const EC_GROUP* group = EC_KEY_get0_group (ec);
        // int nid = EC_GROUP_get_curve_name (group);
        // NID_X9_62_prime256v1
        // NID_secp384r1
        // NID_secp521r1
        // EC_KEY_free (ec);

        switch (mode) {
            case hash_algorithm_t::sha1:
                unitsize = 20;
                break;
            case hash_algorithm_t::sha2_224:
                unitsize = 28;
                break;
            case hash_algorithm_t::sha2_256:
                unitsize = 32;
                break;
            case hash_algorithm_t::sha2_384:
                unitsize = 48;
                break;
            case hash_algorithm_t::sha2_512:
                unitsize = 66;
                break;
            case hash_algorithm_t::sha2_512_224:
                unitsize = 28;
                break;
            case hash_algorithm_t::sha2_512_256:
                unitsize = 32;
                break;
        }

        signature.resize(unitsize * 2);

        /*
         * Computes the ECDSA signature of the given hash value using
         * the supplied private key and returns the created signature.
         */
        // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        ecdsa_sig = ECDSA_do_sign(&hash_value[0], hash_value.size(), ec_key);
        if (nullptr == ecdsa_sig) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        const BIGNUM* bn_r = nullptr;
        const BIGNUM* bn_s = nullptr;

        ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);

        int rlen = BN_num_bytes(bn_r);
        int slen = BN_num_bytes(bn_s);

        if (unitsize < rlen) {
            ret = errorcode_t::unknown;
            __leave2;
        }

        /*
         * Signature = I2OSP(R, n) | I2OSP(S, n)
         * if unitsize is 4 and r is 12, s is 34
         *  r(4 bytes)  + s(4 bytes)
         *  00 00 00 12 | 00 00 00 34 -> valid
         *  12 00 00 00 | 34 00 00 00 -> invalid
         */
        BN_bn2bin(bn_r, &signature[unitsize - rlen]);
        BN_bn2bin(bn_s, &signature[unitsize + (unitsize - slen)]);
    }
    __finally2 {
        if (nullptr != ecdsa_sig) {
            ECDSA_SIG_free(ecdsa_sig);
        }
    }
    return ret;
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, binary_t& signature) {
    return sign_rsassa_pss(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;

    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    int ret_openssl = 0;

    __try2 {
        signature.resize(0);

        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if (kty_rsa != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        hash.open(&hash_handle, mode);
        hash.hash(hash_handle, stream, size, hash_value);
        hash.close(hash_handle);

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(mode);

        binary_t buf;
        const EVP_PKEY* key = pkey;
        RSA* rsa = (RSA*)EVP_PKEY_get0_RSA((EVP_PKEY*)key);  // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        int bufsize = RSA_size(rsa);
        buf.resize(bufsize);

        ret_openssl = RSA_padding_add_PKCS1_PSS(rsa, &buf[0], &hash_value[0], evp_md, -1);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        signature.resize(bufsize);
        ret_openssl = RSA_private_encrypt(bufsize, &buf[0], &signature[0], rsa, RSA_NO_PADDING);
        if (ret_openssl != bufsize) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_sign::sign_eddsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, binary_t& signature) {
    return sign_eddsa(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::sign_eddsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    EVP_MD_CTX* ctx = nullptr;
    int ret_test = 0;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if (kty_okp != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ctx = EVP_MD_CTX_new();
        ret_test = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, (EVP_PKEY*)pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        size_t dgstsize = 256;
        signature.resize(dgstsize);
        ret_test = EVP_DigestSign(ctx, &signature[0], &dgstsize, stream, size);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        signature.resize(dgstsize);
    }
    __finally2 {
        if (ctx) {
            EVP_MD_CTX_destroy(ctx);
        }
    }
    return ret;
}

return_t openssl_sign::verify_digest(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, const binary_t& signature) {
    return verify_digest(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_digest(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    EVP_MD_CTX* md_context = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = errorcode_t::error_verify;

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(mode);

        md_context = EVP_MD_CTX_create();
        if (nullptr == md_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestInit_ex(md_context, evp_md, nullptr);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestVerifyInit(md_context, nullptr, evp_md, nullptr, (EVP_PKEY*)pkey);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestVerifyUpdate(md_context, stream, size);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_DigestVerifyFinal(md_context, &signature[0], signature.size());
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        if (nullptr != md_context) {
            EVP_MD_CTX_destroy(md_context);
        }
    }
    return ret;
}

return_t openssl_sign::verify_hmac(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, const binary_t& signature) {
    return verify_hmac(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_hmac(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        binary_t result;
        ret = sign_digest(pkey, mode, stream, size, result);
        if (result != signature) {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_sign::verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, const binary_t& signature) {
    return verify_digest(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, const binary_t& signature) {
    return verify_digest(pkey, mode, stream, size, signature);
}

return_t openssl_sign::verify_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, const binary_t& signature) {
    return verify_ecdsa(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    ECDSA_SIG* ecdsa_sig = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if (kty_ec != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        EC_KEY* ec_key = (EC_KEY*)EVP_PKEY_get0_EC_KEY((EVP_PKEY*)pkey);

        ret = errorcode_t::error_verify;

        hash.open(&hash_handle, mode);
        hash.hash(hash_handle, stream, size, hash_value);
        hash.close(hash_handle);

        ecdsa_sig = ECDSA_SIG_new();
        if (nullptr == ecdsa_sig) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        size_t signature_size = signature.size();

        /* RFC 7515 A.3.1.  Encoding */
        /* NIST CAVP (cryptographic-algorithm-validation-program) test vector - PASSED */
        BIGNUM* bn_r = nullptr;
        BIGNUM* bn_s = nullptr;
        bn_r = BN_bin2bn(&signature[0], signature_size / 2, nullptr);
        bn_s = BN_bin2bn(&signature[signature_size / 2], signature_size / 2, nullptr);

        ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s);

        /* Verifies that the supplied signature is a valid ECDSA
         * signature of the supplied hash value using the supplied public key.
         */
        ret_openssl = ECDSA_do_verify(&hash_value[0], hash_value.size(), ecdsa_sig, ec_key);
        if (1 != ret_openssl) {
            ret = errorcode_t::error_verify;
            __leave2_trace_openssl(ret);
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        if (nullptr != ecdsa_sig) {
            ECDSA_SIG_free(ecdsa_sig);
        }
    }
    return ret;
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, const binary_t& signature) {
    return verify_rsassa_pss(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto kty = typeof_crypto_key(pkey);
        if (kty_rsa != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = errorcode_t::error_verify;

        hash.open(&hash_handle, mode);
        hash.hash(hash_handle, stream, size, hash_value);
        hash.close(hash_handle);

        EVP_MD* evp_md = (EVP_MD*)advisor->find_evp_md(mode);

        binary_t buf;
        const EVP_PKEY* key = pkey;
        RSA* rsa = (RSA*)EVP_PKEY_get0_RSA((EVP_PKEY*)key);  // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        int bufsize = RSA_size(rsa);
        buf.resize(bufsize);

        RSA_public_decrypt(bufsize, &signature[0], &buf[0], rsa, RSA_NO_PADDING);
        ret_openssl = RSA_verify_PKCS1_PSS(rsa, &hash_value[0], evp_md, &buf[0], -1);
        if (ret_openssl < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t openssl_sign::verify_eddsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const binary_t& input, const binary_t& signature) {
    return verify_eddsa(pkey, mode, &input[0], input.size(), signature);
}

return_t openssl_sign::verify_eddsa(const EVP_PKEY* pkey, hash_algorithm_t mode, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    EVP_MD_CTX* ctx = nullptr;
    int ret_test = 0;

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = typeof_crypto_key(pkey);
        if (kty_okp != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = errorcode_t::error_verify;

        ctx = EVP_MD_CTX_new();
        ret_test = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, (EVP_PKEY*)pkey);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_test = EVP_DigestVerify(ctx, &signature[0], signature.size(), stream, size);
        if (1 != ret_test) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret = errorcode_t::success;
    }
    __finally2 {
        if (ctx) {
            EVP_MD_CTX_destroy(ctx);
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
