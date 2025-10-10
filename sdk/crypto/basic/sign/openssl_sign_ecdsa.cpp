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
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, binary_t& signature, uint32 flags) {
    return sign_ecdsa(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::sign_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    ECDSA_SIG* ecdsa_sig = nullptr;

    __try2 {
        signature.clear();

        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = ktyof_evp_pkey(pkey);
        if (kty_ec != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        EC_KEY* ec_key = (EC_KEY*)EVP_PKEY_get0_EC_KEY((EVP_PKEY*)pkey);

        hash.open(&hash_handle, alg);
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

        unitsize = advisor->unitsizeof_ecdsa(alg);

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

        if (sign_flag_format_der & flags) {
            binary_t temp;
            sig2der(signature, temp);
            signature = std::move(temp);
        }
    }
    __finally2 {
        if (nullptr != ecdsa_sig) {
            ECDSA_SIG_free(ecdsa_sig);
        }
    }
    return ret;
}

return_t openssl_sign::verify_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const binary_t& input, const binary_t& signature, uint32 flags) {
    return verify_ecdsa(pkey, alg, &input[0], input.size(), signature, flags);
}

return_t openssl_sign::verify_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t alg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    openssl_hash hash;
    hash_context_t* hash_handle = nullptr;
    binary_t hash_value;
    ECDSA_SIG* ecdsa_sig = nullptr;
    int ret_openssl = 1;

    __try2 {
        ret = errorcode_t::error_verify;

        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto kty = ktyof_evp_pkey(pkey);
        if (kty_ec != kty) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        EC_KEY* ec_key = (EC_KEY*)EVP_PKEY_get0_EC_KEY((EVP_PKEY*)pkey);

        hash.open(&hash_handle, alg);
        hash.hash(hash_handle, stream, size, hash_value);
        hash.close(hash_handle);

        ecdsa_sig = ECDSA_SIG_new();
        if (nullptr == ecdsa_sig) {
            ret = errorcode_t::out_of_memory;
            __leave2;
        }

        /* RFC 7515 A.3.1.  Encoding */
        /* NIST CAVP (cryptographic-algorithm-validation-program) test vector - PASSED */
        BIGNUM* bn_r = nullptr;
        BIGNUM* bn_s = nullptr;

        if (sign_flag_format_der & flags) {
            binary_t temp;
            auto unitsize = advisor->unitsizeof_ecdsa(alg);
            der2sig(signature, unitsize, temp);
            size_t signature_size = temp.size();
            bn_r = BN_bin2bn(&temp[0], signature_size / 2, nullptr);
            bn_s = BN_bin2bn(&temp[signature_size / 2], signature_size / 2, nullptr);
        } else {
            size_t signature_size = signature.size();
            bn_r = BN_bin2bn(&signature[0], signature_size / 2, nullptr);
            bn_s = BN_bin2bn(&signature[signature_size / 2], signature_size / 2, nullptr);
        }

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

}  // namespace crypto
}  // namespace hotplace
