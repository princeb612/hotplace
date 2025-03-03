/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_hash.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_sign.hpp>
#include <sdk/crypto/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& r, binary_t& s) {
    return_t ret = errorcode_t::success;
    ret = sign_dsa(pkey, hashalg, &input[0], input.size(), r, s);
    return ret;
}

return_t openssl_sign::sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& r, binary_t& s) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto dsa = EVP_PKEY_get0_DSA((EVP_PKEY*)pkey);
        binary_t digest;
        {
            crypto_hash_builder builder;
            auto hash = builder.set(hashalg).build();
            if (hash) {
                hash->digest(stream, size, digest);
                hash->release();
            }
        }

        {
            DSA_SIG* sig = DSA_do_sign(&digest[0], digest.size(), (DSA*)dsa);
            if (sig) {
                const BIGNUM* bn_r = nullptr;
                const BIGNUM* bn_s = nullptr;
                DSA_SIG_get0(sig, &bn_r, &bn_s);
                bn2bin(bn_r, r);
                bn2bin(bn_s, s);
                DSA_SIG_free(sig);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& r, const binary_t& s) {
    return_t ret = errorcode_t::success;
    ret = verify_dsa(pkey, hashalg, &input[0], input.size(), r, s);
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& r, const binary_t& s) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    BIGNUM* bn_r = nullptr;
    BIGNUM* bn_s = nullptr;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto dsa = EVP_PKEY_get0_DSA((EVP_PKEY*)pkey);
        binary_t digest;
        {
            crypto_hash_builder builder;
            auto hash = builder.set(hashalg).build();
            if (hash) {
                hash->digest(stream, size, digest);
                hash->release();
            }
        }

        bin2bn(r, &bn_r);
        bin2bn(s, &bn_s);
        DSA_SIG* sig = DSA_SIG_new();
        DSA_SIG_set0(sig, bn_r, bn_s);
        ret_openssl = DSA_do_verify(&digest[0], digest.size(), sig, (DSA*)dsa);
        if (ret_openssl < 1) {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 {
        if (bn_r) {
            BN_free(bn_r);
        }
        if (bn_s) {
            BN_free(bn_s);
        }
    }
    return ret;
}

return_t openssl_sign::sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature) {
    return_t ret = errorcode_t::success;
    ret = sign_dsa(pkey, hashalg, &input[0], input.size(), signature);
    return ret;
}

return_t openssl_sign::sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t r;
        binary_t s;
        ret = sign_dsa(pkey, hashalg, stream, size, r, s);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_digest(hashalg);
        uint16 dlen = sizeof_digest(hint);

        ret = rs2sig(r, s, dlen, signature);
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    ret = verify_dsa(pkey, hashalg, &input[0], input.size(), signature);
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    // TODO
    return ret;
}

return_t openssl_sign::sign_dsa_asn1(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature) {
    return_t ret = errorcode_t::success;
    ret = sign_dsa_asn1(pkey, hashalg, &input[0], input.size(), signature);
    return ret;
}

return_t openssl_sign::sign_dsa_asn1(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_r;
        binary_t bin_s;

        ret = sign_dsa(pkey, hashalg, stream, size, bin_r, bin_s);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = rs2der(bin_r, bin_s, signature);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify_dsa_asn1(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    ret = verify_dsa_asn1(pkey, hashalg, &input[0], input.size(), signature);
    return ret;
}

return_t openssl_sign::verify_dsa_asn1(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_digest(hashalg);
        uint16 dlen = sizeof_digest(hint);

        binary_t bin_rs;
        ret = der2sig(signature, dlen, bin_rs);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = verify_dsa(pkey, hashalg, stream, size, bin_rs);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
