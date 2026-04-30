/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_sign_dsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sign.hpp>

namespace hotplace {
namespace crypto {

return_t openssl_sign::sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& r, binary_t& s) {
    return_t ret = errorcode_t::success;
    ret = sign_dsa(pkey, hashalg, input.data(), input.size(), r, s);
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
            DSA_SIG_ptr sig(DSA_do_sign(digest.data(), t_narrow_cast(digest.size()), (DSA*)dsa));
            if (sig.get()) {
                const BIGNUM* bn_r = nullptr;
                const BIGNUM* bn_s = nullptr;
                DSA_SIG_get0(sig.get(), &bn_r, &bn_s);
                bn2bin(bn_r, r);
                bn2bin(bn_s, s);
            } else {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& r, const binary_t& s) {
    return_t ret = errorcode_t::success;
    ret = verify_dsa(pkey, hashalg, input.data(), input.size(), r, s);
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& r, const binary_t& s) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
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

        BIGNUM* bignum_r = nullptr;
        BIGNUM* bignum_s = nullptr;
        bin2bn(r, &bignum_r);
        bin2bn(s, &bignum_s);

        BN_ptr bn_r(bignum_r);
        BN_ptr bn_s(bignum_s);

        DSA_SIG_ptr sig(DSA_SIG_new());
        DSA_SIG_set0(sig.get(), bn_r.get(), bn_s.get());
        bn_r.release();  // sig own bn_r
        bn_s.release();  // sig own bn_s

        ret_openssl = DSA_do_verify(digest.data(), t_narrow_cast(digest.size()), sig.get(), (DSA*)dsa);
        if (ret_openssl < 1) {
            ret = errorcode_t::error_verify;
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    ret = sign_dsa(pkey, hashalg, input.data(), input.size(), signature, flags);
    return ret;
}

return_t openssl_sign::sign_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, binary_t& signature, uint32 flags) {
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

        if (sign_flag_format_der & flags) {
            binary_t temp;
            ret = rs2der(r, s, signature);
        } else {
            ret = rs2sig(r, s, dlen, signature);
        }
    }
    __finally2 {}
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const binary_t& input, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    ret = verify_dsa(pkey, hashalg, input.data(), input.size(), signature, flags);
    return ret;
}

return_t openssl_sign::verify_dsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, const byte_t* stream, size_t size, const binary_t& signature, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_r;
        binary_t bin_s;
        if (sign_flag_format_der & flags) {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            auto hint = advisor->hintof_digest(hashalg);
            uint16 dlen = sizeof_digest(hint);
            ret = der2rs(signature, dlen, bin_r, bin_s);
        } else {
            ret = sig2rs(signature, bin_r, bin_s);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = verify_dsa(pkey, hashalg, stream, size, bin_r, bin_s);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
