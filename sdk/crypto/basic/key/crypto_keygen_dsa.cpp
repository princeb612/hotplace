/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_dsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keygen::add_dsa(crypto_key* cryptokey, uint32 nid, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == cryptokey || nid_dsa != nid) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DSA_ptr dsa(DSA_new());
        if (nullptr == dsa.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = DSA_generate_parameters_ex(dsa.get(), 2048, nullptr, 0, nullptr, nullptr, nullptr);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = DSA_generate_key(dsa.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DSA(pkey.get(), dsa.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        dsa.release();  // pkey own dsa

        crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
        ret = cryptokey->add(std::move(key));
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
    return ret;
}

return_t crypto_keygen::add_dsa(crypto_key* cryptokey, uint32 nid, const binary_t& y, const binary_t& x, const binary_t& p, const binary_t& q, const binary_t& g,
                                keydesc&& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DSA_ptr dsa(DSA_new());
        if (nullptr == dsa.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BN_ptr bn_p(BN_bin2bn(p.data(), t_narrow_cast(p.size()), nullptr));
        BN_ptr bn_q(BN_bin2bn(q.data(), t_narrow_cast(q.size()), nullptr));
        BN_ptr bn_g(BN_bin2bn(g.data(), t_narrow_cast(g.size()), nullptr));
        ret_openssl = DSA_set0_pqg(dsa.get(), bn_p.get(), bn_q.get(), bn_g.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        bn_p.release();  // dsa own bn_p
        bn_q.release();  // dsa own bn_q
        bn_g.release();  // dsa own bn_g

        BN_ptr bn_pub;
        BN_ptr bn_priv;
        if (y.size()) {
            bn_pub = std::move(BN_ptr(BN_bin2bn(y.data(), t_narrow_cast(y.size()), nullptr)));
        }
        if (x.size()) {
            bn_priv = std::move(BN_ptr(BN_bin2bn(x.data(), t_narrow_cast(x.size()), nullptr)));
        }
        ret_openssl = DSA_set0_key(dsa.get(), bn_pub.get(), bn_priv.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        bn_pub.release();   // dsa own bn_pub
        bn_priv.release();  // dsa own bn_priv

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DSA(pkey.get(), dsa.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        dsa.release();  // pkey own dsa

        crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
        ret = cryptokey->add(std::move(key));
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
