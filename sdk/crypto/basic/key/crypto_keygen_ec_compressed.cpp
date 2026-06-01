/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_ec_compressed.cpp
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

return_t crypto_keygen::add_ec_compressed(crypto_key* cryptokey, uint32 nid, const binary_t& x, bool ysign, const binary_t& d, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        BN_ptr bn_x(BN_bin2bn(x.data(), t_narrow_cast(x.size()), nullptr));
        BN_ptr bn_d;
        if (d.size() > 0) {
            bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), t_narrow_cast(d.size()), nullptr)));
        }

        if (nullptr == bn_x.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EC_KEY_ptr ec(EC_KEY_new_by_curve_name(nid));
        if (nullptr == ec.get()) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        const EC_GROUP* group = EC_KEY_get0_group(ec.get());
        EC_POINT_ptr point(EC_POINT_new(group));
        if (nullptr == point.get()) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        if (nullptr != bn_d.get()) {
            ret_openssl = EC_KEY_set_private_key(ec.get(), bn_d.get());
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
            bn_d.release();  // ec own bn_d

            ret_openssl = EC_POINT_mul(group, point.get(), bn_d.get(), nullptr, nullptr, nullptr);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        } else {
            ret_openssl = EC_POINT_set_compressed_coordinates(group, point.get(), bn_x.get(), ysign, nullptr);  // EC_POINT_set_compressed_coordinates_GFp
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_openssl = EC_KEY_set_public_key(ec.get(), point.get());
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get());
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        // ec using set1_family (internally upref)

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
