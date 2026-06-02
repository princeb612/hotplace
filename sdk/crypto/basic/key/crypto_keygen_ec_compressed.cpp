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
    BN_ptr bn_x;
    BN_ptr bn_d;
    EC_KEY_ptr ec;
    EC_POINT_ptr point;
    EVP_PKEY_ptr pkey;
    const EC_GROUP* group = nullptr;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey) && (false == x.empty() || false == d.empty()); })
        .run_pipe([&]() -> int {
            bn_x = std::move(BN_ptr(BN_bin2bn(x.data(), t_narrow_cast(x.size()), nullptr)));
            if (false == d.empty()) {
                bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), t_narrow_cast(d.size()), nullptr)));
            }
            return (bn_x.get() && (d.empty() || bn_d.get())) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            ec = std::move(EC_KEY_ptr(EC_KEY_new_by_curve_name(nid)));
            return ec.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            group = EC_KEY_get0_group(ec.get());
            point = std::move(EC_POINT_ptr(EC_POINT_new(group)));
            return point.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            int rc = 1;
            if (bn_d.get()) {
                rc = EC_KEY_set_private_key(ec.get(), bn_d.get());
                if (rc > 0) {
                    bn_d.release();  // ec own bn_d
                } else {
                    return rc;
                }
                rc = EC_POINT_mul(group, point.get(), bn_d.get(), nullptr, nullptr, nullptr);
            } else {
                // EC_POINT_set_compressed_coordinates_GFp
                rc = EC_POINT_set_compressed_coordinates(group, point.get(), bn_x.get(), ysign, nullptr);
            }
            return rc;
        })
        .run_pipe([&]() -> int { return EC_KEY_set_public_key(ec.get(), point.get()); })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new()));
            return pkey.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get()); })
        .run_pipe([&]() -> return_t {
            crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
            auto ret = cryptokey->add(std::move(key));
            if (errorcode_t::success == ret) {
                pkey.release();  // cryptokey own pkey
            }
            return ret;
        });

    return pipeline.result_to_return_t();
}

}  // namespace crypto
}  // namespace hotplace
