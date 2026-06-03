/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_ec.cpp
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

return_t crypto_keygen::add_ec(crypto_key* cryptokey, uint32 nid, keydesc&& desc) {
    EVP_PKEY* pk = nullptr;
    EVP_PKEY_CTX_ptr ctx;
    EVP_PKEY_ptr pkey;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    int type = EVP_PKEY_EC;  // EVP_PKEY_CTX_new_id type

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey); })
        .run_pipe([&]() -> return_t {
            auto hint = advisor->hintof_curve_nid(nid);
            if (nullptr == hint) return errorcode_t::not_supported;
            auto kty = ktyof(hint);
            if (kty_ec != kty) return errorcode_t::different_type;
            return errorcode_t::success;
        })
        .run_pipe([&]() -> int {
            ctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_id(type, nullptr)));
            return ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_keygen_init(ctx.get()); })
        .run_pipe([&]() -> int { return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), nid); })
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        .run_pipe([&]() -> int { return EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE); })
#endif
        .run_pipe([&]() -> int {
            // [openssl 3.0.3] return errorcode_t::success but pkey is nullptr
            auto rc = EVP_PKEY_keygen(ctx.get(), &pk);
            return ((rc > 0) && pk) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(pk));
            return pkey.get() ? 1 : 0;
        })
#if OPENSSL_VERSION_NUMBER < 0x30000000L
        .run_pipe([&]() -> int {
            // set ASN.1 OPENSSL_EC_NAMED_CURVE flag for PEM export (PEM_write_bio_PUBKEY, PEM_write_bio_PrivateKey)
            // openssl 3.0 EVP_PKEY_get0 family return const key pointer
            return EC_KEY_set_asn1_flag((EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey.get()), OPENSSL_EC_NAMED_CURVE);
        })
#endif
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

return_t crypto_keygen::add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, keydesc&& desc) {
    BN_ptr bn_x;
    BN_ptr bn_y;
    BN_ptr bn_d;
    EC_KEY_ptr ec;
    EC_POINT_ptr point;
    EVP_PKEY_ptr pkey;
    const EC_GROUP* group = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey) && (false == x.empty() && false == y.empty()); })
        .run_pipe([&]() -> return_t {
            auto hint = advisor->hintof_curve_nid(nid);
            if (nullptr == hint) return errorcode_t::bad_request;
            auto kty = ktyof(hint);
            if (kty_ec != kty) return errorcode_t::different_type;
            return errorcode_t::success;
        })
        .run_pipe([&]() -> int {
            bn_x = std::move(BN_ptr(BN_bin2bn(x.data(), t_narrow_cast(x.size()), nullptr)));
            bn_y = std::move(BN_ptr(BN_bin2bn(y.data(), t_narrow_cast(y.size()), nullptr)));
            if (false == d.empty()) {
                bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), t_narrow_cast(d.size()), nullptr)));
            }
            return (bn_x.get() && bn_y.get() && (d.empty() || bn_d.get())) ? 1 : 0;
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
            if (bn_d.get()) {
                auto rc = EC_KEY_set_private_key(ec.get(), bn_d.get());
                if (rc < 1) return rc;
                return EC_POINT_mul(group, point.get(), bn_d.get(), nullptr, nullptr, nullptr);
            } else {
                return EC_POINT_set_affine_coordinates(group, point.get(), bn_x.get(), bn_y.get(), nullptr);
            }
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
