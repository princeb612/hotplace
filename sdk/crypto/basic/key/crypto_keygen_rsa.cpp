/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_rsa.cpp
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

return_t crypto_keygen::add_rsa(crypto_key* cryptokey, uint32 nid, size_t bits, keydesc&& desc) {
    EVP_PKEY* pk = nullptr;
    EVP_PKEY_CTX_ptr pkey_context;
    EVP_PKEY_ptr pkey;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool {
            if (bits < 2048) {
                bits = 2048;
            }
            // nid_rsa2 not supported
            return ((nullptr != cryptokey) && (nid_rsa == nid || nid_rsapss == nid));
        })
        .run_pipe([&]() -> int {
            pkey_context = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_id(nid, nullptr)));
            return pkey_context.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_keygen_init(pkey_context.get()); })
        .run_pipe([&]() -> int { return EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_context.get(), t_narrow_cast(bits)); })
        .run_pipe([&]() -> int {
            auto rc = EVP_PKEY_keygen(pkey_context.get(), &pk);
            return ((rc > 0) && pk) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(pk));
            return pkey.get() ? 1 : 0;
        })
        .run_pipe([&]() -> return_t {
            crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));
            auto ret = cryptokey->add(std::move(key));
            if (errorcode_t::success == ret) {
                pkey.release();  // cryptokey own pkey
            }
            // else free pkey_context
            return ret;
        });

    return pipeline.result_to_return_t();
}

return_t crypto_keygen::add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, keydesc&& desc) {
    BN_ptr bn_n;
    BN_ptr bn_e;
    BN_ptr bn_d;
    EVP_PKEY_ptr pkey;
    RSA_ptr rsa;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return ((nullptr != cryptokey) && (nid_rsa == nid) && (false == n.empty() && false == e.empty())); })
        .run_pipe([&]() -> int {
            rsa = std::move(RSA_ptr(RSA_new()));
            return rsa.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            bn_n = std::move(BN_ptr(BN_bin2bn(n.data(), t_narrow_cast(n.size()), nullptr)));
            bn_e = std::move(BN_ptr(BN_bin2bn(e.data(), t_narrow_cast(e.size()), nullptr)));
            if (false == d.empty()) {
                bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), t_narrow_cast(d.size()), nullptr)));
            }
            return (bn_n.get() && bn_e.get() && (d.empty() || bn_d.get())) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            auto rc = RSA_set0_key(rsa.get(), bn_n.get(), bn_e.get(), bn_d.get());
            if (rc > 0) {
                bn_n.release();  // rsa own bn_n
                bn_e.release();  // rsa own bn_e
                bn_d.release();  // rsa own bn_d
            }
            return rc;
        })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new()));
            return pkey.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_set_type(pkey.get(), nid); })
        .run_pipe([&]() -> int {
            auto rc = EVP_PKEY_assign_RSA(pkey.get(), rsa.get());
            if (rc > 0) {
                rsa.release();  // pkey own rsa
            }
            return rc;
        })
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

return_t crypto_keygen::add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                                const binary_t& dp, const binary_t& dq, const binary_t& qi, keydesc&& desc) {
    BN_ptr bn_n;
    BN_ptr bn_e;
    BN_ptr bn_d;
    EVP_PKEY_ptr pkey;
    RSA_ptr rsa;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey) && (nid_rsa == nid) && (false == n.empty() && false == e.empty()); })
        .run_pipe([&]() -> int {
            rsa = std::move(RSA_ptr(RSA_new()));
            return rsa.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            bn_n = std::move(BN_ptr(BN_bin2bn(n.data(), t_narrow_cast(n.size()), nullptr)));
            bn_e = std::move(BN_ptr(BN_bin2bn(e.data(), t_narrow_cast(e.size()), nullptr)));
            if (false == d.empty()) {
                bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), t_narrow_cast(d.size()), nullptr)));
            }
            return (bn_n.get() && bn_e.get() && (d.empty() || bn_d.get())) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            int rc = RSA_set0_key(rsa.get(), bn_n.get(), bn_e.get(), bn_d.get());
            if (rc > 0) {
                bn_n.release();  // rsa own bn_n
                bn_e.release();  // rsa own bn_e
                bn_d.release();  // rsa own bn_d
            }
            return rc;
        })
        .run_pipe([&]() -> int {
            BN_ptr bn_p;
            BN_ptr bn_q;

            if (false == p.empty()) {
                bn_p = std::move(BN_ptr(BN_bin2bn(p.data(), t_narrow_cast(p.size()), nullptr)));
            }
            if (false == q.empty()) {
                bn_q = std::move(BN_ptr(BN_bin2bn(q.data(), t_narrow_cast(q.size()), nullptr)));
            }

            auto rc = RSA_set0_factors(rsa.get(), bn_p.get(), bn_q.get());
            if (rc > 0) {
                bn_p.release();  // rsa own bn_p
                bn_q.release();  // rsa own bn_q
            }
            return rc;
        })
        .run_pipe([&]() -> int {
            BN_ptr bn_dmp1;
            BN_ptr bn_dmq1;
            BN_ptr bn_iqmp;

            if (false == dp.empty()) {
                bn_dmp1 = std::move(BN_ptr(BN_bin2bn(dp.data(), t_narrow_cast(dp.size()), nullptr)));
            }
            if (false == dq.empty()) {
                bn_dmq1 = std::move(BN_ptr(BN_bin2bn(dq.data(), t_narrow_cast(dq.size()), nullptr)));
            }
            if (false == qi.empty()) {
                bn_iqmp = std::move(BN_ptr(BN_bin2bn(qi.data(), t_narrow_cast(qi.size()), nullptr)));
            }

            auto rc = RSA_set0_crt_params(rsa.get(), bn_dmp1.get(), bn_dmq1.get(), bn_iqmp.get());
            if (rc > 0) {
                bn_dmp1.release();  // rsa own bn_dmp1
                bn_dmq1.release();  // rsa own bn_dmq1
                bn_iqmp.release();  // rsa own bn_iqmp
            }
            return rc;
        })
        .run_pipe([&]() -> int { return RSA_check_key(rsa.get()); })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new()));
            return pkey.get() ? 1 : 0;
        })
        // .run_pipe([&]() -> int { return EVP_PKEY_set_type(pkey.get(), nid); })
        .run_pipe([&]() -> int {
            auto rc = EVP_PKEY_assign_RSA(pkey.get(), rsa.get());
            if (rc > 0) {
                rsa.release();  // pkey own rsa
            }
            return rc;
        })
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

return_t crypto_keygen::add_rsapss(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, keydesc&& desc) {
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    BN_ptr bn_n;
    BN_ptr bn_e;
    BN_ptr bn_d;
    EVP_PKEY* pkey_pss = nullptr;
    EVP_PKEY_CTX_ptr ctx;
    EVP_PKEY_ptr pkey;
    OSSL_PARAM_BLD_ptr bld;
    OSSL_PARAM_ptr params;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey) && (nid_rsapss == nid) && (false == n.empty() && false == e.empty()); })
        .run_pipe([&]() -> int {
            // OBJ_nid2txt(nid) -> "RSA-PSS"
            ctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_from_name(nullptr, "RSA-PSS", nullptr)));
            return ctx.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int { return EVP_PKEY_fromdata_init(ctx.get()); })
        .run_pipe([&]() -> int {
            bld = std::move(OSSL_PARAM_BLD_ptr(OSSL_PARAM_BLD_new()));
            return bld.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            bn_n = std::move(BN_ptr(BN_bin2bn(n.data(), t_narrow_cast(n.size()), nullptr)));
            bn_e = std::move(BN_ptr(BN_bin2bn(e.data(), t_narrow_cast(e.size()), nullptr)));
            if (false == d.empty()) {
                bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), t_narrow_cast(d.size()), nullptr)));
            }
            return (bn_n.get() && bn_e.get() && (d.empty() || bn_d.get())) ? 1 : 0;
        })
        .run_pipe([&]() -> int { return OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, bn_n.get()); })
        .run_pipe([&]() -> int { return OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, bn_e.get()); })
        .run_pipe([&]() -> int { return bn_d.get() ? OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_D, bn_d.get()) : 1; })
        .run_pipe([&]() -> int {
            params = std::move(OSSL_PARAM_ptr(OSSL_PARAM_BLD_to_param(bld.get())));
            return params.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            auto rc = EVP_PKEY_fromdata(ctx.get(), &pkey_pss, bn_d.get() ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params.get());
            return ((rc > 0) && pkey_pss) ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(pkey_pss));
            return pkey.get() ? 1 : 0;
        })
        .run_pipe([&]() -> return_t {
            crypto_key_object key(pkey.get(), std::forward<keydesc>(desc));

            auto ret = cryptokey->add(std::move(key));
            if (errorcode_t::success == ret) {
                pkey.release();  // cryptokey own pkey
            }
            return ret;
        });

    return pipeline.result_to_return_t();
#else
    return errorcode_t::not_supported;
#endif
}

}  // namespace crypto
}  // namespace hotplace
