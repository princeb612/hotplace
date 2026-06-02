/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_ec_uncompressed.cpp
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

return_t crypto_keygen::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const byte_t* pubkey, size_t pubsize, const byte_t* privkey, size_t privsize,
                                            keydesc&& desc) {
    EC_KEY* eck = nullptr;
    EC_KEY_ptr eckey;
    EVP_PKEY_ptr pkey;

    function_pipeline<int> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey) && (pubkey && pubsize); })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new()));
            return pkey.get() ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            eck = EC_KEY_new_by_curve_name(nid);
            return eck ? 1 : 0;
        })
        .run_pipe([&]() -> int {
            // call both o2i_ECPublicKey and EC_KEY_set_private_key
            int rc = 1;
            if (pubkey && pubsize) {
                o2i_ECPublicKey(/* inout */ &eck, &pubkey, t_narrow_cast(pubsize));
                eckey = std::move(EC_KEY_ptr(eck));
            }
            if (privkey && privsize) {
                BN_ptr bn_priv(BN_bin2bn(privkey, t_narrow_cast(privsize), nullptr));
                rc = EC_KEY_set_private_key(eckey.get(), bn_priv.get());  // free bn_priv
            }
            return rc;
        })
        .run_pipe([&]() -> int {
            auto rc = EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get());
            if (rc > 0) {
                eckey.release();  // pkey own eckey
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

}  // namespace crypto
}  // namespace hotplace
