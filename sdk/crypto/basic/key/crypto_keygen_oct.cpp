/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_oct.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keygen::add_oct(crypto_key* cryptokey, size_t size, keydesc&& desc) {
    EVP_PKEY_ptr pkey;
    binary_t temp;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey); })
        .run_pipe([&]() -> int {
            openssl_prng r;
            r.random(temp, size);

            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, temp.data(), t_narrow_cast(size))));
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
}

return_t crypto_keygen::add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, keydesc&& desc) {
    EVP_PKEY_ptr pkey;

    function_pipeline<int, osslerror_category> pipeline;
    pipeline  //
        .set_tracer(pipeline_trace_dbg_openssl_print)
        .test_parameter([&]() -> bool { return (nullptr != cryptokey) && (nullptr != k); })
        .run_pipe([&]() -> int {
            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, k, t_narrow_cast(size))));
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
}

}  // namespace crypto
}  // namespace hotplace
