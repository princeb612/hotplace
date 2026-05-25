/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   openssl_kdf_scrypt.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7914 The scrypt Password-Based Key Derivation Function
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

#if defined __linux__
#include <dlfcn.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace hotplace {
namespace crypto {

return_t openssl_kdf::scrypt(binary_t& derived, size_t dlen, const std::string& password, const binary_t& salt, int n, int r, int p) {
    return_t ret = errorcode_t::success;
    __try2 {
        derived.clear();

#if OPENSSL_VERSION_NUMBER < 0x30000000L
        if (0 == salt.size()) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
#endif

        EVP_PKEY_CTX_ptr ctx;

        function_pipeline<int> pipeline;
        pipeline  //
            .set_tracer(pipeline_trace_dbg_openssl_print)
            .run_pipe([&]() -> int {
                ctx = std::move(EVP_PKEY_CTX_ptr(EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr)));
                return ctx.get() ? 1 : 0;
            })
            .run_pipe([&]() -> int { return EVP_PKEY_derive_init(ctx.get()); })
            .run_pipe([&]() -> int { return EVP_PKEY_CTX_set1_pbe_pass(ctx.get(), password.c_str(), t_narrow_cast(password.size())); })
            .run_pipe([&]() -> int { return EVP_PKEY_CTX_set1_scrypt_salt(ctx.get(), salt.data(), t_narrow_cast(salt.size())); })
            .run_pipe([&]() -> int { return EVP_PKEY_CTX_set_scrypt_N(ctx.get(), n); })
            .run_pipe([&]() -> int { return EVP_PKEY_CTX_set_scrypt_r(ctx.get(), r); })
            .run_pipe([&]() -> int { return EVP_PKEY_CTX_set_scrypt_p(ctx.get(), p); })
            .run_pipe([&]() -> int {
                derived.resize(dlen);
                return EVP_PKEY_derive(ctx.get(), derived.data(), &dlen);
            });
        ret = pipeline.result_to_return_t();
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
