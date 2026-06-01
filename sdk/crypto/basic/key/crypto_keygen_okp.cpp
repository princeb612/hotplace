/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen_okp.cpp
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

return_t crypto_keygen::add_okp(crypto_key* cryptokey, uint32 nid, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int type = nid;  // EVP_PKEY_CTX_new_id type

        auto hint = advisor->hintof_curve_nid(nid);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto kty = ktyof(hint);
        if (kty_okp != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(type, nullptr));
        if (nullptr == ctx.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        // OKP
        ret_openssl = EVP_PKEY_keygen_init(ctx.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY* pk = nullptr;
        ret_openssl = EVP_PKEY_keygen(ctx.get(), &pk);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_ptr pkey(pk);

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

return_t crypto_keygen::add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, keydesc&& desc) {
    return add_okp(cryptokey, nid, x.data(), x.size(), d.data(), d.size(), std::forward<keydesc>(desc));
}

return_t crypto_keygen::add_okp(crypto_key* cryptokey, uint32 nid, const byte_t* x, size_t pubsize, const byte_t* d, size_t privsize, keydesc&& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_curve_nid(nid);
        if (nullptr == hint) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        auto kty = ktyof(hint);
        if (kty_okp != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        EVP_PKEY_ptr pkey;
        if (d && privsize) {
            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new_raw_private_key(nid, nullptr, d, privsize)));
        } else if (x && pubsize) {
            pkey = std::move(EVP_PKEY_ptr(EVP_PKEY_new_raw_public_key(nid, nullptr, x, pubsize)));
        } else {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == pkey.get()) {
            ret = errorcode_t::bad_request;
            __leave2_trace_openssl(ret);
        }

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
