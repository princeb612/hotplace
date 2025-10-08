/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    int ret_openssl = 0;
    EVP_PKEY* params = nullptr;
    EVP_PKEY_CTX* keyctx = nullptr;
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

        ctx = EVP_PKEY_CTX_new_id(type, nullptr);
        if (nullptr == ctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        // OKP
        ret_openssl = EVP_PKEY_keygen_init(ctx);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_keygen(ctx, &pkey);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        if (pkey) {
            crypto_key_object key(pkey, desc);
            ret = cryptokey->add(key);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        if (keyctx) {
            EVP_PKEY_CTX_free(keyctx);
        }
        if (params) {
            EVP_PKEY_free(params);
        }

        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
    }
    return ret;
}

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
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

        if (d.size()) {
            pkey = EVP_PKEY_new_raw_private_key(nid, nullptr, &d[0], d.size());
        } else if (x.size()) {
            pkey = EVP_PKEY_new_raw_public_key(nid, nullptr, &x[0], x.size());
        }
        if (nullptr == pkey) {
            ret = errorcode_t::bad_request;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);
        cryptokey->add(key);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_okp_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_okp(cryptokey, nid, bin_x, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_okp(cryptokey, nid, bin_x, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_okp(cryptokey, nid, bin_x, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_okp(cryptokey, nid, bin_x, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_okp_b64(cryptokey, nid, x, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_okp_b64u(cryptokey, nid, x, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_okp_b16(cryptokey, nid, x, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == cryptokey) || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_okp_b16rfc(cryptokey, nid, x, d, desc);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
