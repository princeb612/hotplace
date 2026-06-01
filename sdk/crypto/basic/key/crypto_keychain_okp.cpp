/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_okp.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, keydesc&& desc) { return crypto_keygen::add_okp(cryptokey, nid, std::forward<keydesc>(desc)); }

return_t crypto_keychain::add_okp(crypto_key* cryptokey, const char* curve, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_curve(curve);
    if (hint) {
        ret = add_okp(cryptokey, hint->nid, std::forward<keydesc>(desc));
    }
    return ret;
}

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, keydesc&& desc) {
    return add_okp(cryptokey, nid, x.data(), x.size(), d.data(), d.size(), std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, const byte_t* x, size_t xsize, const byte_t* d, size_t dsize, keydesc&& desc) {
    return crypto_keygen::add_okp(cryptokey, nid, x, xsize, d, dsize, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_okp(crypto_key* cryptokey, const char* curve, const binary_t& x, const binary_t& d, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_curve(curve);
    if (hint) {
        ret = add_okp(cryptokey, hint->nid, x, d, std::forward<keydesc>(desc));
    }
    return ret;
}

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* x, const char* d, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_okp_b64(cryptokey, nid, x, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_okp_b64u(cryptokey, nid, x, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_okp_b16(cryptokey, nid, x, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_okp_b16rfc(cryptokey, nid, x, d, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_okp_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp(cryptokey, nid, bin_x, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp(cryptokey, nid, bin_x, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp(cryptokey, nid, bin_x, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp(cryptokey, nid, bin_x, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp(crypto_key* cryptokey, const char* curve, encoding_t encoding, const char* x, const char* d, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_okp_b64(cryptokey, curve, x, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_okp_b64u(cryptokey, curve, x, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_okp_b16(cryptokey, curve, x, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_okp_b16rfc(cryptokey, curve, x, d, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_okp_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp_b64(cryptokey, nid, x, d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp_b64u(cryptokey, nid, x, d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp_b16(cryptokey, nid, x, d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_okp_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* d, keydesc&& desc) {
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

        ret = add_okp_b16rfc(cryptokey, nid, x, d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
