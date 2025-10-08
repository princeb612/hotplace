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

return_t crypto_keychain::add_ec2(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_curve_nid(nid);
    if (hint) {
        auto kty = ktyof(hint);
        switch (kty) {
            case kty_okp:
                ret = add_okp(cryptokey, nid, desc);
                break;
            case kty_ec:
                ret = add_ec(cryptokey, nid, desc);
                break;
            default:
                ret = errorcode_t::bad_request;
                break;
        }
    } else {
        ret = errorcode_t::bad_request;
    }
    return ret;
}

return_t crypto_keychain::add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_curve_nid(nid);
    if (hint) {
        auto kty = ktyof(hint);
        switch (kty) {
            case kty_okp:
                ret = add_okp(cryptokey, nid, x, d, desc);
                break;
            case kty_ec:
                ret = add_ec(cryptokey, nid, x, y, d, desc);
                break;
            default:
                ret = errorcode_t::bad_request;
                break;
        }
    } else {
        ret = errorcode_t::bad_request;
    }
    return ret;
}

return_t crypto_keychain::add_ec2_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec2_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec2_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec2_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec2_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec2_b64(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec2_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec2_b64u(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec2_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec2_b16(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec2_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || (nullptr == x && nullptr == d)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec2_b16rfc(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
