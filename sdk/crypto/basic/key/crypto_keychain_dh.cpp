/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_dh.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
 *
 *   y = g^x mod p
 *     p : prime
 *     g : generator
 *     x : privateate key
 *     y : public key
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, keydesc&& desc) { return crypto_keygen::add_dh(cryptokey, nid, std::forward<keydesc>(desc)); }

return_t crypto_keychain::add_dh(crypto_key* cryptokey, const char* curve, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_curve(curve);
    if (hint) {
        ret = add_dh(cryptokey, hint->nid, std::forward<keydesc>(desc));
    }
    return ret;
}

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& y, const binary_t& x, keydesc&& desc) {
    return crypto_keygen::add_dh(cryptokey, nid, y, x, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& p, const binary_t& q, const binary_t& g, const binary_t& x, keydesc&& desc) {
    return crypto_keygen::add_dh(cryptokey, nid, p, q, g, x, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* y, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_dh_b64(cryptokey, nid, y, x, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_dh_b64u(cryptokey, nid, y, x, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_dh_b16(cryptokey, nid, y, x, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_dh_b16rfc(cryptokey, nid, y, x, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16rfc(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* p, const char* q, const char* g, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_dh_b64(cryptokey, nid, p, q, g, x, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_dh_b64u(cryptokey, nid, p, q, g, x, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_dh_b16(cryptokey, nid, p, q, g, x, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_dh_b16rfc(cryptokey, nid, p, q, g, x, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16rfc(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
