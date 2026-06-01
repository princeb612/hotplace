/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_dsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keygen.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, uint32 nid, keydesc&& desc) { return crypto_keygen::add_dsa(cryptokey, nid, std::forward<keydesc>(desc)); }

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, const char* name, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int nid = OBJ_sn2nid(name);
        if (nid_dsa != nid) {
            nid = OBJ_ln2nid(name);
        }
        if (nid_dsa != nid) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = add_dsa(cryptokey, nid, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, uint32 nid, const binary_t& y, const binary_t& x, const binary_t& p, const binary_t& q, const binary_t& g,
                                  keydesc&& desc) {
    return crypto_keygen::add_dsa(cryptokey, nid, y, x, p, q, g, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* y, const char* x, const char* p, const char* q, const char* g,
                                  keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_dsa_b64(cryptokey, nid, y, x, p, q, g, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_dsa_b64u(cryptokey, nid, y, x, p, q, g, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_dsa_b16(cryptokey, nid, y, x, p, q, g, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_dsa_b16rfc(cryptokey, nid, y, x, p, q, g, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_dsa_b64(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const char* p, const char* q, const char* g, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y || nullptr == p || (nullptr == q && nullptr == x) || nullptr == g) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(y, bin_pub);
        os2b(x, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dsa_b64u(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const char* p, const char* q, const char* g, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y || nullptr == p || (nullptr == q && nullptr == x) || nullptr == g) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(y, bin_pub);
        os2b(x, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dsa_b16(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const char* p, const char* q, const char* g, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y || nullptr == p || (nullptr == q && nullptr == x) || nullptr == g) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(y, bin_pub);
        os2b(x, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const char* p, const char* q, const char* g, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y || nullptr == p || (nullptr == q && nullptr == x) || nullptr == g) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(y, bin_pub);
        os2b(x, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
