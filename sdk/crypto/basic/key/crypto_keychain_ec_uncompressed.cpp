/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_ec_uncompressed.cpp
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

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const binary_t& pubkey, const binary_t& privkey, keydesc&& desc) {
    return add_ec_uncompressed(cryptokey, nid, pubkey.data(), pubkey.size(), privkey.data(), privkey.size(), std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const byte_t* pubkey, size_t pubsize, const byte_t* privkey, size_t privsize,
                                              keydesc&& desc) {
    return crypto_keygen::add_ec_uncompressed(cryptokey, nid, pubkey, pubsize, privkey, privsize, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_ec_uncompressed_b64(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_ec_uncompressed_b64u(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_ec_uncompressed_b16(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_ec_uncompressed_b16rfc(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pubkey) {
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

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64u(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pubkey) {
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

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pubkey) {
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

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pubkey) {
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

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, const char* curve, const binary_t& pubkey, const binary_t& privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_uncompressed(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, const char* curve, encoding_t encoding, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_ec_uncompressed_b64(cryptokey, curve, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_ec_uncompressed_b64u(cryptokey, curve, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_ec_uncompressed_b16(cryptokey, curve, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_ec_uncompressed_b16rfc(cryptokey, curve, pubkey, privkey, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == pubkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_uncompressed_b64(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64u(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == pubkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_uncompressed_b64u(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == pubkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_uncompressed_b16(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16rfc(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == pubkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_uncompressed_b16rfc(cryptokey, nid, pubkey, privkey, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
