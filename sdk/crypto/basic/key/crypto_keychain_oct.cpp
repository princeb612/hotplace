/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_oct.cpp
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

return_t crypto_keychain::add_oct(crypto_key* cryptokey, size_t size, keydesc&& desc) { return crypto_keygen::add_oct(cryptokey, size, std::forward<keydesc>(desc)); }

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const binary_t& k, keydesc&& desc) {
    return add_oct(cryptokey, k.data(), k.size(), std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, keydesc&& desc) {
    return crypto_keygen::add_oct(cryptokey, k, size, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, jwa_t alg, const binary_t& k, keydesc&& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(std::forward<keydesc>(desc));
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_oct(cryptokey, k, std::move(kd));
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, encoding_t encoding, const char* k, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_oct_b64(cryptokey, k, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_oct_b64u(cryptokey, k, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_oct_b16(cryptokey, k, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_oct_b16rfc(cryptokey, k, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_oct_b64(crypto_key* cryptokey, const char* k, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_k;

        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_oct_b64u(crypto_key* cryptokey, const char* k, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_k;

        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_oct_b16(crypto_key* cryptokey, const char* k, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_k;
        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_oct_b16rfc(crypto_key* cryptokey, const char* k, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_k;
        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
