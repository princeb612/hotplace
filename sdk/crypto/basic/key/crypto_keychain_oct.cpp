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
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_oct(crypto_key* cryptokey, size_t size, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_prng r;
        binary_t temp;
        r.random(temp, size);
        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, &temp[0], size);
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);
        ret = cryptokey->add(key);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const binary_t& k, const keydesc& desc) { return add_oct(cryptokey, &k[0], k.size(), desc); }

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, k, size);
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);
        ret = cryptokey->add(key);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, jwa_t alg, const binary_t& k, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_oct(cryptokey, k, kd);
}

return_t crypto_keychain::add_oct_b64(crypto_key* cryptokey, const char* k, const keydesc& desc) {
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

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_oct_b64u(crypto_key* cryptokey, const char* k, const keydesc& desc) {
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

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_oct_b16(crypto_key* cryptokey, const char* k, const keydesc& desc) {
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

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_oct_b16rfc(crypto_key* cryptokey, const char* k, const keydesc& desc) {
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

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
