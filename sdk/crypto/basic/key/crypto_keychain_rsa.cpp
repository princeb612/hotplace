/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_rsa.cpp
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

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, size_t bits, keydesc&& desc) {
    return crypto_keygen::add_rsa(cryptokey, nid, bits, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, size_t bits, keydesc&& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(std::forward<keydesc>(desc));
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, bits, std::move(kd));
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, keydesc&& desc) {
    // EVP_PKEY_RSA, NID_rsaEncryption
    // EVP_PKEY_RSA2, NID_rsa
    // EVP_PKEY_RSA_PSS, NID_rsassaPss
    if (EVP_PKEY_RSA == nid || EVP_PKEY_RSA2 == nid) {
        return crypto_keygen::add_rsa(cryptokey, nid, n, e, d, std::forward<keydesc>(desc));
    } else if (EVP_PKEY_RSA_PSS == nid) {
        return crypto_keygen::add_rsapss(cryptokey, nid, n, e, d, std::forward<keydesc>(desc));
    } else {
        return errorcode_t::bad_request;
    }
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, keydesc&& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(std::forward<keydesc>(desc));
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, n, e, d, std::move(kd));
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                                  const binary_t& dp, const binary_t& dq, const binary_t& qi, keydesc&& desc) {
    return add_rsa(cryptokey, nid, n, e, d, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                                  const binary_t& dp, const binary_t& dq, const binary_t& qi, keydesc&& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(std::forward<keydesc>(desc));
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, n, e, d, std::move(kd));
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* n, const char* e, const char* d, keydesc&& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_rsa_b64(cryptokey, nid, n, e, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base64url:
            ret = add_rsa_b64u(cryptokey, nid, n, e, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16:
            ret = add_rsa_b16(cryptokey, nid, n, e, d, std::forward<keydesc>(desc));
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_rsa_b16rfc(cryptokey, nid, n, e, d, std::forward<keydesc>(desc));
            break;
        default:
            ret = errorcode_t::not_supported;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, keydesc&& desc) {
    return add_rsa_b64(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                      const char* dq, const char* qi, keydesc&& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, keydesc&& desc) {
    return add_rsa_b64u(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                       const char* dq, const char* qi, keydesc&& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, keydesc&& desc) {
    return add_rsa_b16(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                      const char* dq, const char* qi, keydesc&& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, keydesc&& desc) {
    return add_rsa_b16rfc(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, std::forward<keydesc>(desc));
}

return_t crypto_keychain::add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                         const char* dq, const char* qi, keydesc&& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, std::forward<keydesc>(desc));
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
