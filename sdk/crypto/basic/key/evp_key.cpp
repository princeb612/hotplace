/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

return_t nidof_evp_pkey(const EVP_PKEY* pkey, uint32& nid) {
    return_t ret = errorcode_t::success;

    __try2 {
        nid = 0;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        nid = EVP_PKEY_id(pkey);
        if (EVP_PKEY_EC == nid) {
            EC_KEY* ec = EVP_PKEY_get1_EC_KEY((EVP_PKEY*)pkey);
            if (ec) {
                const EC_GROUP* group = EC_KEY_get0_group(ec);
                nid = EC_GROUP_get_curve_name(group);
                EC_KEY_free(ec);
            }
        }
        if (0 == nid) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool kindof_ecc(const EVP_PKEY* pkey) {
    bool test = false;

    if (pkey) {
        int type = EVP_PKEY_id(pkey);
        test = ((EVP_PKEY_EC == type) || (EVP_PKEY_ED25519 == type) || (EVP_PKEY_ED448 == type) || (EVP_PKEY_X25519 == type) || (EVP_PKEY_X448 == type));
    }
    return test;
}

crypto_kty_t typeof_crypto_key(const EVP_PKEY* pkey) {
    crypto_kty_t kty = crypto_kty_t::kty_unknown;
    if (pkey) {
        int type = EVP_PKEY_id(pkey);

        switch (type) {
            case EVP_PKEY_HMAC:
                kty = crypto_kty_t::kty_oct;
                break;
            case EVP_PKEY_RSA:
            case EVP_PKEY_RSA2:
                kty = crypto_kty_t::kty_rsa;
                break;
            case EVP_PKEY_RSA_PSS:
                kty = crypto_kty_t::kty_rsapss;
                break;
            case EVP_PKEY_EC:
                kty = crypto_kty_t::kty_ec;
                break;
            case EVP_PKEY_X25519:
            case EVP_PKEY_X448:
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
                kty = crypto_kty_t::kty_okp;
                break;
            case EVP_PKEY_DH:
                kty = crypto_kty_t::kty_dh;
                break;
            case EVP_PKEY_DSA:
                kty = crypto_kty_t::kty_dsa;
                break;
            default:
                break;
        }
    }
    return kty;
}

return_t is_private_key(const EVP_PKEY* pkey, bool& result) {
    return_t ret = errorcode_t::success;

    __try2 {
        result = false;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const EVP_PKEY* key = pkey;
        int type = EVP_PKEY_id(key);

        switch (type) {
            case EVP_PKEY_HMAC:
                result = true;
                break;
            case EVP_PKEY_RSA:
            case EVP_PKEY_RSA2:
            case EVP_PKEY_RSA_PSS:
                if (nullptr != RSA_get0_d(EVP_PKEY_get0_RSA((EVP_PKEY*)key))) {
                    result = true;
                }
                break;
            case EVP_PKEY_EC: {
                const BIGNUM* bn = EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY((EVP_PKEY*)key));
                if (nullptr != bn) {
                    result = true;
                }
                break;
            }
            case EVP_PKEY_X25519:
            case EVP_PKEY_X448:
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448: {
                binary_t bin_d;
                size_t len_d = 256;
                bin_d.resize(len_d);
                int check = EVP_PKEY_get_raw_private_key(pkey, &bin_d[0], &len_d);
                bin_d.resize(len_d);
                if (1 == check) {
                    result = true;
                }
                break;
            }
            case EVP_PKEY_DH: {
                auto dh = EVP_PKEY_get0_DH((EVP_PKEY*)pkey);
                const BIGNUM* bn_priv = nullptr;
                DH_get0_key(dh, nullptr, &bn_priv);
                if (bn_priv) {
                    result = true;
                }
            } break;
            case EVP_PKEY_DSA: {
                auto dsa = EVP_PKEY_get0_DSA((EVP_PKEY*)pkey);
                const BIGNUM* bn_pub = nullptr;
                const BIGNUM* bn_priv = nullptr;
                DSA_get0_key(dsa, &bn_pub, &bn_priv);
                if (bn_priv) {
                    binary_t bin_priv;
                    bn2bin(bn_priv, bin_priv);
                    if (bin_priv.size()) {
                        result = true;
                    }
                }
            } break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool kindof_ecc(crypto_kty_t type) { return (crypto_kty_t::kty_ec == type) || (crypto_kty_t::kty_okp == type); }

const char* nameof_key_type(crypto_kty_t type) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    return advisor->nameof_kty(type);
}

bool is_kindof(const EVP_PKEY* pkey, crypto_kty_t type) {
    bool test = false;
    crypto_kty_t kty = typeof_crypto_key(pkey);

    test = (kty == type);
    return test;
}

return_t bn2bin(const BIGNUM* bn, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == bn) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        bin.resize(BN_num_bytes(bn));
        BN_bn2bin(bn, &bin[0]);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t bin2bn(const binary_t& bin, BIGNUM** bn) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == bn) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (bin.size()) {
            *bn = BN_bin2bn(&bin[0], bin.size(), nullptr);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
