/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_key::get_public_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2) {
    return_t ret = errorcode_t::success;

    pub1.clear();
    pub2.clear();

    crypto_kty_t type = crypto_kty_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract(pkey, crypt_access_t::public_key, type, datamap);
    if (errorcode_t::success == ret) {
        switch (type) {
            case crypto_kty_t::kty_oct: {
                // do nothing
            } break;
            case crypto_kty_t::kty_rsa:
            case crypto_kty_t::kty_rsapss: {
                // n, e
                iter = datamap.find(crypt_item_t::item_rsa_n);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_rsa_e);
                if (datamap.end() != iter) {
                    pub2 = iter->second;
                }
            } break;
            case crypto_kty_t::kty_ec: {
                // x, y
                iter = datamap.find(crypt_item_t::item_ec_x);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_ec_y);
                if (datamap.end() != iter) {
                    pub2 = iter->second;
                }
            } break;
            case crypto_kty_t::kty_okp: {
                // x
                iter = datamap.find(crypt_item_t::item_ec_x);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
            } break;
            case crypto_kty_t::kty_dh: {
                // pub
                iter = datamap.find(crypt_item_t::item_dh_pub);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
            } break;
            case crypto_kty_t::kty_dsa: {
                // do nothing
            } break;
            case crypto_kty_t::kty_mlkem: {
                // pub
                iter = datamap.find(crypt_item_t::item_mlkem_pub);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
            } break;
        }
    }
    return ret;
}

return_t crypto_key::ec_uncompressed_key(const EVP_PKEY* pkey, binary_t& uncompressed, binary_t& priv) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_kty_t kty = ktyof_evp_pkey(pkey);
        if (kty_ec != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        ret = get_key(pkey, public_key | private_key, uncompressed, priv, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::ec_compressed_key(const EVP_PKEY* pkey, binary_t& compressed, binary_t& priv) {
    return_t ret = errorcode_t::success;

    __try2 {
        compressed.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_kty_t kty = ktyof_evp_pkey(pkey);
        if (kty_ec != kty) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        binary_t x;
        binary_t y;
        binary_t d;
        ret = get_key(pkey, kty, x, y, d, true);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // | y    | format  | ysign    |
        // | even | 02 || x | 0, false |
        // | odd  | 03 || x | 1, true  |
        uint8 lsb = *y.rbegin();
        bool ysign = (lsb % 2) ? true : false;
        binary_append(compressed, uint8(ysign ? 3 : 2));
        binary_append(compressed, x);
        priv = std::move(d);
    }
    __finally2 {}

    return ret;
}

return_t crypto_key::get_private_key(const EVP_PKEY* pkey, binary_t& priv) {
    return_t ret = errorcode_t::success;

    priv.clear();

    crypto_kty_t type = crypto_kty_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract(pkey, crypt_access_t::private_key, type, datamap);
    if (errorcode_t::success == ret) {
        switch (type) {
            case crypto_kty_t::kty_oct: {
                // k
                iter = datamap.find(crypt_item_t::item_hmac_k);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_rsa:
            case crypto_kty_t::kty_rsapss: {
                // d
                iter = datamap.find(crypt_item_t::item_rsa_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_ec:
            case crypto_kty_t::kty_okp: {
                // d
                iter = datamap.find(crypt_item_t::item_ec_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_dh: {
                // priv
                iter = datamap.find(crypt_item_t::item_dh_priv);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_dsa: {
                // x
                iter = datamap.find(crypt_item_t::item_dsa_x);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_mlkem: {
                iter = datamap.find(crypt_item_t::item_mlkem_priv);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
        }
    }
    return ret;
}

return_t crypto_key::get_asn1public_key(const EVP_PKEY* pkey, binary_t& pub) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int type = EVP_PKEY_id(pkey);
        if (EVP_PKEY_KEYMGMT != type) {
            int len = i2d_PUBKEY((EVP_PKEY*)pkey, nullptr);
            if (len < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            pub.resize(len);
            byte_t* p = &pub[0];
            len = i2d_PUBKEY((EVP_PKEY*)pkey, &p);
        } else {
            crypto_keychain keychain;
            ret = keychain.pkey_encode(nullptr, pkey, pub, key_encoding_pub_der);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, binary_t& pub, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;
    ret = get_key(pkey, public_key | private_key, pub, priv, preserve);
    return ret;
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, int flags, binary_t& pub, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pub.clear();
        priv.clear();

        crypto_kty_t kty = ktyof_evp_pkey(pkey);
        crypt_datamap_t datamap;
        crypt_datamap_t::iterator iter;

        ret = extract(pkey, flags, kty, datamap, preserve);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto lambda_get_item = [&](crypt_item_t item, binary_t& bin) -> void {
            auto iter = datamap.find(item);
            if (datamap.end() != iter) {
                bin = iter->second;
            }
        };

        switch (kty) {
            case kty_oct: {
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_hmac_k, priv);
                }
            } break;
            case kty_rsa:
            case kty_rsapss: {
                if (asn1public_key & flags) {
                    lambda_get_item(crypt_item_t::item_asn1der, pub);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_rsa_d, priv);
                }
            } break;
            case kty_ec: {
                if (asn1public_key & flags) {
                    lambda_get_item(crypt_item_t::item_asn1der, pub);
                } else if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_pub_uncompressed, pub);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_d, priv);
                }
            } break;
            case kty_okp: {
                if (asn1public_key & flags) {
                    lambda_get_item(crypt_item_t::item_asn1der, pub);
                } else if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_x, pub);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_d, priv);
                }
            } break;
            case kty_dh: {
                if (asn1public_key & flags) {
                    lambda_get_item(crypt_item_t::item_asn1der, pub);
                } else if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_dh_pub, pub);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_dh_priv, priv);
                }
            } break;
            case kty_dsa: {
                if (asn1public_key & flags) {
                    lambda_get_item(crypt_item_t::item_asn1der, pub);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_dsa_priv, priv);
                }
            } break;
            case kty_mlkem: {
                if ((public_key | asn1public_key) & flags) {
                    lambda_get_item(crypt_item_t::item_mlkem_pub, pub);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_mlkem_priv, priv);
                }
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    crypto_kty_t type = crypto_kty_t::kty_unknown;

    return get_key(pkey, crypt_access_t::private_key | crypt_access_t::public_key, type, pub1, pub2, priv, preserve);
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, int flags, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    crypto_kty_t type = crypto_kty_t::kty_unknown;

    return get_key(pkey, flags, type, pub1, pub2, priv, preserve);
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;

    pub1.clear();
    pub2.clear();
    priv.clear();
    type = crypto_kty_t::kty_unknown;

    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;
    ret = extract(pkey, flags, type, datamap, preserve);
    if (errorcode_t::success == ret) {
        auto lambda_get_item = [&](crypt_item_t item, binary_t& bin) -> void {
            auto iter = datamap.find(item);
            if (datamap.end() != iter) {
                bin = iter->second;
            }
        };

        switch (type) {
            case crypto_kty_t::kty_oct: {
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_hmac_k, priv);
                }
            } break;
            case crypto_kty_t::kty_rsa:
            case crypto_kty_t::kty_rsapss: {
                if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_rsa_n, pub1);
                    lambda_get_item(crypt_item_t::item_rsa_e, pub2);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_rsa_d, priv);
                }
            } break;
            case crypto_kty_t::kty_ec: {
                if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_x, pub1);
                    lambda_get_item(crypt_item_t::item_ec_y, pub2);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_d, priv);
                }
            } break;
            case crypto_kty_t::kty_okp: {
                if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_x, pub1);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_ec_d, priv);
                }
            } break;
            case crypto_kty_t::kty_dh: {
                if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_dh_pub, pub1);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_dh_priv, priv);
                }
            } break;
            case crypto_kty_t::kty_dsa: {
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_dsa_priv, priv);
                }
            } break;
            case crypto_kty_t::kty_mlkem: {
                if (public_key & flags) {
                    lambda_get_item(crypt_item_t::item_mlkem_pub, pub1);
                }
                if (private_key & flags) {
                    lambda_get_item(crypt_item_t::item_mlkem_priv, priv);
                }
            } break;
        }
    }
    return ret;
}

return_t crypto_key::get_privkey(const EVP_PKEY* pkey, crypto_kty_t& type, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;

    priv.clear();

    type = crypto_kty_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;
    int flag_request = crypt_access_t::private_key;

    ret = extract(pkey, flag_request, type, datamap, preserve);
    if (errorcode_t::success == ret) {
        switch (type) {
            case crypto_kty_t::kty_oct: {
                iter = datamap.find(crypt_item_t::item_hmac_k);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_rsa: {
                iter = datamap.find(crypt_item_t::item_rsa_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_ec: {
                iter = datamap.find(crypt_item_t::item_ec_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_okp: {
                iter = datamap.find(crypt_item_t::item_ec_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_dh: {
                iter = datamap.find(crypt_item_t::item_dh_priv);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_dsa: {
                iter = datamap.find(crypt_item_t::item_dsa_priv);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_mlkem: {
                iter = datamap.find(crypt_item_t::item_mlkem_priv);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
