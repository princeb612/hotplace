/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/evp_key.hpp>

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
        if (crypto_kty_t::kty_oct == type) {
            // do nothing
        } else if (crypto_kty_t::kty_rsa == type) {
            iter = datamap.find(crypt_item_t::item_rsa_n);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_rsa_e);
            if (datamap.end() != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_kty_t::kty_ec == type) {
            iter = datamap.find(crypt_item_t::item_ec_x);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_ec_y);
            if (datamap.end() != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_kty_t::kty_okp == type) {
            iter = datamap.find(crypt_item_t::item_ec_x);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::ec_uncompressed_key(const EVP_PKEY* pkey, binary_t& uncompressed, binary_t& priv) {
    return_t ret = errorcode_t::success;
    __try2 {
        uncompressed.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_kty_t kty = typeof_crypto_key(pkey);
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

        binary_append(uncompressed, uint8(4));
        binary_append(uncompressed, x);
        binary_append(uncompressed, y);
        priv = std::move(d);
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

        crypto_kty_t kty = typeof_crypto_key(pkey);
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
            case crypto_kty_t::kty_ec:
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
        }
    }
    return ret;
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, binary_t& pub, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_kty_t kty = typeof_crypto_key(pkey);
        switch (kty) {
            case kty_oct:
            case kty_okp:
            case kty_dh: {
                binary_t bin_pub1;
                binary_t bin_pub2;
                binary_t bin_priv;

                ret = get_key(pkey, bin_pub1, bin_pub2, bin_priv, preserve);
                if (errorcode_t::success == ret) {
                    pub = std::move(bin_pub1);
                    priv = std::move(bin_priv);
                }
            } break;
            case kty_ec: {
                ret = ec_uncompressed_key(pkey, pub, priv);
            } break;
            case kty_rsa:
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

    return get_key(pkey, 1, type, pub1, pub2, priv, preserve);
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    crypto_kty_t type = crypto_kty_t::kty_unknown;

    return get_key(pkey, flag, type, pub1, pub2, priv, preserve);
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, int flag, crypto_kty_t& type, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;

    pub1.clear();
    pub2.clear();
    priv.clear();
    type = crypto_kty_t::kty_unknown;

    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;
    int flag_request = crypt_access_t::public_key;

    if (flag) {
        flag_request |= crypt_access_t::private_key;
    }
    ret = extract(pkey, flag_request, type, datamap, preserve);
    if (errorcode_t::success == ret) {
        switch (type) {
            case crypto_kty_t::kty_oct: {
                iter = datamap.find(crypt_item_t::item_hmac_k);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_rsa:
            case crypto_kty_t::kty_rsapss: {
                iter = datamap.find(crypt_item_t::item_rsa_n);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_rsa_e);
                if (datamap.end() != iter) {
                    pub2 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_rsa_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_ec: {
                iter = datamap.find(crypt_item_t::item_ec_x);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_ec_y);
                if (datamap.end() != iter) {
                    pub2 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_ec_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_okp: {
                iter = datamap.find(crypt_item_t::item_ec_x);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_ec_d);
                if (datamap.end() != iter) {
                    priv = iter->second;
                }
            } break;
            case crypto_kty_t::kty_dh: {
                iter = datamap.find(crypt_item_t::item_dh_pub);
                if (datamap.end() != iter) {
                    pub1 = iter->second;
                }
                iter = datamap.find(crypt_item_t::item_dh_priv);
                if (datamap.end() != iter) {
                    priv = iter->second;
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
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
