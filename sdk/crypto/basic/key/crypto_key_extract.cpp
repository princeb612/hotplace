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
#include <hotplace/sdk/crypto/basic/evp_key.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_key::extract(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, crypt_datamap_t& datamap, bool preserve) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;

    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = ktyof_evp_pkey(pkey);
        switch (type) {
            case crypto_kty_t::kty_oct:
                ret = extract_oct(pkey, flags, type, datamap, preserve);
                break;
            case crypto_kty_t::kty_rsa:
            case crypto_kty_t::kty_rsapss:
                ret = extract_rsa(pkey, flags, type, datamap, preserve);
                break;
            case crypto_kty_t::kty_ec:
                ret = extract_ec(pkey, flags, type, datamap, preserve);
                break;
            case crypto_kty_t::kty_okp:
                ret = extract_okp(pkey, flags, type, datamap, preserve);
                break;
            case crypto_kty_t::kty_dh:
                ret = extract_dh(pkey, flags, type, datamap, preserve);
                break;
            case crypto_kty_t::kty_dsa:
                ret = extract_dsa(pkey, flags, type, datamap, preserve);
                break;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::extract_oct(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = ktyof_evp_pkey(pkey);

        if (crypto_kty_t::kty_oct != type) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        if (crypt_access_t::private_key & flags) {
            size_t key_length = 0;
            binary_t bin_k;
            EVP_PKEY_get_raw_private_key(pkey, nullptr, &key_length);
            bin_k.resize(key_length);
            EVP_PKEY_get_raw_private_key(pkey, &bin_k[0], &key_length);

            datamap.insert(std::make_pair(crypt_item_t::item_hmac_k, bin_k));
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::extract_rsa(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = ktyof_evp_pkey(pkey);

        if ((crypto_kty_t::kty_rsa != type) && (crypto_kty_t::kty_rsapss != type)) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        const BIGNUM* n = nullptr;
        const BIGNUM* e = nullptr;
        const BIGNUM* d = nullptr;

        const RSA* rsa = EVP_PKEY_get0_RSA((EVP_PKEY*)pkey);
        RSA_get0_key(rsa, &n, &e, &d);

        if (crypt_access_t::asn1public_key & flags) {
            /**
             * RFC 3279 Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
             * 2.3.1  RSA Keys
             * The RSA public key MUST be encoded using the ASN.1 type RSAPublicKey:
             *
             *    RSAPublicKey ::= SEQUENCE {
             *       modulus            INTEGER,    -- n
             *       publicExponent     INTEGER  }  -- e
             */
            binary_t bin_pub;
            get_asn1public_key(pkey, bin_pub);
            datamap.insert(std::make_pair(crypt_item_t::item_asn1der, bin_pub));
        } else if (crypt_access_t::public_key & flags) {
            binary_t bin_n;
            binary_t bin_e;
            bn2bin(n, bin_n);
            bn2bin(e, bin_e);
            datamap.insert(std::make_pair(crypt_item_t::item_rsa_n, bin_n));
            datamap.insert(std::make_pair(crypt_item_t::item_rsa_e, bin_e));
        }

        if (crypt_access_t::private_key & flags) {
            if (d) {
                binary_t bin_d;
                int len_d = BN_num_bytes(d);
                bin_d.resize(len_d);
                BN_bn2bin(d, &bin_d[0]);
                datamap.insert(std::make_pair(crypt_item_t::item_rsa_d, bin_d));
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::extract_ec(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;
    EC_KEY* ec = nullptr;

    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = ktyof_evp_pkey(pkey);

        if (crypto_kty_t::kty_ec != type) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        // preserve leading zero octets
        uint32 keysize = 0;
        if (plzero || (crypt_access_t::public_key & flags)) {
            uint32 nid = 0;
            nidof_evp_pkey(pkey, nid);
            crypto_advisor* advisor = crypto_advisor::get_instance();
            auto hint = advisor->hintof_curve_nid(nid);
            keysize = keysizeof(hint);
        }

        if (crypt_access_t::asn1public_key & flags) {
            binary_t bin_pub;
            get_asn1public_key(pkey, bin_pub);
            datamap.insert(std::make_pair(crypt_item_t::item_asn1der, bin_pub));
        } else if (crypt_access_t::public_key & flags) {
            x = BN_new();
            y = BN_new();

            ec = EVP_PKEY_get1_EC_KEY((EVP_PKEY*)pkey);

            const EC_GROUP* group = EC_KEY_get0_group(ec);
            const EC_POINT* pub = EC_KEY_get0_public_key(ec);

            ret_openssl = EC_POINT_get_affine_coordinates(group, pub, x, y, nullptr);  // EC_POINT_get_affine_coordinates_GFp
            if (ret_openssl) {
                binary_t bin_x;
                binary_t bin_y;

                bn2bin(x, bin_x);
                bn2bin(y, bin_y);

                auto len_x = bin_x.size();
                auto len_y = bin_y.size();

                if (keysize) {
                    if (keysize > len_x) {
                        bin_x.insert(bin_x.begin(), keysize - len_x, 0);
                    }
                    if (keysize > len_y) {
                        bin_y.insert(bin_y.begin(), keysize - len_y, 0);
                    }
                }

                datamap.insert(std::make_pair(crypt_item_t::item_ec_x, bin_x));
                datamap.insert(std::make_pair(crypt_item_t::item_ec_y, bin_y));

                binary_t uncompressed;
                binary_append(uncompressed, uint8(4));
                binary_append(uncompressed, bin_x);
                binary_append(uncompressed, bin_y);
                datamap.insert(std::make_pair(crypt_item_t::item_ec_pub_uncompressed, uncompressed));
            }
        }
        if (crypt_access_t::private_key & flags) {
            const BIGNUM* d = EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY((EVP_PKEY*)pkey));
            if (d) {
                binary_t bin_d;
                bn2bin(d, bin_d);

                auto len_d = bin_d.size();

                if (keysize) {
                    if (keysize > len_d) {
                        bin_d.insert(bin_d.begin(), keysize - len_d, 0);
                    }
                }

                datamap.insert(std::make_pair(crypt_item_t::item_ec_d, bin_d));
            }
        }
    }
    __finally2 {
        if (ec) {
            EC_KEY_free(ec);
        }
        if (x) {
            BN_free(x);
        }
        if (y) {
            BN_free(y);
        }
    }
    return ret;
}

return_t crypto_key::extract_okp(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = ktyof_evp_pkey(pkey);

        if (crypto_kty_t::kty_okp != type) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        // preserve leading zero octets
        uint32 curve_size = 0;
        if (plzero) {
            uint32 nid = 0;
            nidof_evp_pkey(pkey, nid);
            switch (nid) {
                case NID_ED25519:
                case NID_X25519:
                    curve_size = 32;
                    break;
                case EVP_PKEY_ED448:
                case EVP_PKEY_X448:
                    curve_size = 57;
                    break;
            }
        }

        if (crypt_access_t::asn1public_key & flags) {
            binary_t bin_pub;
            get_asn1public_key(pkey, bin_pub);
            datamap.insert(std::make_pair(crypt_item_t::item_asn1der, std::move(bin_pub)));
        } else if (crypt_access_t::public_key & flags) {
            binary_t bin_x;
            size_t len_x = curve_size ? curve_size : 256;
            bin_x.resize(len_x);
            ret_openssl = EVP_PKEY_get_raw_public_key(pkey, &bin_x[0], &len_x);
            bin_x.resize(len_x);

            if (curve_size) {
                if (curve_size > len_x) {
                    bin_x.insert(bin_x.begin(), curve_size - len_x, 0);
                }
            }

            if (1 == ret_openssl) {
                datamap.insert(std::make_pair(crypt_item_t::item_ec_x, std::move(bin_x)));
            }
        }
        if (crypt_access_t::private_key & flags) {
            binary_t bin_d;
            size_t len_d = curve_size ? curve_size : 256;
            bin_d.resize(len_d);
            ret_openssl = EVP_PKEY_get_raw_private_key(pkey, &bin_d[0], &len_d);
            bin_d.resize(len_d);

            if (curve_size) {
                if (curve_size > len_d) {
                    bin_d.insert(bin_d.begin(), curve_size - len_d, 0);
                }
            }

            if (1 == ret_openssl) {
                datamap.insert(std::make_pair(crypt_item_t::item_ec_d, std::move(bin_d)));
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::extract_dh(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = ktyof_evp_pkey(pkey);

        if (crypto_kty_t::kty_dh != type) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        const DH* dh = nullptr;
        const BIGNUM* bn_pub = nullptr;
        const BIGNUM* bn_priv = nullptr;
        int len_pub = 0;
        int len_priv = 0;
        binary_t bin_pub;
        binary_t bin_priv;

        dh = EVP_PKEY_get0_DH((EVP_PKEY*)pkey);
        if (nullptr == dh) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        DH_get0_key(dh, &bn_pub, &bn_priv);

        /**
         * RFC 3279 Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
         * 2.3.3  Diffie-Hellman Key Exchange Keys
         */
        if (crypt_access_t::asn1public_key & flags) {
            get_asn1public_key(pkey, bin_pub);
            datamap.insert(std::make_pair(crypt_item_t::item_asn1der, std::move(bin_pub)));
        } else if (crypt_access_t::public_key & flags) {
            if (bn_pub) {
                len_pub = BN_num_bytes(bn_pub);
                bin_pub.resize(len_pub);
                BN_bn2bin(bn_pub, &bin_pub[0]);
                datamap.insert(std::make_pair(crypt_item_t::item_dh_pub, std::move(bin_pub)));
            }
        }

        if (crypt_access_t::private_key & flags) {
            if (bn_priv) {
                len_priv = BN_num_bytes(bn_priv);
                bin_priv.resize(len_priv);
                BN_bn2bin(bn_priv, &bin_priv[0]);
                datamap.insert(std::make_pair(crypt_item_t::item_dh_priv, std::move(bin_priv)));
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_key::extract_dsa(const EVP_PKEY* pkey, int flags, crypto_kty_t& type, crypt_datamap_t& datamap, bool plzero) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;
    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = ktyof_evp_pkey(pkey);

        if (crypto_kty_t::kty_dsa != type) {
            ret = errorcode_t::different_type;
            __leave2;
        }

        auto dsa = EVP_PKEY_get0_DSA((EVP_PKEY*)pkey);
        const BIGNUM* bn_p = nullptr;
        const BIGNUM* bn_q = nullptr;
        const BIGNUM* bn_g = nullptr;
        const BIGNUM* bn_y = nullptr;
        const BIGNUM* bn_x = nullptr;

        DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);
        DSA_get0_key(dsa, &bn_y, &bn_x);

        /**
         * RFC 3279 Algorithms and Identifiers for the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
         * 2.3.2  DSA Signature Keys
         */
        if (crypt_access_t::asn1public_key & flags) {
            binary_t bin_pub;
            get_asn1public_key(pkey, bin_pub);
            datamap.insert(std::make_pair(crypt_item_t::item_asn1der, std::move(bin_pub)));
        } else if (crypt_access_t::public_key & flags) {
            if (0) {
                if (bn_y) {
                    binary_t bin_y;
                    bn2bin(bn_y, bin_y);
                    datamap.insert(std::make_pair(crypt_item_t::item_dsa_y, std::move(bin_y)));
                }
                if (bn_p) {
                    binary_t bin_p;
                    bn2bin(bn_p, bin_p);
                    datamap.insert(std::make_pair(crypt_item_t::item_dsa_p, std::move(bin_p)));
                }
                if (bn_q) {
                    binary_t bin_q;
                    bn2bin(bn_q, bin_q);
                    datamap.insert(std::make_pair(crypt_item_t::item_dsa_q, std::move(bin_q)));
                }
                if (bn_g) {
                    binary_t bin_g;
                    bn2bin(bn_g, bin_g);
                    datamap.insert(std::make_pair(crypt_item_t::item_dsa_g, std::move(bin_g)));
                }
            }
        }

        if (crypt_access_t::private_key & flags) {
            if (bn_x) {
                binary_t bin_x;
                bn2bin(bn_x, bin_x);
                datamap.insert(std::make_pair(crypt_item_t::item_dsa_priv, std::move(bin_x)));
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
