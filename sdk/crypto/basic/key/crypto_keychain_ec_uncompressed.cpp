/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const binary_t& pubkey, const binary_t& privkey, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EC_KEY* eckey = nullptr;
    BIGNUM* bn_priv = nullptr;
    int rc = 1;
    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey = EVP_PKEY_new();
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        eckey = EC_KEY_new_by_curve_name(nid);
        if (nullptr == eckey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto p = &pubkey[0];
        o2i_ECPublicKey(&eckey, &p, pubkey.size());

        if (privkey.size()) {
            bn_priv = BN_bin2bn(&privkey[0], privkey.size(), nullptr);

            rc = EC_KEY_set_private_key(eckey, bn_priv);
            if (rc != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        rc = EVP_PKEY_assign_EC_KEY(pkey, eckey);
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        crypto_key_object key(pkey, desc);
        ret = cryptokey->add(key);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        // if (eckey) {
        //     EC_KEY_free(eckey);
        // }
        if (bn_priv) {
            BN_free(bn_priv);
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pubkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64_encoding);
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64u(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pubkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64url_encoding);
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc) {
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

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pubkey, const char* privkey, const keydesc& desc) {
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

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, const char* curve, const binary_t& pubkey, const binary_t& privkey, const keydesc& desc) {
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

        ret = add_ec_uncompressed(cryptokey, nid, pubkey, privkey, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc) {
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

        ret = add_ec_uncompressed_b64(cryptokey, nid, pubkey, privkey, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b64u(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc) {
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

        ret = add_ec_uncompressed_b64u(cryptokey, nid, pubkey, privkey, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc) {
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

        ret = add_ec_uncompressed_b16(cryptokey, nid, pubkey, privkey, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed_b16rfc(crypto_key* cryptokey, const char* curve, const char* pubkey, const char* privkey, const keydesc& desc) {
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

        ret = add_ec_uncompressed_b16rfc(cryptokey, nid, pubkey, privkey, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
