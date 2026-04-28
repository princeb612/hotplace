/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_ec_uncompressed.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const binary_t& pubkey, const binary_t& privkey, const keydesc& desc) {
    return add_ec_uncompressed(cryptokey, nid, pubkey.data(), pubkey.size(), privkey.data(), privkey.size(), desc);
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const byte_t* pubkey, size_t pubsize, const byte_t* privkey, size_t privsize,
                                              const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EC_KEY* eck = nullptr;
    int rc = 1;
    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        eck = EC_KEY_new_by_curve_name(nid);
        if (nullptr == eck) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // call both o2i_ECPublicKey and EC_KEY_set_private_key
        if (pubkey && pubsize) {
            o2i_ECPublicKey(/* inout */ &eck, &pubkey, pubsize);
        }

        EC_KEY_ptr eckey(eck);
        eck = nullptr;  // eckey own eck

        if (privkey && privsize) {
            BN_ptr bn_priv(BN_bin2bn(privkey, privsize, nullptr));

            rc = EC_KEY_set_private_key(eckey.get(), bn_priv.get());
            if (rc != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        rc = EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.get());
        if (rc < 1) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        eckey.release();  // pkey own eckey

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        pkey.release();  // cryptokey own pkey
    }
    __finally2 {
        if (eck) {
            EC_KEY_free(eck);
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* pubkey, const char* privkey, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_ec_uncompressed_b64(cryptokey, nid, pubkey, privkey, desc);
            break;
        case encoding_t::encoding_base64url:
            ret = add_ec_uncompressed_b64u(cryptokey, nid, pubkey, privkey, desc);
            break;
        case encoding_t::encoding_base16:
            ret = add_ec_uncompressed_b16(cryptokey, nid, pubkey, privkey, desc);
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_ec_uncompressed_b16rfc(cryptokey, nid, pubkey, privkey, desc);
            break;
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
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {}
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
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;

        os2b(pubkey, bin_pub);
        os2b(privkey, bin_priv);

        ret = add_ec_uncompressed(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {}
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
    __finally2 {}
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
    __finally2 {}
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
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_ec_uncompressed(crypto_key* cryptokey, const char* curve, encoding_t encoding, const char* pubkey, const char* privkey,
                                              const keydesc& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_ec_uncompressed_b64(cryptokey, curve, pubkey, privkey, desc);
            break;
        case encoding_t::encoding_base64url:
            ret = add_ec_uncompressed_b64u(cryptokey, curve, pubkey, privkey, desc);
            break;
        case encoding_t::encoding_base16:
            ret = add_ec_uncompressed_b16(cryptokey, curve, pubkey, privkey, desc);
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_ec_uncompressed_b16rfc(cryptokey, curve, pubkey, privkey, desc);
            break;
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
    __finally2 {}
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
    __finally2 {}
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
    __finally2 {}
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
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
