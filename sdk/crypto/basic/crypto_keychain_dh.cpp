/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <fstream>
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    int ret_openssl = 0;
    EVP_PKEY* params = nullptr;
    EVP_PKEY_CTX* keyctx = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
        ret_openssl = EVP_PKEY_paramgen_init(ctx);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_CTX_set_dh_nid(ctx, nid);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_paramgen(ctx, &params);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        keyctx = EVP_PKEY_CTX_new(params, nullptr);
        if (nullptr == keyctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_keygen_init(keyctx);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_keygen(keyctx, &pkey);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        if (pkey) {
            crypto_key_object key(pkey, desc);
            ret = cryptokey->add(key);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        if (keyctx) {
            EVP_PKEY_CTX_free(keyctx);
        }
        if (params) {
            EVP_PKEY_free(params);
        }

        if (ctx) {
            EVP_PKEY_CTX_free(ctx);
        }
    }
    return ret;
}

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& pub, const binary_t& priv, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    DH* dh = nullptr;
    int ret_openssl = 0;
    __try2 {
        if (nullptr == cryptokey || pub.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
         * dh = DH_new
         * BN_hex2bn(&p, "ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1...")
         * BN_hex2bn(&g, "02")
         * DH_set0_pqg(dh, p, nullptr, g)
         */
        dh = DH_new_by_nid(nid);  // p, g, length
        if (nullptr == dh) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIGNUM* bn_pub = nullptr;
        BIGNUM* bn_priv = nullptr;

        bn_pub = BN_bin2bn(&pub[0], pub.size(), nullptr);
        if (priv.size()) {
            bn_priv = BN_bin2bn(&priv[0], priv.size(), nullptr);
        }

        ret_openssl = DH_set0_key(dh, bn_pub, bn_priv);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        pkey = EVP_PKEY_new();
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DH(pkey, dh);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        if (pkey) {
            crypto_key_object key(pkey, desc);
            ret = cryptokey->add(key);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
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

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);

        ret = add_dh(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
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

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);

        ret = add_dh(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode(input, strlen(input));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);

        ret = add_dh(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dh_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode_rfc(std::string(input));
            }
        };

        binary_t bin_pub;
        binary_t bin_priv;

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);

        ret = add_dh(cryptokey, nid, bin_pub, bin_priv, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
