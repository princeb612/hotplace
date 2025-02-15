/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_keychain.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    DSA* dsa = nullptr;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        dsa = DSA_new();
        if (nullptr == dsa) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = DSA_generate_parameters_ex(dsa, 2048, nullptr, 0, nullptr, nullptr, nullptr);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = DSA_generate_key(dsa);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        pkey = EVP_PKEY_new();
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DSA(pkey, dsa);
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
            if (dsa) {
                DSA_free(dsa);
            }
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, uint32 nid, const binary_t& pub, const binary_t& priv, const binary_t& p, const binary_t& q,
                                  const binary_t& g, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    DSA* dsa = nullptr;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        dsa = DSA_new();
        if (nullptr == dsa) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        BIGNUM* bn_p = nullptr;
        BIGNUM* bn_q = nullptr;
        BIGNUM* bn_g = nullptr;
        bn_p = BN_bin2bn(&p[0], p.size(), nullptr);
        bn_q = BN_bin2bn(&q[0], q.size(), nullptr);
        bn_g = BN_bin2bn(&g[0], g.size(), nullptr);
        ret_openssl = DSA_set0_pqg(dsa, bn_p, bn_q, bn_g);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        BIGNUM* bn_pub = nullptr;
        BIGNUM* bn_priv = nullptr;
        bn_pub = BN_bin2bn(&pub[0], pub.size(), nullptr);
        bn_priv = BN_bin2bn(&priv[0], priv.size(), nullptr);
        ret_openssl = DSA_set0_key(dsa, bn_pub, bn_priv);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        pkey = EVP_PKEY_new();
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DSA(pkey, dsa);
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
            if (dsa) {
                DSA_free(dsa);
            }
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_dsa_b64(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                                      const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub || nullptr == p || nullptr == q || nullptr == g) {
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
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dsa_b64u(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                                       const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub || nullptr == p || nullptr == q || nullptr == g) {
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
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dsa_b16(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                                      const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub || nullptr == p || nullptr == q || nullptr == g) {
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
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* pub, const char* priv, const char* p, const char* q, const char* g,
                                         const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub || nullptr == p || nullptr == q || nullptr == g) {
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
        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;

        os2b(pub, bin_pub);
        os2b(priv, bin_priv);
        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);

        ret = add_dsa(cryptokey, nid, bin_pub, bin_priv, bin_p, bin_q, bin_g, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
