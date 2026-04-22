/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DSA_ptr dsa(DSA_new());
        if (nullptr == dsa.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = DSA_generate_parameters_ex(dsa.get(), 2048, nullptr, 0, nullptr, nullptr, nullptr);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = DSA_generate_key(dsa.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DSA(pkey.get(), dsa.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        dsa.release();  // pkey own dsa

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dsa(crypto_key* cryptokey, uint32 nid, const binary_t& pub, const binary_t& priv, const binary_t& p, const binary_t& q,
                                  const binary_t& g, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DSA_ptr dsa(DSA_new());
        if (nullptr == dsa.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BN_ptr bn_p(BN_bin2bn(p.data(), p.size(), nullptr));
        BN_ptr bn_q(BN_bin2bn(q.data(), q.size(), nullptr));
        BN_ptr bn_g(BN_bin2bn(g.data(), g.size(), nullptr));
        ret_openssl = DSA_set0_pqg(dsa.get(), bn_p.get(), bn_q.get(), bn_g.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        bn_p.release();  // dsa own bn_p
        bn_q.release();  // dsa own bn_q
        bn_g.release();  // dsa own bn_g

        BN_ptr bn_pub;
        BN_ptr bn_priv;
        if (pub.size()) {
            bn_pub = std::move(BN_ptr(BN_bin2bn(pub.data(), pub.size(), nullptr)));
        }
        if (priv.size()) {
            bn_priv = std::move(BN_ptr(BN_bin2bn(priv.data(), priv.size(), nullptr)));
        }
        ret_openssl = DSA_set0_key(dsa.get(), bn_pub.get(), bn_priv.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        bn_pub.release();   // dsa own bn_pub
        bn_priv.release();  // dsa own bn_priv

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DSA(pkey.get(), dsa.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        dsa.release();  // pkey own dsa

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
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
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
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
    __finally2 {}
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
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
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
    __finally2 {}
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
                output = std::move(base16_decode(input, strlen(input)));
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
    __finally2 {}
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
                output = std::move(base16_decode_rfc(std::string(input)));
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
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
