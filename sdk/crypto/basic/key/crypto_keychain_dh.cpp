/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_dh.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
 *
 *   y = g^x mod p
 *     p : prime
 *     g : generator
 *     x : privateate key
 *     y : public key
 */

#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr));
        ret_openssl = EVP_PKEY_paramgen_init(ctx.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_CTX_set_dh_nid(ctx.get(), nid);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY* p = nullptr;
        ret_openssl = EVP_PKEY_paramgen(ctx.get(), &p);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        EVP_PKEY_ptr params(p);

        EVP_PKEY_CTX_ptr keyctx(EVP_PKEY_CTX_new(params.get(), nullptr));
        if (nullptr == keyctx) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_keygen_init(keyctx.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        EVP_PKEY* pk = nullptr;
        ret_openssl = EVP_PKEY_keygen(keyctx.get(), &pk);
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        if (nullptr == pk) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        EVP_PKEY_ptr pkey(pk);

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pkey.release();  // cryptokey own pkey

        // free keyctx
        // free params
        // free ctx
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& y, const binary_t& x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;
    __try2 {
        if (nullptr == cryptokey || y.empty()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DH_ptr dh(DH_new_by_nid(nid));
        if (nullptr == dh) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BN_ptr bn_x;
        BN_ptr bn_y(BN_bin2bn(y.data(), y.size(), nullptr));
        if (x.size()) {
            bn_x = std::move(BN_ptr(BN_bin2bn(x.data(), x.size(), nullptr)));
        }

        ret_openssl = DH_set0_key(dh.get(), bn_y.get(), bn_x.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        bn_x.release();  // dh own bn_x
        bn_y.release();  // dh own bn_y

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DH(pkey.get(), dh.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        dh.release();  // pkey own dh

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

return_t crypto_keychain::add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& p, const binary_t& q, const binary_t& g, const binary_t& x,
                                 const keydesc& desc) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 0;
    __try2 {
        if (nullptr == cryptokey || p.empty() || g.empty() || (q.empty() && x.empty())) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        DH_ptr dh(DH_new_by_nid(nid));
        if (nullptr == dh) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BN_ptr bn_p(BN_bin2bn(p.data(), p.size(), nullptr));
        BN_ptr bn_q;
        if (false == q.empty()) {
            bn_q = std::move(BN_ptr(BN_bin2bn(q.data(), q.size(), nullptr)));
        }
        BN_ptr bn_g(BN_bin2bn(g.data(), g.size(), nullptr));
        BN_ptr bn_x;
        if (x.empty()) {
            bn_x = std::move(BN_ptr(BN_new()));
            // x ∈ [2, q-1]
            BN_rand_range(bn_x.get(), bn_q.get());
            // ensure x >= 2
            if (BN_cmp(bn_x.get(), BN_value_one()) <= 0) {
                BN_add_word(bn_x.get(), 2);
            }
        } else {
            bn_x = std::move(BN_ptr(BN_bin2bn(x.data(), x.size(), nullptr)));  // y = g^x mod p
        }

        BN_ptr bn_y(BN_new());
        BN_CTX_ptr bn_ctx(BN_CTX_new());

        // y = g^x mod p
        ret_openssl = BN_mod_exp(bn_y.get(), bn_g.get(), bn_x.get(), bn_p.get(), bn_ctx.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        // public key (y) verification
        {
            // 1 < y < p-1
            if (BN_cmp(bn_y.get(), BN_value_one()) <= 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            if (BN_cmp(bn_y.get(), bn_p.get()) >= 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            // y^q mod p == 1
            BN_ptr bn_tmp(BN_new());
            BN_mod_exp(bn_tmp.get(), bn_y.get(), bn_q.get(), bn_p.get(), bn_ctx.get());
            if (false == BN_is_one(bn_tmp.get())) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
        }

        ret_openssl = DH_set0_pqg(dh.get(), bn_p.get(), bn_q.get(), bn_g.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        bn_p.release();  // dh own bn_p
        bn_q.release();  // dh own bn_q
        bn_g.release();  // dh own bn_g

        ret_openssl = DH_set0_key(dh.get(), bn_y.get(), bn_x.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        bn_y.release();  // dh own bn_y
        bn_x.release();  // dh own bn_x

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        if (nullptr == pkey.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        ret_openssl = EVP_PKEY_assign_DH(pkey.get(), dh.get());
        if (ret_openssl < 0) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        dh.release();  // pkey own dh

        crypto_key_object key(pkey.get(), desc);
        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pkey.release();  // cryptokey own pkey
    }
    __finally2 {}
    return ret;
    // free bn_ctx
}

return_t crypto_keychain::add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16rfc(crypto_key* cryptokey, uint32 nid, const char* y, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == y) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_y;
        binary_t bin_x;

        os2b(y, bin_y);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_y, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b64(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b64u(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_dh_b16rfc(crypto_key* cryptokey, uint32 nid, const char* p, const char* q, const char* g, const char* x, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == p || nullptr == g || (nullptr == q && nullptr == x)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_g;
        binary_t bin_x;

        os2b(p, bin_p);
        os2b(q, bin_q);
        os2b(g, bin_g);
        os2b(x, bin_x);

        ret = add_dh(cryptokey, nid, bin_p, bin_q, bin_g, bin_x, desc);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
