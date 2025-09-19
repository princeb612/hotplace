/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, size_t bits, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pkey_context = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (bits < 2048) {
            bits = 2048;
        }

        pkey_context = EVP_PKEY_CTX_new_id(nid, nullptr);
        if (nullptr == pkey_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_keygen_init(pkey_context);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        // ret_openssl = EVP_PKEY_CTX_ctrl(pkey_context, nid, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, nullptr);
        ret_openssl = EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_context, bits);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_keygen(pkey_context, &pkey);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);

        ret = cryptokey->add(key);
    }
    __finally2 {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free(pkey_context);  // EVP_PKEY_free here !
        }
    }
    return ret;
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, size_t bits, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, bits, kd);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    RSA* rsa = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == n.size() || 0 == e.size()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        rsa = RSA_new();
        if (nullptr == rsa) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIGNUM* bn_n = nullptr;
        BIGNUM* bn_e = nullptr;
        BIGNUM* bn_d = nullptr;

        bn_n = BN_bin2bn(&n[0], n.size(), nullptr);
        bn_e = BN_bin2bn(&e[0], e.size(), nullptr);
        if (0 != d.size()) {
            bn_d = BN_bin2bn(&d[0], d.size(), nullptr);
        }

        RSA_set0_key(rsa, bn_n, bn_e, bn_d);

        pkey = EVP_PKEY_new();

        ret_openssl = EVP_PKEY_set_type(pkey, nid);  // NID_rsaEncryption, NID_rsa, NID_rsassaPss
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_assign_RSA(pkey, rsa);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        // RSA_solve (rsa);

        crypto_key_object key(pkey, desc);
        ret = cryptokey->add(key);
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

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, n, e, d, kd);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p,
                                  const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    RSA* rsa = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == n.size() || 0 == e.size()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        rsa = RSA_new();
        if (nullptr == rsa) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIGNUM* bn_n = nullptr;
        BIGNUM* bn_e = nullptr;
        BIGNUM* bn_d = nullptr;
        BIGNUM* bn_p = nullptr;
        BIGNUM* bn_q = nullptr;
        BIGNUM* bn_dmp1 = nullptr;
        BIGNUM* bn_dmq1 = nullptr;
        BIGNUM* bn_iqmp = nullptr;

        bn_n = BN_bin2bn(&n[0], n.size(), nullptr);
        bn_e = BN_bin2bn(&e[0], e.size(), nullptr);
        if (0 != d.size()) {
            bn_d = BN_bin2bn(&d[0], d.size(), nullptr);
        }

        if (0 != p.size()) {
            bn_p = BN_bin2bn(&p[0], p.size(), nullptr);
        }
        if (0 != q.size()) {
            bn_q = BN_bin2bn(&q[0], q.size(), nullptr);
        }
        if (0 != dp.size()) {
            bn_dmp1 = BN_bin2bn(&dp[0], dp.size(), nullptr);
        }
        if (0 != dq.size()) {
            bn_dmq1 = BN_bin2bn(&dq[0], dq.size(), nullptr);
        }
        if (0 != qi.size()) {
            bn_iqmp = BN_bin2bn(&qi[0], qi.size(), nullptr);
        }

        RSA_set0_key(rsa, bn_n, bn_e, bn_d);
        RSA_set0_factors(rsa, bn_p, bn_q);
        RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp);

        pkey = EVP_PKEY_new();

        ret_openssl = EVP_PKEY_set_type(pkey, nid);  // NID_rsaEncryption, NID_rsa, NID_rsassaPss
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_assign_RSA(pkey, rsa);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        /* verify */
        ret_openssl = RSA_check_key(rsa);
        if (ret_openssl <= 0) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace_openssl(ret);
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
    }
    return ret;
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p,
                                  const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, n, e, d, p, q, dp, dq, qi, kd);
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc) {
    return add_rsa_b64(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, desc);
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q,
                                      const char* dp, const char* dq, const char* qi, const keydesc& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_dp;
        binary_t bin_dq;
        binary_t bin_qi;

        if (p && q && dp && dq && qi) {
            os2b(p, bin_p);
            os2b(q, bin_q);
            os2b(dp, bin_dp);
            os2b(dq, bin_dq);
            os2b(qi, bin_qi);
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, bin_p, bin_q, bin_dp, bin_dq, bin_qi, desc);
        } else {
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, desc);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc) {
    return add_rsa_b64u(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, desc);
}

return_t crypto_keychain::add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q,
                                       const char* dp, const char* dq, const char* qi, const keydesc& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base64_decode(input, strlen(input), encoding_t::encoding_base64url));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_dp;
        binary_t bin_dq;
        binary_t bin_qi;

        if (p && q && dp && dq && qi) {
            os2b(p, bin_p);
            os2b(q, bin_q);
            os2b(dp, bin_dp);
            os2b(dq, bin_dq);
            os2b(qi, bin_qi);
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, bin_p, bin_q, bin_dp, bin_dq, bin_qi, desc);
        } else {
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, desc);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc) {
    return add_rsa_b16(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, desc);
}

return_t crypto_keychain::add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q,
                                      const char* dp, const char* dq, const char* qi, const keydesc& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode(input, strlen(input)));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_dp;
        binary_t bin_dq;
        binary_t bin_qi;

        if (p && q && dp && dq && qi) {
            os2b(p, bin_p);
            os2b(q, bin_q);
            os2b(dp, bin_dp);
            os2b(dq, bin_dq);
            os2b(qi, bin_qi);
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, bin_p, bin_q, bin_dp, bin_dq, bin_qi, desc);
        } else {
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, desc);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keychain::add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc) {
    return add_rsa_b16rfc(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, desc);
}

return_t crypto_keychain::add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q,
                                         const char* dp, const char* dq, const char* qi, const keydesc& desc) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = std::move(base16_decode_rfc(std::string(input)));
            }
        };

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        os2b(n, bin_n);
        os2b(e, bin_e);
        os2b(d, bin_d);

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_dp;
        binary_t bin_dq;
        binary_t bin_qi;

        if (p && q && dp && dq && qi) {
            os2b(p, bin_p);
            os2b(q, bin_q);
            os2b(dp, bin_dp);
            os2b(dq, bin_dq);
            os2b(qi, bin_qi);
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, bin_p, bin_q, bin_dp, bin_dq, bin_qi, desc);
        } else {
            ret = add_rsa(cryptokey, nid, bin_n, bin_e, bin_d, desc);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
