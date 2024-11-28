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
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/crypto/basic/openssl_sdk.hpp>

namespace hotplace {
namespace crypto {

crypto_keychain::crypto_keychain() {
    // do nothing
}

crypto_keychain::~crypto_keychain() {
    // do nothing
}

return_t crypto_keychain::load(crypto_key* crypto_key, const char* buffer, int flags) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t crypto_keychain::write(crypto_key* crypto_key, char* buf, size_t* buflen, int flags) {
    return_t ret = errorcode_t::success;

    return ret;
}

return_t crypto_keychain::load_file(crypto_key* crypto_key, const char* file, int flags) { return errorcode_t::success; }

return_t crypto_keychain::load_pem(crypto_key* cryptokey, const char* buffer, int flags, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = cryptokey->load_pem(buffer, flags, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::load_pem_file(crypto_key* cryptokey, const char* file, int flags, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = cryptokey->load_pem_file(file, flags, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::write_file(crypto_key* cryptokey, const char* file, int flags) { return errorcode_t::success; }

return_t crypto_keychain::write_pem(crypto_key* cryptokey, stream_t* stream, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = cryptokey->write_pem(stream, flags);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::write_pem_file(crypto_key* cryptokey, const char* file, int flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = cryptokey->write_pem_file(file, flags);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, size_t bits, crypto_use_t use) {
    return add_rsa(cryptokey, NID_rsaEncryption, nullptr, nullptr, bits, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, int nid, size_t bits, crypto_use_t use) {
    return add_rsa(cryptokey, nid, nullptr, nullptr, bits, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, size_t bits, crypto_use_t use) {
    return add_rsa(cryptokey, NID_rsaEncryption, kid, nullptr, bits, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, int nid, const char* kid, size_t bits, crypto_use_t use) {
    return add_rsa(cryptokey, nid, kid, nullptr, bits, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, size_t bits, crypto_use_t use) {
    return add_rsa(cryptokey, NID_rsaEncryption, kid, alg, bits, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, size_t bits, crypto_use_t use) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pkey_context = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
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

        crypto_key_object key(pkey, use, kid, alg);

        ret = cryptokey->add(key);
    }
    __finally2 {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free(pkey_context);  // EVP_PKEY_free here !
        }
    }
    return ret;
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, size_t bits, crypto_use_t use) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);

    return add_rsa(cryptokey, kid, hint ? hint->alg_name : nullptr, bits, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d,
                                  crypto_use_t use) {
    return add_rsa(cryptokey, NID_rsaEncryption, kid, alg, n, e, d, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d,
                                  crypto_use_t use) {
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

        crypto_key_object key(pkey, use, kid, alg);
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

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d,
                                  crypto_use_t use) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);

    return add_rsa(cryptokey, kid, hint ? hint->alg_name : nullptr, n, e, d, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d,
                                  const binary_t& p, const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, crypto_use_t use) {
    return add_rsa(cryptokey, NID_rsaEncryption, kid, alg, n, e, d, p, q, dp, dq, qi, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const binary_t& n, const binary_t& e, const binary_t& d,
                                  const binary_t& p, const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, crypto_use_t use) {
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

        crypto_key_object key(pkey, use, kid, alg);

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

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p,
                                  const binary_t& q, const binary_t& dp, const binary_t& dq, const binary_t& qi, crypto_use_t use) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);

    return add_rsa(cryptokey, kid, hint ? hint->alg_name : nullptr, n, e, d, p, q, dp, dq, qi, use);
}

return_t crypto_keychain::add_rsa_b64u(crypto_key* cryptokey, const char* kid, const char* alg, const char* n_value, const char* e_value, const char* d_value,
                                       const char* p_value, const char* q_value, const char* dp_value, const char* dq_value, const char* qi_value,
                                       crypto_use_t use) {
    return add_rsa_b64u(cryptokey, NID_rsaEncryption, kid, alg, n_value, e_value, d_value, p_value, q_value, dp_value, dq_value, qi_value, use);
}

return_t crypto_keychain::add_rsa_b64u(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const char* n_value, const char* e_value,
                                       const char* d_value, const char* p_value, const char* q_value, const char* dp_value, const char* dq_value,
                                       const char* qi_value, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n_value || nullptr == e_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        bin_n = base64_decode(n_value, strlen(n_value), base64_encoding_t::base64url_encoding);
        bin_e = base64_decode(e_value, strlen(e_value), base64_encoding_t::base64url_encoding);
        if (nullptr != d_value) {
            bin_d = base64_decode(d_value, strlen(d_value), base64_encoding_t::base64url_encoding);
        }

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_dp;
        binary_t bin_dq;
        binary_t bin_qi;

        if (p_value && q_value && dp_value && dq_value && qi_value) {
            bin_p = base64_decode(p_value, strlen(p_value), base64_encoding_t::base64url_encoding);
            bin_q = base64_decode(q_value, strlen(q_value), base64_encoding_t::base64url_encoding);
            bin_dp = base64_decode(dp_value, strlen(dp_value), base64_encoding_t::base64url_encoding);
            bin_dq = base64_decode(dq_value, strlen(dq_value), base64_encoding_t::base64url_encoding);
            bin_qi = base64_decode(qi_value, strlen(qi_value), base64_encoding_t::base64url_encoding);
            ret = add_rsa(cryptokey, nid, kid, alg, bin_n, bin_e, bin_d, bin_p, bin_q, bin_dp, bin_dq, bin_qi, use);
        } else {
            ret = add_rsa(cryptokey, nid, kid, alg, bin_n, bin_e, bin_d, use);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, const char* kid, const char* alg, const char* n_value, const char* e_value, const char* d_value,
                                      const char* p_value, const char* q_value, const char* dp_value, const char* dq_value, const char* qi_value,
                                      crypto_use_t use) {
    return add_rsa_b64(cryptokey, NID_rsaEncryption, kid, alg, n_value, e_value, d_value, p_value, q_value, dp_value, dq_value, qi_value, use);
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const char* n_value, const char* e_value,
                                      const char* d_value, const char* p_value, const char* q_value, const char* dp_value, const char* dq_value,
                                      const char* qi_value, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n_value || nullptr == e_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_n;
        binary_t bin_e;
        binary_t bin_d;

        bin_n = base64_decode(n_value, strlen(n_value), base64_encoding_t::base64_encoding);
        bin_e = base64_decode(e_value, strlen(e_value), base64_encoding_t::base64_encoding);
        if (nullptr != d_value) {
            bin_d = base64_decode(d_value, strlen(d_value), base64_encoding_t::base64_encoding);
        }

        binary_t bin_p;
        binary_t bin_q;
        binary_t bin_dp;
        binary_t bin_dq;
        binary_t bin_qi;

        if (p_value && q_value && dp_value && dq_value && qi_value) {
            bin_p = base64_decode(p_value, strlen(p_value), base64_encoding_t::base64_encoding);
            bin_q = base64_decode(q_value, strlen(q_value), base64_encoding_t::base64_encoding);
            bin_dp = base64_decode(dp_value, strlen(dp_value), base64_encoding_t::base64_encoding);
            bin_dq = base64_decode(dq_value, strlen(dq_value), base64_encoding_t::base64_encoding);
            bin_qi = base64_decode(qi_value, strlen(qi_value), base64_encoding_t::base64_encoding);
            add_rsa(cryptokey, nid, kid, alg, bin_n, bin_e, bin_d, bin_p, bin_q, bin_dp, bin_dq, bin_qi, use);
        } else {
            add_rsa(cryptokey, nid, kid, alg, bin_n, bin_e, bin_d, use);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_rsa_b16(crypto_key* cryptokey, const char* kid, const char* alg, const char* n, const char* e, const char* d, crypto_use_t use) {
    return add_rsa(cryptokey, NID_rsaEncryption, kid, alg, base16_decode(n), base16_decode(e), base16_decode(d), use);
}

return_t crypto_keychain::add_rsa_b16(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const char* n, const char* e, const char* d,
                                      crypto_use_t use) {
    return add_rsa(cryptokey, nid, kid, alg, base16_decode(n), base16_decode(e), base16_decode(d), use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, const char* kid, const char* alg, const byte_t* n, size_t size_n, const byte_t* e, size_t size_e,
                                  const byte_t* d, size_t size_d, crypto_use_t use) {
    return add_rsa(cryptokey, NID_rsaEncryption, kid, alg, n, size_n, e, size_e, d, size_d, use);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, int nid, const char* kid, const char* alg, const byte_t* n, size_t size_n, const byte_t* e,
                                  size_t size_e, const byte_t* d, size_t size_d, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == cryptokey || nullptr == n || nullptr == e) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = add_rsa(cryptokey, nid, kid, alg, binary(n, size_n), binary(e, size_e), binary(d, size_d), use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, int nid, crypto_use_t use) { return add_ec(cryptokey, nullptr, nullptr, nid, use); }

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* kid, int nid, crypto_use_t use) { return add_ec(cryptokey, kid, nullptr, nid, use); }

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, crypto_use_t use) {
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

        int type = 0;
        switch (nid) {
            case NID_X9_62_prime256v1:
            case NID_secp256k1:
            case NID_secp384r1:
            case NID_secp521r1:
                type = EVP_PKEY_EC;
                break;
            case NID_X25519:
            case NID_ED25519:
                /*
                 *  # define EVP_PKEY_X25519 NID_X25519
                 *  # define EVP_PKEY_ED25519 NID_ED25519
                 */
                type = nid;
                break;
            case NID_X448:
            case NID_ED448:
                /*
                 *  # define EVP_PKEY_X448 NID_X448
                 *  # define EVP_PKEY_ED448 NID_ED448
                 */
                type = nid;
                break;
            default:
                type = nid;
                break;
        }

        ctx = EVP_PKEY_CTX_new_id(type, nullptr);
        if (EVP_PKEY_EC == type) {
            ret_openssl = EVP_PKEY_paramgen_init(ctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            ret_openssl = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
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
            if (nullptr == pkey) { /* [openssl 3.0.3] return success but pkey is nullptr */
                ret = errorcode_t::internal_error;
                __leave2;
            }
            // set ASN.1 OPENSSL_EC_NAMED_CURVE flag for PEM export (PEM_write_bio_PUBKEY, PEM_write_bio_PrivateKey)
            EC_KEY_set_asn1_flag((EC_KEY*)EVP_PKEY_get0_EC_KEY(pkey), OPENSSL_EC_NAMED_CURVE);  // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        } else {
            ret_openssl = EVP_PKEY_keygen_init(ctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
            ret_openssl = EVP_PKEY_keygen(ctx, &pkey);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
        }

        if (pkey) {
            crypto_key_object key(pkey, use, kid, alg);
            ret = cryptokey->add(key);
        }
    }
    __finally2 {
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

return_t crypto_keychain::add_ec(crypto_key* cryptokey, int nid, const binary_t& x, const binary_t& y, const binary_t& d, crypto_use_t use) {
    return add_ec(cryptokey, nullptr, nullptr, nid, x, y, d, use);
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* kid, int nid, const binary_t& x, const binary_t& y, const binary_t& d, crypto_use_t use) {
    return add_ec(cryptokey, kid, nullptr, nid, x, y, d, use);
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, const binary_t& y, const binary_t& d,
                                 crypto_use_t use) {
    return_t ret = errorcode_t::success;

    switch (nid) {
        case NID_X25519:
        case NID_X448:
        case NID_ED25519:
        case NID_ED448:
            ret = add_ec_nid_OKP(cryptokey, kid, alg, nid, x, d, use);
            break;
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
        default:
            ret = add_ec_nid_EC(cryptokey, kid, alg, nid, x, y, d, use);
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, uint8 ybit, const binary_t& d,
                                 crypto_use_t use) {
    return_t ret = errorcode_t::success;

    switch (nid) {
        case NID_X25519:
        case NID_X448:
        case NID_ED25519:
        case NID_ED448:
            ret = add_ec_nid_OKP(cryptokey, kid, alg, nid, x, d, use);
            break;
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
        default:
            ret = add_ec_nid_EC(cryptokey, kid, alg, nid, x, ybit, d, use);
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* kid, int nid, const binary_t& x, uint8 ybit, const binary_t& d, crypto_use_t use) {
    return add_ec(cryptokey, kid, nullptr, nid, x, ybit, d, use);
}

return_t crypto_keychain::add_ec_nid_EC(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, const binary_t& y,
                                        const binary_t& d, crypto_use_t use) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EC_KEY* ec = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_y = nullptr;
    BIGNUM* bn_d = nullptr;
    EC_POINT* pub = nullptr;
    EC_POINT* point = nullptr;
    BN_CTX* cfg = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint16 useflag = use;
        switch (nid) {
            case NID_X25519:
            case NID_X448:
                useflag &= ~crypto_use_t::use_sig;
                break;
            case NID_ED25519:
            case NID_ED448:
                useflag &= ~crypto_use_t::use_enc;
                break;
            default:
                break;
        }

        bn_x = BN_bin2bn(&x[0], x.size(), nullptr);
        bn_y = BN_bin2bn(&y[0], y.size(), nullptr);
        if (d.size() > 0) {
            bn_d = BN_bin2bn(&d[0], d.size(), nullptr);
        }

        if (nullptr == bn_x && nullptr == bn_y) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        ec = EC_KEY_new_by_curve_name(nid);
        if (nullptr == ec) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        const EC_GROUP* group = EC_KEY_get0_group(ec);
        point = EC_POINT_new(group);
        if (nullptr == point) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        if (nullptr != bn_d) {
            ret_openssl = EC_KEY_set_private_key(ec, bn_d);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }

            ret_openssl = EC_POINT_mul(group, point, bn_d, nullptr, nullptr, nullptr);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        } else {
            ret_openssl = EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, nullptr);  // EC_POINT_set_affine_coordinates_GFp
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_openssl = EC_KEY_set_public_key(ec, point);
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        pkey = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pkey, ec);  // EC_KEY_up_ref
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, (crypto_use_t)useflag, kid, alg);
        switch (nid) {
            case NID_X9_62_prime256v1:
                break;
            case NID_secp384r1:
                break;
            case NID_secp521r1:
                break;
        }

        cryptokey->add(key);
    }
    __finally2 {
        if (ec) {
            EC_KEY_free(ec);
        }
        if (bn_x) {
            BN_clear_free(bn_x);
        }
        if (bn_y) {
            BN_clear_free(bn_y);
        }
        if (bn_d) {
            BN_clear_free(bn_d);
        }
        if (pub) {
            EC_POINT_free(pub);
        }
        if (point) {
            EC_POINT_free(point);
        }
        if (cfg) {
            BN_CTX_free(cfg);
        }

        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec_nid_EC(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, uint8 ybit, const binary_t& d,
                                        crypto_use_t use) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EC_KEY* ec = nullptr;
    BIGNUM* bn_x = nullptr;
    BIGNUM* bn_d = nullptr;
    EC_POINT* pub = nullptr;
    EC_POINT* point = nullptr;
    BN_CTX* cfg = nullptr;
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bn_x = BN_bin2bn(&x[0], x.size(), nullptr);
        if (d.size() > 0) {
            bn_d = BN_bin2bn(&d[0], d.size(), nullptr);
        }

        if (nullptr == bn_x) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        ec = EC_KEY_new_by_curve_name(nid);
        if (nullptr == ec) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        const EC_GROUP* group = EC_KEY_get0_group(ec);
        point = EC_POINT_new(group);
        if (nullptr == point) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        if (nullptr != bn_d) {
            ret_openssl = EC_KEY_set_private_key(ec, bn_d);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }

            ret_openssl = EC_POINT_mul(group, point, bn_d, nullptr, nullptr, nullptr);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        } else {
            // RFC8152 13.1.1.  Double Coordinate Curves
            // Compute the sign bit as laid out in the Elliptic-Curve-Point-to-Octet-String Conversion function of [SEC1]
            // If the sign bit is zero, then encode y as a CBOR false value; otherwise, encode y as a CBOR true value.
            ret_openssl = EC_POINT_set_compressed_coordinates(group, point, bn_x, ybit, nullptr);  // EC_POINT_set_compressed_coordinates_GFp
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl(ret);
            }
        }

        ret_openssl = EC_KEY_set_public_key(ec, point);
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        pkey = EVP_PKEY_new();
        EVP_PKEY_set1_EC_KEY(pkey, ec);  // EC_KEY_up_ref
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, use, kid, alg);
        switch (nid) {
            case NID_X9_62_prime256v1:
                break;
            case NID_secp384r1:
                break;
            case NID_secp521r1:
                break;
        }

        cryptokey->add(key);
    }
    __finally2 {
        if (ec) {
            EC_KEY_free(ec);
        }
        if (bn_x) {
            BN_clear_free(bn_x);
        }
        if (bn_d) {
            BN_clear_free(bn_d);
        }
        if (pub) {
            EC_POINT_free(pub);
        }
        if (point) {
            EC_POINT_free(point);
        }
        if (cfg) {
            BN_CTX_free(cfg);
        }

        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec_nid_OKP(crypto_key* cryptokey, const char* kid, const char* alg, int nid, const binary_t& x, const binary_t& d,
                                         crypto_use_t use) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (d.size()) {
            pkey = EVP_PKEY_new_raw_private_key(nid, nullptr, &d[0], d.size());
        } else if (x.size()) {
            pkey = EVP_PKEY_new_raw_public_key(nid, nullptr, &x[0], x.size());
        }
        if (nullptr == pkey) {
            ret = errorcode_t::bad_request;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, use, kid, alg);
        cryptokey->add(key);
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

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* kid, jwa_t alg, int nid, const binary_t& x, const binary_t& y, const binary_t& d,
                                 crypto_use_t use) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);

    return add_ec(cryptokey, kid, hint ? hint->alg_name : nullptr, nid, x, y, d, use);
}

return_t crypto_keychain::add_ec_b64u(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                                      crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64u(crypto_key, kid, alg, nid, x, y, d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* crypto_key, const char* kid, const char* alg, int nid, const char* x, const char* y, const char* d,
                                      crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;
        bin_x = base64_decode(x, strlen(x), base64_encoding_t::base64url_encoding);
        if (y) {
            bin_y = base64_decode(y, strlen(y), base64_encoding_t::base64url_encoding);
        }
        if (d) {
            bin_d = base64_decode(d, strlen(d), base64_encoding_t::base64url_encoding);
        }

        ret = add_ec(crypto_key, kid, alg, nid, bin_x, bin_y, bin_d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, uint8 ybit, const char* d,
                                      crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64u(crypto_key, kid, alg, nid, x, ybit, d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* crypto_key, const char* kid, const char* alg, int nid, const char* x, uint8 ybit, const char* d,
                                      crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        binary_t bin_x;
        binary_t bin_d;
        bin_x = base64_decode(x, strlen(x), base64_encoding_t::base64url_encoding);
        if (d) {
            bin_d = base64_decode(d, strlen(d), base64_encoding_t::base64url_encoding);
        }

        ret = add_ec(crypto_key, kid, alg, nid, bin_x, ybit, bin_d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64(crypto_key, kid, alg, nid, x, y, d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* crypto_key, const char* kid, const char* alg, int nid, const char* x, const char* y, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        bin_x = base64_decode(x, strlen(x), base64_encoding_t::base64_encoding);
        if (y) {
            /* kty EC */
            bin_y = base64_decode(y, strlen(y), base64_encoding_t::base64_encoding);
        }
        if (d) {
            /* private key */
            bin_d = base64_decode(d, strlen(d), base64_encoding_t::base64_encoding);
        }

        ret = add_ec(crypto_key, kid, alg, nid, bin_x, bin_y, bin_d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, uint8 ybit, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64(crypto_key, kid, alg, nid, x, ybit, d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* crypto_key, const char* kid, const char* alg, int nid, const char* x, uint8 ybit, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t bin_x;
        binary_t bin_d;

        bin_x = base64_decode(x, strlen(x), base64_encoding_t::base64_encoding);
        if (d) {
            /* private key */
            bin_d = base64_decode(d, strlen(d), base64_encoding_t::base64_encoding);
        }

        ret = add_ec(crypto_key, kid, alg, nid, bin_x, ybit, bin_d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, const char* y, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = add_ec_b16(crypto_key, kid, alg, nid, x, y, d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* crypto_key, const char* kid, const char* alg, int nid, const char* x, const char* y, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = add_ec(crypto_key, kid, alg, nid, base16_decode(x), base16_decode(y), base16_decode(d), use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const char* x, uint8 ybit, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = add_ec_b16(crypto_key, kid, alg, nid, x, ybit, d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* crypto_key, const char* kid, const char* alg, int nid, const char* x, uint8 ybit, const char* d,
                                     crypto_use_t use) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == crypto_key || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = add_ec(crypto_key, kid, alg, nid, base16_decode(x), ybit, base16_decode(d), use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const byte_t* x, size_t size_x, const byte_t* y,
                                 size_t size_y, const byte_t* d, size_t size_d, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec(crypto_key, kid, alg, nid, binary(x, size_x), binary(y, size_y), binary(d, size_d), use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* crypto_key, const char* kid, const char* alg, const char* curve, const binary_t& x, const binary_t& y,
                                 const binary_t& d, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        add_ec(crypto_key, kid, alg, nid, x, y, d, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, size_t size, crypto_use_t use) { return add_oct(cryptokey, nullptr, nullptr, nullptr, size, use); }

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, size_t size, crypto_use_t use) {
    return add_oct(cryptokey, kid, nullptr, nullptr, size, use);
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, const char* alg, size_t size, crypto_use_t use) {
    return add_oct(cryptokey, kid, alg, nullptr, size, use);
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, jwa_t alg, size_t size, crypto_use_t use) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);

    return add_oct(cryptokey, kid, hint ? hint->alg_name : nullptr, size, use);
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const binary_t& k, crypto_use_t use) { return add_oct(cryptokey, nullptr, nullptr, k, use); }

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, const binary_t& k, crypto_use_t use) {
    return add_oct(cryptokey, kid, nullptr, k, use);
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, const char* alg, const binary_t& k, crypto_use_t use) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, &k[0], k.size());
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, use, kid, alg);

        ret = cryptokey->add(key);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, jwa_t alg, const binary_t& k, crypto_use_t use) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);

    return add_oct(cryptokey, kid, hint ? hint->alg_name : nullptr, k, use);
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, crypto_use_t use) {
    return add_oct(cryptokey, nullptr, nullptr, k, size, use);
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, const byte_t* k, size_t size, crypto_use_t use) {
    return add_oct(cryptokey, kid, nullptr, k, size, use);
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, const char* alg, const byte_t* k, size_t size, crypto_use_t use) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (k) {
            pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, k, size);
        } else {
            openssl_prng r;
            binary_t temp;
            r.random(temp, size);
            pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, &temp[0], size);
        }
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, use, kid, alg);

        ret = cryptokey->add(key);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const char* kid, jwa_t alg, const byte_t* k, size_t size, crypto_use_t use) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);

    return add_oct(cryptokey, kid, hint ? hint->alg_name : nullptr, k, size, use);
}

return_t crypto_keychain::add_oct_b64u(crypto_key* crypto_key, const char* kid, const char* alg, const char* k_value, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == k_value) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t k_decoded = base64_decode(k_value, strlen(k_value), base64_encoding_t::base64url_encoding);

        add_oct(crypto_key, kid, alg, k_decoded, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_oct_b64(crypto_key* crypto_key, const char* kid, const char* alg, const char* k, crypto_use_t use) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == crypto_key || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t k_decoded = base64_decode(k, strlen(k), base64_encoding_t::base64_encoding);

        add_oct(crypto_key, kid, alg, k_decoded, use);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_oct_b16(crypto_key* crypto_key, const char* kid, const char* alg, const char* k, crypto_use_t use) {
    return add_oct(crypto_key, kid, alg, base16_decode(k), use);
}

return_t crypto_keychain::add_dh(crypto_key* cryptokey, int nid, const char* kid) {
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
            crypto_key_object key(pkey, crypto_use_t::use_any, kid);
            ret = cryptokey->add(key);
        }
    }
    __finally2 {
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

return_t crypto_keychain::add_dh(crypto_key* cryptokey, int nid, const char* kid, const binary_t& pub, const binary_t& priv) {
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
            crypto_key_object key(pkey, crypto_use_t::use_any, kid);
            ret = cryptokey->add(key);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dh_b64u(crypto_key* cryptokey, int nid, const char* kid, const char* pub, const char* priv) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t pub_decoded;
        binary_t priv_decoded;
        pub_decoded = base64_decode(pub, strlen(pub), base64_encoding_t::base64url_encoding);
        if (priv) {
            priv_decoded = base64_decode(priv, strlen(priv), base64_encoding_t::base64url_encoding);
        }
        ret = add_dh(cryptokey, nid, kid, pub_decoded, priv_decoded);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dh_b64(crypto_key* cryptokey, int nid, const char* kid, const char* pub, const char* priv) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t pub_decoded;
        binary_t priv_decoded;
        pub_decoded = base64_decode(pub, strlen(pub), base64_encoding_t::base64_encoding);
        if (priv) {
            priv_decoded = base64_decode(priv, strlen(priv), base64_encoding_t::base64_encoding);
        }
        ret = add_dh(cryptokey, nid, kid, pub_decoded, priv_decoded);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_dh_b16(crypto_key* cryptokey, int nid, const char* kid, const char* pub, const char* priv) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == pub) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        binary_t pub_decoded;
        binary_t priv_decoded;
        pub_decoded = base16_decode(pub, strlen(pub));
        if (priv) {
            priv_decoded = base16_decode(priv, strlen(priv));
        }
        ret = add_dh(cryptokey, nid, kid, pub_decoded, priv_decoded);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

const EVP_PKEY* crypto_keychain::choose(crypto_key* key, const std::string& kid, crypto_kty_t kty, return_t& code) {
    const EVP_PKEY* pkey = nullptr;
    code = errorcode_t::not_exist;
    if (key) {
        if (kid.empty()) {
            std::string selected_kid;
            pkey = key->select(selected_kid, kty);
            if (pkey) {
                code = errorcode_t::inaccurate;
            }
        } else {
            pkey = key->find(kid.c_str(), kty);
            if (pkey) {
                code = errorcode_t::success;
            }
        }
    }
    return pkey;
}

}  // namespace crypto
}  // namespace hotplace
