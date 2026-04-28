/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keychain_rsa.cpp
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
    int ret_openssl = 1;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (bits < 2048) {
            bits = 2048;
        }

        EVP_PKEY_CTX_ptr pkey_context(EVP_PKEY_CTX_new_id(nid, nullptr));
        if (nullptr == pkey_context.get()) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_keygen_init(pkey_context.get());
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_context.get(), bits);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        EVP_PKEY* pk = nullptr;
        ret_openssl = EVP_PKEY_keygen(pkey_context.get(), &pk);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        EVP_PKEY_ptr pkey(pk);

        crypto_key_object key(pkey.get(), desc);

        ret = cryptokey->add(key);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pkey.release();  // cryptokey own pkey

        // free pkey_context
    }
    __finally2 {}
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

        RSA_ptr rsa(RSA_new());
        if (nullptr == rsa.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BN_ptr bn_n(BN_bin2bn(n.data(), n.size(), nullptr));
        BN_ptr bn_e(BN_bin2bn(e.data(), e.size(), nullptr));
        BN_ptr bn_d;
        if (0 != d.size()) {
            bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), d.size(), nullptr)));
        }

        RSA_set0_key(rsa.get(), bn_n.get(), bn_e.get(), bn_d.get());
        bn_n.release();  // rsa own bn_n
        bn_e.release();  // rsa own bn_e
        bn_d.release();  // rsa own bn_d

        EVP_PKEY_ptr pkey(EVP_PKEY_new());
        ret_openssl = EVP_PKEY_set_type(pkey.get(), nid);  // NID_rsaEncryption, NID_rsa, NID_rsassaPss
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_assign_RSA(pkey.get(), rsa.get());
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }
        rsa.release();  // pkey own rsa

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

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, n, e, d, kd);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                                  const binary_t& dp, const binary_t& dq, const binary_t& qi, const keydesc& desc) {
    return_t ret = errorcode_t::success;
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

        RSA_ptr rsa(RSA_new());
        if (nullptr == rsa.get()) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BN_ptr bn_n(BN_bin2bn(n.data(), n.size(), nullptr));
        BN_ptr bn_e(BN_bin2bn(e.data(), e.size(), nullptr));
        BN_ptr bn_d;
        BN_ptr bn_p;
        BN_ptr bn_q;
        BN_ptr bn_dmp1;
        BN_ptr bn_dmq1;
        BN_ptr bn_iqmp;

        if (0 != d.size()) {
            bn_d = std::move(BN_ptr(BN_bin2bn(d.data(), d.size(), nullptr)));
        }

        if (0 != p.size()) {
            bn_p = std::move(BN_ptr(BN_bin2bn(p.data(), p.size(), nullptr)));
        }
        if (0 != q.size()) {
            bn_q = std::move(BN_ptr(BN_bin2bn(q.data(), q.size(), nullptr)));
        }
        if (0 != dp.size()) {
            bn_dmp1 = std::move(BN_ptr(BN_bin2bn(dp.data(), dp.size(), nullptr)));
        }
        if (0 != dq.size()) {
            bn_dmq1 = std::move(BN_ptr(BN_bin2bn(dq.data(), dq.size(), nullptr)));
        }
        if (0 != qi.size()) {
            bn_iqmp = std::move(BN_ptr(BN_bin2bn(qi.data(), qi.size(), nullptr)));
        }

        RSA_set0_key(rsa.get(), bn_n.get(), bn_e.get(), bn_d.get());
        bn_n.release();  // rsa own bn_n
        bn_e.release();  // rsa own bn_e
        bn_d.release();  // rsa own bn_d
        RSA_set0_factors(rsa.get(), bn_p.get(), bn_q.get());
        bn_p.release();  // rsa own bn_p
        bn_q.release();  // rsa own bn_q
        RSA_set0_crt_params(rsa.get(), bn_dmp1.get(), bn_dmq1.get(), bn_iqmp.get());
        bn_dmp1.release();  // rsa own bn_dmp1
        bn_dmq1.release();  // rsa own bn_dmq1
        bn_iqmp.release();  // rsa own bn_iqmp

        /* verify */
        ret_openssl = RSA_check_key(rsa.get());
        if (ret_openssl <= 0) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace_openssl(ret);
        }

        EVP_PKEY_ptr pkey(EVP_PKEY_new());

        ret_openssl = EVP_PKEY_set_type(pkey.get(), nid);  // NID_rsaEncryption, NID_rsa, NID_rsassaPss
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        ret_openssl = EVP_PKEY_assign_RSA(pkey.get(), rsa.get());
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        rsa.release();  // pkey own rsa

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

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, jwa_t alg, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                                  const binary_t& dp, const binary_t& dq, const binary_t& qi, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_rsa(cryptokey, nid_rsa, n, e, d, p, q, dp, dq, qi, kd);
}

return_t crypto_keychain::add_rsa(crypto_key* cryptokey, uint32 nid, encoding_t encoding, const char* n, const char* e, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    switch (encoding) {
        case encoding_t::encoding_base64:
            ret = add_rsa_b64(cryptokey, nid, n, e, d, desc);
            break;
        case encoding_t::encoding_base64url:
            ret = add_rsa_b64u(cryptokey, nid, n, e, d, desc);
            break;
        case encoding_t::encoding_base16:
            ret = add_rsa_b16(cryptokey, nid, n, e, d, desc);
            break;
        case encoding_t::encoding_base16rfc:
            ret = add_rsa_b16rfc(cryptokey, nid, n, e, d, desc);
            break;
    }
    return ret;
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const keydesc& desc) {
    return add_rsa_b64(cryptokey, nid, n, e, d, nullptr, nullptr, nullptr, nullptr, nullptr, desc);
}

return_t crypto_keychain::add_rsa_b64(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                      const char* dq, const char* qi, const keydesc& desc) {
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

        if (p && q && dp && dq && qi) {
            binary_t bin_p;
            binary_t bin_q;
            binary_t bin_dp;
            binary_t bin_dq;
            binary_t bin_qi;

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

return_t crypto_keychain::add_rsa_b64u(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                       const char* dq, const char* qi, const keydesc& desc) {
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

return_t crypto_keychain::add_rsa_b16(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                      const char* dq, const char* qi, const keydesc& desc) {
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

return_t crypto_keychain::add_rsa_b16rfc(crypto_key* cryptokey, uint32 nid, const char* n, const char* e, const char* d, const char* p, const char* q, const char* dp,
                                         const char* dq, const char* qi, const keydesc& desc) {
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
