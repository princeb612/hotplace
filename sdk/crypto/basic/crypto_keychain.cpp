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

crypto_keychain::crypto_keychain() {
    // do nothing
}

crypto_keychain::~crypto_keychain() {
    // do nothing
}

return_t crypto_keychain::load(crypto_key* cryptokey, keyflag_t mode, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        switch (mode) {
            case key_pemfile:
                ret = load_pem(cryptokey, buffer, size, desc, flags);
                break;
            case key_certfile:
                ret = load_cert(cryptokey, buffer, size, desc, flags);
                break;
            case key_derfile:
                ret = load_der(cryptokey, (byte_t*)buffer, size, desc, flags);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::load_pem(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    /**
     * RFC 7468 Textual Encodings of PKIX, PKCS, and CMS Structures
     */
    BIO* bio_pub = nullptr;
    BIO* bio_priv = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bio_pub = BIO_new(BIO_s_mem());
        bio_priv = BIO_new(BIO_s_mem());
        if (nullptr == bio_pub || nullptr == bio_priv) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio_pub, buffer, size);
        BIO_write(bio_priv, buffer, size);

        while (1) {
            EVP_PKEY* pkey_pub = nullptr;
            pkey_pub = PEM_read_bio_PUBKEY(bio_pub, nullptr, nullptr, nullptr);
            if (pkey_pub) {
                crypto_key_object key(pkey_pub, desc);
                cryptokey->add(key);
            } else {
                break;
            }
        }

        while (1) {
            EVP_PKEY* pkey_priv = nullptr;
            pkey_priv = PEM_read_bio_PrivateKey(bio_priv, nullptr, nullptr, nullptr);
            if (pkey_priv) {
                crypto_key_object key(pkey_priv, desc);
                cryptokey->add(key);
            } else {
                break;
            }
        }
        ERR_clear_error();
    }
    __finally2 {
        if (bio_pub) {
            BIO_free_all(bio_pub);
        }
        if (bio_priv) {
            BIO_free_all(bio_priv);
        }
    }
    return ret;
}

return_t crypto_keychain::load_cert(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    X509* cert = nullptr;
    BIO* bio = nullptr;
    EVP_PKEY* pkey = nullptr;
    __try2 {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bio = BIO_new(BIO_s_mem());
        if (nullptr == bio) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio, buffer, size);
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (nullptr == cert) {
            ret = errorcode_t::internal_error;
            __leave2;
        }
        pkey = X509_get_pubkey(cert);
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        crypto_key_object key(pkey, desc);
        cryptokey->add(key);

        ERR_clear_error();
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        if (bio) {
            BIO_free(bio);
        }
        if (cert) {
            X509_free(cert);
        }
    }
    return ret;
}

return_t crypto_keychain::load_der(crypto_key* cryptokey, const byte_t* buffer, size_t size, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    X509* x509 = nullptr;
    BIO* bio = nullptr;
    EVP_PKEY* pkey = nullptr;
    __try2 {
        if (nullptr == cryptokey || nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bio = BIO_new(BIO_s_mem());
        if (nullptr == bio) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        BIO_write(bio, buffer, size);
        const byte_t* p = buffer;
        // The letters i and d in i2d_TYPE() stand for "internal" (that is, an internal C structure) and "DER" respectively.
        // So i2d_TYPE() converts from internal to DER. d2i_ vice versa
        pkey = d2i_PrivateKey_bio(bio, nullptr);
        if (nullptr == pkey) {
            x509 = d2i_X509(nullptr, &p, size);
            pkey = X509_get_pubkey(x509);
        }
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        crypto_key_object key(pkey, desc);
        cryptokey->add(key);

        ERR_clear_error();
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
        if (bio) {
            BIO_free(bio);
        }
        if (x509) {
            X509_free(x509);
        }
    }
    return ret;
}

return_t crypto_keychain::write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        switch (mode) {
            case key_pemfile:
                ret = write_pem(cryptokey, stream, flag);
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::write_pem(crypto_key* cryptokey, stream_t* stream, int flag) {
    return_t ret = errorcode_t::success;
    BIO* out = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear();

        out = BIO_new(BIO_s_mem());
        if (nullptr == out) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        auto lambda = [](crypto_key_object* key, void* param) -> void { dump_pem(key->get_pkey(), (BIO*)param); };

        cryptokey->for_each(lambda, (void*)out);

        binary_t buf;
        buf.resize(64);
        int len = 0;
        while (1) {
            len = BIO_read(out, &buf[0], buf.size());
            if (0 >= len) {
                break;
            }
            stream->write(&buf[0], len);
        }
    }
    __finally2 {
        if (out) {
            BIO_free_all(out);
        }
    }
    return ret;
}

return_t crypto_keychain::load_file(crypto_key* cryptokey, keyflag_t mode, const char* filename, const keydesc& desc, int flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == filename) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(filename);
        if (errorcode_t::success == ret) {
            fs.begin_mmap();
            ret = load(cryptokey, mode, (char*)fs.data(), fs.size(), desc, flags);
            fs.close();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::write_file(crypto_key* cryptokey, keyflag_t mode, const char* filename, int flag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == filename) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        basic_stream bs;
        ret = write(cryptokey, mode, &bs, flag);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        std::ofstream file(filename, std::ios::trunc);
        file.write(bs.c_str(), bs.size());
        file.close();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

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
                output = base64_decode(input, strlen(input), base64_encoding_t::base64_encoding);
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
    __finally2 {
        // do nothing
    }
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
                output = base64_decode(input, strlen(input), base64_encoding_t::base64url_encoding);
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
    __finally2 {
        // do nothing
    }
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
                output = base16_decode(input, strlen(input));
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
    __finally2 {
        // do nothing
    }
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
                output = base16_decode_rfc(std::string(input));
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
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, const keydesc& desc) {
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

        int type = 0;  // EVP_PKEY_CTX_new_id type
        switch (nid) {
            case NID_X25519:
            case NID_ED25519:
            case NID_X448:
            case NID_ED448:
                type = nid;
                break;
            case NID_X9_62_prime256v1:
            case NID_secp256k1:
            case NID_secp384r1:
            case NID_secp521r1:
            // other curves ...
            default:
                type = EVP_PKEY_EC;
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
                ret = errorcode_t::not_supported;
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
            // OKP
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

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;

    switch (nid) {
        case NID_X25519:
        case NID_X448:
        case NID_ED25519:
        case NID_ED448:
            ret = add_okp(cryptokey, nid, x, d, desc);
            break;
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
        // other curves
        default:
            ret = add_ec2(cryptokey, nid, x, y, d, desc);
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, uint32 nid, jwa_t alg, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_ec(cryptokey, nid, x, y, d, desc);
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* curve, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == cryptokey || nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec(cryptokey, nid, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec(crypto_key* cryptokey, const char* curve, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == cryptokey || nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, const keydesc& desc) {
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

        crypto_key_object key(pkey, desc);
        ret = cryptokey->add(key);
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

return_t crypto_keychain::add_ec2(crypto_key* cryptokey, uint32 nid, const binary_t& x, bool ysign, const binary_t& d, const keydesc& desc) {
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
            ret_openssl = EC_POINT_set_compressed_coordinates(group, point, bn_x, ysign, nullptr);  // EC_POINT_set_compressed_coordinates_GFp
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

        crypto_key_object key(pkey, desc);
        ret = cryptokey->add(key);
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

return_t crypto_keychain::add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, const keydesc& desc) {
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

        crypto_key_object key(pkey, desc);
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

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64_encoding);
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64url_encoding);
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode(input, strlen(input));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode_rfc(std::string(input));
            }
        };

        binary_t bin_x;
        binary_t bin_y;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(y, bin_y);
        os2b(d, bin_d);

        ret = add_ec(cryptokey, nid, bin_x, bin_y, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64_encoding);
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64url_encoding);
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode(input, strlen(input));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, uint32 nid, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode_rfc(std::string(input));
            }
        };

        binary_t bin_x;
        binary_t bin_d;

        os2b(x, bin_x);
        os2b(d, bin_d);

        ret = add_ec2(cryptokey, nid, bin_x, ysign, bin_d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64u(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b16(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, const char* y, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b16rfc(cryptokey, nid, x, y, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b64u(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b64u(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b16(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_ec_b16rfc(crypto_key* cryptokey, const char* curve, const char* x, bool ysign, const char* d, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == curve || nullptr == x) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        crypto_advisor* advisor = crypto_advisor::get_instance();
        ret = advisor->nidof_ec_curve(curve, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = add_ec_b16rfc(cryptokey, nid, x, ysign, d, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_oct(crypto_key* cryptokey, size_t size, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        openssl_prng r;
        binary_t temp;
        r.random(temp, size);
        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, &temp[0], size);
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);
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

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const binary_t& k, const keydesc& desc) { return add_oct(cryptokey, &k[0], k.size(), desc); }

return_t crypto_keychain::add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, k, size);
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl(ret);
        }

        crypto_key_object key(pkey, desc);
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

return_t crypto_keychain::add_oct(crypto_key* cryptokey, jwa_t alg, const binary_t& k, const keydesc& desc) {
    crypto_advisor* advisor = crypto_advisor::get_instance();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm(alg);
    keydesc kd(desc);
    if (hint) {
        kd.set_alg(nameof_alg(hint));
    }
    return add_oct(cryptokey, k, kd);
}

return_t crypto_keychain::add_oct_b64(crypto_key* cryptokey, const char* k, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64_encoding);
            }
        };

        binary_t bin_k;

        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_oct_b64u(crypto_key* cryptokey, const char* k, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base64_decode(input, strlen(input), base64_encoding_t::base64url_encoding);
            }
        };

        binary_t bin_k;

        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_oct_b16(crypto_key* cryptokey, const char* k, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode(input, strlen(input));
            }
        };

        binary_t bin_k;
        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_keychain::add_oct_b16rfc(crypto_key* cryptokey, const char* k, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == cryptokey || nullptr == k) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto os2b = [](const char* input, binary_t& output) -> void {
            if (input) {
                output = base16_decode_rfc(std::string(input));
            }
        };

        binary_t bin_k;
        os2b(k, bin_k);

        ret = add_oct(cryptokey, bin_k, desc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

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
