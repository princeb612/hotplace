/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>  // dump_notrunc
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/io/cbor/cbor_data.hpp>
#include <hotplace/sdk/io/cbor/cbor_publisher.hpp>

namespace hotplace {
namespace crypto {

static void pkey_param_printf(crypt_item_t type, const binary_t& key, stream_t* stream, uint8 hex_part, uint8 indent) {
    constexpr char constexpr_hmac[] = "k";

    constexpr char constexpr_rsa_n[] = "modulus (00:n)";
    constexpr char constexpr_rsa_e[] = "public exponent (e)";
    constexpr char constexpr_rsa_d[] = "private exponent (d)";

    constexpr char constexpr_rsa_p[] = "prime1 (00:p)";
    constexpr char constexpr_rsa_q[] = "prime2 (00:q)";
    constexpr char constexpr_rsa_dp[] = "exponent1 (dp)";
    constexpr char constexpr_rsa_dq[] = "exponent2 (00:dq)";
    constexpr char constexpr_rsa_qi[] = "coefficient (qi)";

    constexpr char constexpr_ec_x[] = "x";
    constexpr char constexpr_ec_y[] = "y";
    constexpr char constexpr_ec_pub[] = "public (04:x:y)";
    constexpr char constexpr_ec_d[] = "d (private)";

    constexpr char constexpr_dsa_p[] = "p";
    constexpr char constexpr_dsa_q[] = "q";
    constexpr char constexpr_dsa_g[] = "g";

    constexpr char constexpr_pub[] = "public";
    constexpr char constexpr_priv[] = "private";

    std::map<crypt_item_t, const char*> table;
    t_maphint<crypt_item_t, const char*> hint(table);

    table[crypt_item_t::item_hmac_k] = constexpr_hmac;
    table[crypt_item_t::item_hmac_k] = constexpr_hmac;
    table[crypt_item_t::item_rsa_n] = constexpr_rsa_n;
    table[crypt_item_t::item_rsa_e] = constexpr_rsa_e;
    table[crypt_item_t::item_rsa_d] = constexpr_rsa_d;
    table[crypt_item_t::item_rsa_p] = constexpr_rsa_p;
    table[crypt_item_t::item_rsa_q] = constexpr_rsa_q;
    table[crypt_item_t::item_rsa_dp] = constexpr_rsa_dp;
    table[crypt_item_t::item_rsa_dq] = constexpr_rsa_dq;
    table[crypt_item_t::item_rsa_qi] = constexpr_rsa_qi;
    table[crypt_item_t::item_ec_x] = constexpr_ec_x;
    table[crypt_item_t::item_ec_y] = constexpr_ec_y;
    table[crypt_item_t::item_ec_pub] = constexpr_ec_pub;
    table[crypt_item_t::item_ec_d] = constexpr_ec_d;
    table[crypt_item_t::item_dh_pub] = constexpr_pub;
    table[crypt_item_t::item_dh_priv] = constexpr_priv;
    table[crypt_item_t::item_dsa_pub] = constexpr_pub;
    table[crypt_item_t::item_dsa_priv] = constexpr_priv;
    table[crypt_item_t::item_dsa_p] = constexpr_dsa_p;
    table[crypt_item_t::item_dsa_q] = constexpr_dsa_q;
    table[crypt_item_t::item_dsa_g] = constexpr_dsa_g;

    __try2 {
        if (nullptr == stream) {
            __leave2;
        }

        const char* msg = nullptr;
        hint.find(type, &msg);
        if (msg) {
            stream->fill(indent / 2, ' ');
            stream->printf("%s\n", msg);
        }

        /* base64url encoding */
        std::string b64url_encoded = std::move(base64_encode(key, encoding_t::encoding_base64url));
        cbor_data* root = new cbor_data(key);

        /* openssl evp_pkey_print style */
        binary_t param = key;
        switch (type) {
            case crypt_item_t::item_rsa_n:
            case crypt_item_t::item_rsa_d:
            case crypt_item_t::item_rsa_p:
            case crypt_item_t::item_rsa_q:
            case crypt_item_t::item_rsa_dp:
            case crypt_item_t::item_rsa_dq:
            case crypt_item_t::item_ec_x:
            case crypt_item_t::item_ec_y:
            case crypt_item_t::item_ec_d:
            case crypt_item_t::item_dsa_p:
            case crypt_item_t::item_dsa_q:
            case crypt_item_t::item_dsa_g:
                param.insert(param.begin(), 0);
                break;
            default:
                break;
        }
        size_t size = param.size();
        for (size_t i = 0; i < size; i++) {
            size_t module = i % hex_part;
            if (0 == module) {
                if (0 != i) {
                    stream->printf("\n");
                }
                stream->fill(indent, ' ');
            }
            stream->printf("%02x", param[i]);
            if (i + 1 != size) {
                stream->printf(":");
            }
        }
        stream->printf("\n");

        /* base64url encoding */
        stream->fill(indent, ' ');
        stream->printf("\e[35m");
        stream->printf("%s", b64url_encoded.c_str());
        stream->printf("\e[0m");
        stream->printf("\n");

        /* COSE-style */
        if (root) {
            cbor_publisher publisher;
            basic_stream diagnostic;

            publisher.publish(root, &diagnostic);

            stream->fill(indent, ' ');
            stream->printf("\e[33m");
            stream->printf("%s", diagnostic.c_str());
            stream->printf("\e[0m");
            stream->printf("\n");

            root->release();
        }
    }
    __finally2 {}
}

void dump_key_openssl(const EVP_PKEY* pkey, stream_t* stream, uint8 indent) {
    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            __leave2;
        }

        bool is_private = false;
        is_private_key(pkey, is_private);

        BIO* bio = BIO_new(BIO_s_mem());
        if (bio) {
            if (is_private) {
                EVP_PKEY_print_private(bio, pkey, indent, nullptr);
            } else {
                EVP_PKEY_print_public(bio, pkey, indent, nullptr);
            }

            char temp[16];
            int l = 0;
            while (1) {
                l = BIO_read(bio, temp, sizeof(temp));
                if (0 >= l) {
                    break;
                }
                stream->write(temp, l);
            }

            BIO_free(bio);
        }
    }
    __finally2 {}
}

/*
 * @brief   RSA
 * @desc
 *          reference http://stackoverflow.com/questions/24093272/how-to-load-a-private-key-from-a-jwk-into-openssl
 * @examples
 *          const RSA* rsa = EVP_PKEY_get0_RSA (pkey);
 *          ret = RSA_solve (rsa);
 *          if (errorcode_t::success == ret) {
 *              const BIGNUM* bn_p = RSA_get0_p (rsa);
 *              const BIGNUM* bn_q = RSA_get0_q (rsa);
 *              const BIGNUM* bn_dp = RSA_get0_dmp1 (rsa);
 *              const BIGNUM* bn_dq = RSA_get0_dmq1 (rsa);
 *              const BIGNUM* bn_qi = RSA_get0_iqmp (rsa);
 *          }
 */
static return_t RSA_solve(RSA* rsa) {
    return_t ret = errorcode_t::success;
    BN_CTX* bn_ctx = nullptr;
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;
    BIGNUM* d = nullptr;
    BIGNUM* g = nullptr;
    BIGNUM* i = nullptr;
    BIGNUM* j = nullptr;
    BIGNUM* k = nullptr;
    BIGNUM* p = nullptr;
    BIGNUM* q = nullptr;
    BIGNUM* t = nullptr;
    BIGNUM* x = nullptr;
    BIGNUM* y = nullptr;
    BIGNUM* z = nullptr;

    __try2 {
        if (nullptr == rsa) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const BIGNUM* bn_n = nullptr;
        const BIGNUM* bn_e = nullptr;
        const BIGNUM* bn_d = nullptr;
        RSA_get0_key(rsa, &bn_n, &bn_e, &bn_d);

        if (nullptr == bn_n || nullptr == bn_e || nullptr == bn_d) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        bn_ctx = BN_CTX_new();
        n = BN_dup(bn_n);
        e = BN_dup(bn_e);
        d = BN_dup(bn_d);
        g = BN_new();
        i = BN_new();
        j = BN_new();
        k = BN_new();
        p = BN_new();
        q = BN_new();
        t = BN_new();
        x = BN_new();
        y = BN_new();
        z = BN_new();
        // g = 1
        BN_copy(g, BN_value_one());

        // step1:
        // k = e * d - 1
        BN_mul(k, e, d, bn_ctx);
        BN_sub(k, k, BN_value_one());
        if (1 == BN_is_odd(k)) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

    step2:
        BN_add_word(g, 2);  // g += 2;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        while (1 != BN_check_prime(g, bn_ctx, nullptr)) {
#else
        while (1 != BN_is_prime_ex(g, BN_prime_checks, bn_ctx, nullptr)) {
#endif
            BN_add_word(g, 2);  // g += 2;
        }
        BN_copy(t, k);  // t = k

    step3:
        if (1 == BN_is_odd(t)) {
            goto step2;
        }

        BN_rshift(t, t, 1);              // t >> 1;
        BN_mod_exp(x, g, t, n, bn_ctx);  // x = g ^ t mod n

        // step4:
        if (BN_cmp(x, BN_value_one()) <= 0) {
            goto step3;  // x <= 1
        }
        BN_sub(z, x, BN_value_one());
        BN_gcd(y, z, n, bn_ctx);  // y = gcd (x-1, n)
        if (BN_cmp(y, BN_value_one()) <= 0) {
            goto step3;  // y <= 1
        }
        BN_div(z, nullptr, n, y, bn_ctx);  // z = n / y

        int cmp = BN_cmp(y, z);
        BN_copy(p, (cmp >= 0) ? y : z);
        BN_copy(q, (cmp >= 0) ? z : y);

        RSA_set0_factors(rsa, BN_dup(p), BN_dup(q));

        BIGNUM* dmp1 = nullptr;
        BIGNUM* dmq1 = nullptr;
        BIGNUM* iqmp = nullptr;

        // dmp1 = d mod (p-1)
        BN_sub(i, p, BN_value_one());
        BN_mod(j, d, i, bn_ctx);
        dmp1 = BN_dup(j);

        // dmq1 = d mod (q-1)
        BN_sub(i, q, BN_value_one());
        BN_mod(j, d, i, bn_ctx);
        dmq1 = BN_dup(j);

        // iqmp = q^-1 mod p
        BN_mod_inverse(i, q, p, bn_ctx);
        iqmp = BN_dup(i);

        RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
    }
    __finally2 {
        if (bn_ctx) {
            BN_CTX_free(bn_ctx);
        }
        if (n) {
            BN_free(n);
        }
        if (e) {
            BN_free(e);
        }
        if (d) {
            BN_free(d);
        }
        if (g) {
            BN_free(g);
        }
        if (i) {
            BN_free(i);
        }
        if (j) {
            BN_free(j);
        }
        if (k) {
            BN_free(k);
        }
        if (p) {
            BN_free(p);
        }
        if (q) {
            BN_free(q);
        }
        if (t) {
            BN_free(t);
        }
        if (x) {
            BN_free(x);
        }
        if (y) {
            BN_free(y);
        }
        if (z) {
            BN_free(z);
        }
    }
    return ret;
}

return_t dump_key(const EVP_PKEY* pkey, stream_t* stream, uint8 hex_part, uint8 indent, uint8 flag) {
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == hex_part) {
            hex_part = 16;
        }
        if (0 == (dump_notrunc & flag)) {
            stream->clear();
        }

        int type = EVP_PKEY_id(pkey);
        switch (type) {
            case EVP_PKEY_HMAC:
                stream->printf("oct");
                break;
            case EVP_PKEY_RSA:
                stream->printf("RSA");
                break;
            case EVP_PKEY_RSA2:
                stream->printf("RSA2");
                break;
            case EVP_PKEY_RSA_PSS:
                stream->printf("RSA_PSS");
                break;
            case EVP_PKEY_EC:
                stream->printf("EC");
                break;
            case EVP_PKEY_X25519:
                stream->printf("X25519");
                break;
            case EVP_PKEY_X448:
                stream->printf("X448");
                break;
            case EVP_PKEY_ED25519:
                stream->printf("Ed25519");
                break;
            case EVP_PKEY_ED448:
                stream->printf("Ed448");
                break;
            case EVP_PKEY_DH:
                stream->printf("DH");
                break;
            case EVP_PKEY_DSA:
                stream->printf("DSA");
                break;
            case EVP_PKEY_KEYMGMT:
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        constexpr char constexpr_priv[] = "(private key)";
        constexpr char constexpr_pub[] = "(public key)";

        bool is_private = false;
        is_private_key(pkey, is_private);

        stream->printf(" ");
        if (is_private) {
            stream->printf(constexpr_priv);
        } else {
            stream->printf(constexpr_pub);
        }
        stream->printf("\n");

        crypto_key key;
        binary_t pub1;
        binary_t pub2;
        binary_t priv;
        key.get_key(pkey, pub1, pub2, priv, true);  // preserve leading zero octects

        switch (type) {
            case EVP_PKEY_HMAC:
                pkey_param_printf(crypt_item_t::item_hmac_k, priv, stream, hex_part, indent);
                break;
            case EVP_PKEY_RSA:
            case EVP_PKEY_RSA2:
            case EVP_PKEY_RSA_PSS:
                pkey_param_printf(crypt_item_t::item_rsa_n, pub1, stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_rsa_e, pub2, stream, hex_part, indent);

                if (is_private) {
                    pkey_param_printf(crypt_item_t::item_rsa_d, priv, stream, hex_part, indent);

                    const RSA* rsa = EVP_PKEY_get0_RSA((EVP_PKEY*)pkey);
                    ret = RSA_solve((RSA*)rsa);
                    if (errorcode_t::success == ret) {
                        const BIGNUM* bn_p = RSA_get0_p(rsa);
                        const BIGNUM* bn_q = RSA_get0_q(rsa);
                        const BIGNUM* bn_dp = RSA_get0_dmp1(rsa);
                        const BIGNUM* bn_dq = RSA_get0_dmq1(rsa);
                        const BIGNUM* bn_qi = RSA_get0_iqmp(rsa);
                        binary_t bin_p;
                        binary_t bin_q;
                        binary_t bin_dp;
                        binary_t bin_dq;
                        binary_t bin_qi;
                        bn2bin(bn_p, bin_p);
                        bn2bin(bn_q, bin_q);
                        bn2bin(bn_dp, bin_dp);
                        bn2bin(bn_dq, bin_dq);
                        bn2bin(bn_qi, bin_qi);

                        pkey_param_printf(crypt_item_t::item_rsa_p, bin_p, stream, hex_part, indent);
                        pkey_param_printf(crypt_item_t::item_rsa_q, bin_q, stream, hex_part, indent);
                        pkey_param_printf(crypt_item_t::item_rsa_dp, bin_dp, stream, hex_part, indent);
                        pkey_param_printf(crypt_item_t::item_rsa_dq, bin_dq, stream, hex_part, indent);
                        pkey_param_printf(crypt_item_t::item_rsa_qi, bin_qi, stream, hex_part, indent);
                    }
                }
                break;
            case EVP_PKEY_EC: {
                stream->printf("curve ");

                uint32 nid = 0;
                nidof_evp_pkey(pkey, nid);
                const hint_curve_t* hint_curve = advisor->hintof_curve_nid(nid);
                if (hint_curve) {
                    if (hint_curve->name_nist) {
                        stream->printf("%s ", hint_curve->name_nist);
                    }
                    stream->printf("aka ");
                    if (hint_curve->name_x962) {
                        stream->printf("%s ", hint_curve->name_x962);
                    }
                    if (hint_curve->name_sec) {
                        stream->printf("%s ", hint_curve->name_sec);
                    }
                    if (hint_curve->name_wtls) {
                        stream->printf("%s ", hint_curve->name_wtls);
                    }
                    stream->printf("\n");
                }

                pkey_param_printf(crypt_item_t::item_ec_x, pub1, stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_ec_y, pub2, stream, hex_part, indent);
                {
                    binary_t pub;
                    pub.insert(pub.end(), 4);
                    pub.insert(pub.end(), pub1.begin(), pub1.end());
                    pub.insert(pub.end(), pub2.begin(), pub2.end());
                    pkey_param_printf(crypt_item_t::item_ec_pub, pub, stream, hex_part, indent);
                }
                if (is_private) {
                    pkey_param_printf(crypt_item_t::item_ec_d, priv, stream, hex_part, indent);
                }
            } break;
            case EVP_PKEY_X25519:
            case EVP_PKEY_X448:
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448: {
                stream->printf("curve ");

                uint32 nid = 0;
                nidof_evp_pkey(pkey, nid);
                const hint_curve_t* hint_curve = advisor->hintof_curve_nid(nid);
                if (hint_curve) {
                    stream->printf("%s", hint_curve->name_nist);
                    stream->printf("\n");
                }

                pkey_param_printf(crypt_item_t::item_ec_x, pub1, stream, hex_part, indent);
                if (is_private) {
                    pkey_param_printf(crypt_item_t::item_ec_d, priv, stream, hex_part, indent);
                }
            } break;
            case EVP_PKEY_DH: {
                auto dh = EVP_PKEY_get0_DH((EVP_PKEY*)pkey);
                const BIGNUM* bn_pub = nullptr;
                const BIGNUM* bn_priv = nullptr;
                DH_get0_key(dh, &bn_pub, &bn_priv);
                int nid = DH_get_nid(dh);
                stream->printf(" %i\n", nid);

                binary_t bin_pub;
                binary_t bin_priv;
                bn2bin(bn_pub, bin_pub);
                pkey_param_printf(crypt_item_t::item_dh_pub, bin_pub, stream, hex_part, indent);

                if (bn_priv) {
                    bn2bin(bn_priv, bin_priv);
                    pkey_param_printf(crypt_item_t::item_dh_priv, bin_priv, stream, hex_part, indent);
                }
            } break;
            case EVP_PKEY_DSA: {
                auto dsa = EVP_PKEY_get0_DSA((EVP_PKEY*)pkey);
                const BIGNUM* bn_p = nullptr;
                const BIGNUM* bn_q = nullptr;
                const BIGNUM* bn_g = nullptr;
                const BIGNUM* bn_pub = nullptr;
                const BIGNUM* bn_priv = nullptr;
                DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);
                DSA_get0_key(dsa, &bn_pub, &bn_priv);

                binary_t bin_pub;
                binary_t bin_priv;
                binary_t bin_p;
                binary_t bin_q;
                binary_t bin_g;

                bn2bin(bn_pub, bin_pub);
                bn2bin(bn_priv, bin_priv);
                bn2bin(bn_p, bin_p);
                bn2bin(bn_q, bin_q);
                bn2bin(bn_g, bin_g);
                pkey_param_printf(crypt_item_t::item_dsa_pub, bin_pub, stream, hex_part, indent);
                if (bin_priv.size()) {
                    pkey_param_printf(crypt_item_t::item_dsa_priv, bin_priv, stream, hex_part, indent);
                }
                pkey_param_printf(crypt_item_t::item_dsa_p, bin_p, stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dsa_q, bin_q, stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dsa_g, bin_g, stream, hex_part, indent);
            } break;
            default: {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
                BIO* bio = BIO_new(BIO_s_mem());
                EVP_PKEY_print_params(bio, pkey, indent, nullptr);
                char temp[16];
                int l = 0;
                while (1) {
                    l = BIO_read(bio, temp, sizeof(temp));
                    if (0 >= l) {
                        break;
                    }
                    stream->write(temp, l);
                }
                BIO_free(bio);
#endif
            } break;
        }

        /* PEM */
        basic_stream pem_encoded;
        dump_pem(pkey, &pem_encoded);
        stream->printf("%.*s", pem_encoded.size(), pem_encoded.data());
        stream->printf("\n");

        // dump_key_openssl (pkey, stream, 0);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
