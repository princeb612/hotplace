/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   dump_key.cpp
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
    __try2 {
        if (nullptr == stream || key.empty()) {
            __leave2;
        }

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

        constexpr char constexpr_dsa_p[] = "p (prime)";
        constexpr char constexpr_dsa_q[] = "q (subprime)";
        constexpr char constexpr_dsa_g[] = "g (generator)";

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
        table[crypt_item_t::item_dh_p] = constexpr_dsa_p;
        table[crypt_item_t::item_dh_q] = constexpr_dsa_q;
        table[crypt_item_t::item_dh_g] = constexpr_dsa_g;
        table[crypt_item_t::item_dh_pub] = constexpr_pub;
        table[crypt_item_t::item_dh_priv] = constexpr_priv;

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
            case crypt_item_t::item_dh_p:
            case crypt_item_t::item_dh_q:
            case crypt_item_t::item_dh_g:
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
        stream->printf(ANSI_ESCAPE "35m");
        stream->printf("%s", b64url_encoded.c_str());
        stream->printf(ANSI_ESCAPE "0m");
        stream->printf("\n");

        /* COSE-style */
        if (root) {
            cbor_publisher publisher;
            basic_stream diagnostic;

            publisher.publish(root, &diagnostic);

            stream->fill(indent, ' ');
            stream->printf(ANSI_ESCAPE "33m");
            stream->printf("%s", diagnostic.c_str());
            stream->printf(ANSI_ESCAPE "0m");
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

        BIO_ptr bio(BIO_new(BIO_s_mem()));
        if (bio.get()) {
            if (is_private) {
                EVP_PKEY_print_private(bio.get(), pkey, indent, nullptr);
            } else {
                EVP_PKEY_print_public(bio.get(), pkey, indent, nullptr);
            }

            char temp[16];
            int l = 0;
            while (1) {
                l = BIO_read(bio.get(), temp, sizeof(temp));
                if (0 >= l) {
                    break;
                }
                stream->write(temp, l);
            }
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

    __try2 {
        if (nullptr == rsa) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const BIGNUM* bn_n0 = nullptr;
        const BIGNUM* bn_e0 = nullptr;
        const BIGNUM* bn_d0 = nullptr;
        RSA_get0_key(rsa, &bn_n0, &bn_e0, &bn_d0);

        if (nullptr == bn_n0 || nullptr == bn_e0 || nullptr == bn_d0) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        BN_CTX_ptr bn_ctx(BN_CTX_new());
        BN_ptr bn_n(BN_dup(bn_n0));
        BN_ptr bn_e(BN_dup(bn_e0));
        BN_ptr bn_d(BN_dup(bn_d0));
        BN_ptr bn_g(BN_new());
        BN_ptr bn_i(BN_new());
        BN_ptr bn_j(BN_new());
        BN_ptr bn_k(BN_new());
        BN_ptr bn_p(BN_new());
        BN_ptr bn_q(BN_new());
        BN_ptr bn_t(BN_new());
        BN_ptr bn_x(BN_new());
        BN_ptr bn_y(BN_new());
        BN_ptr bn_z(BN_new());
        // bn_g = 1
        BN_copy(bn_g.get(), BN_value_one());

        // step1:
        // bn_k = bn_e * bn_d - 1
        BN_mul(bn_k.get(), bn_e.get(), bn_d.get(), bn_ctx.get());
        BN_sub(bn_k.get(), bn_k.get(), BN_value_one());
        if (1 == BN_is_odd(bn_k.get())) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

    step2:
        BN_add_word(bn_g.get(), 2);  // bn_g += 2;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        while (1 != BN_check_prime(bn_g.get(), bn_ctx.get(), nullptr)) {
#else
        while (1 != BN_is_prime_ex(bn_g.get(), BN_prime_checks, bn_ctx.get(), nullptr)) {
#endif
            BN_add_word(bn_g.get(), 2);  // bn_g += 2;
        }
        BN_copy(bn_t.get(), bn_k.get());  // bn_t = bn_k

    step3:
        if (1 == BN_is_odd(bn_t.get())) {
            goto step2;
        }

        BN_rshift(bn_t.get(), bn_t.get(), 1);                                      // bn_t >> 1;
        BN_mod_exp(bn_x.get(), bn_g.get(), bn_t.get(), bn_n.get(), bn_ctx.get());  // bn_x = bn_g ^ bn_t mod bn_n

        // step4:
        if (BN_cmp(bn_x.get(), BN_value_one()) <= 0) {
            goto step3;  // bn_x <= 1
        }
        BN_sub(bn_z.get(), bn_x.get(), BN_value_one());
        BN_gcd(bn_y.get(), bn_z.get(), bn_n.get(), bn_ctx.get());  // bn_y = gcd (bn_x-1, bn_n)
        if (BN_cmp(bn_y.get(), BN_value_one()) <= 0) {
            goto step3;  // bn_y <= 1
        }
        BN_div(bn_z.get(), nullptr, bn_n.get(), bn_y.get(), bn_ctx.get());  // bn_z = bn_n / bn_y

        int cmp = BN_cmp(bn_y.get(), bn_z.get());
        BN_copy(bn_p.get(), (cmp >= 0) ? bn_y.get() : bn_z.get());
        BN_copy(bn_q.get(), (cmp >= 0) ? bn_z.get() : bn_y.get());

        RSA_set0_factors(rsa, BN_dup(bn_p.get()), BN_dup(bn_q.get()));

        // bn_dmp1 = bn_d mod (bn_p-1)
        BN_sub(bn_i.get(), bn_p.get(), BN_value_one());
        BN_mod(bn_j.get(), bn_d.get(), bn_i.get(), bn_ctx.get());
        BN_ptr bn_dmp1(BN_dup(bn_j.get()));

        // bn_dmq1 = bn_d mod (bn_q-1)
        BN_sub(bn_i.get(), bn_q.get(), BN_value_one());
        BN_mod(bn_j.get(), bn_d.get(), bn_i.get(), bn_ctx.get());
        BN_ptr bn_dmq1(BN_dup(bn_j.get()));

        // bn_iqmp = bn_q^-1 mod bn_p
        BN_mod_inverse(bn_i.get(), bn_q.get(), bn_p.get(), bn_ctx.get());
        BN_ptr bn_iqmp(BN_dup(bn_i.get()));

        RSA_set0_crt_params(rsa, bn_dmp1.get(), bn_dmq1.get(), bn_iqmp.get());
        bn_dmp1.release();  // rsa own bn_dmp1
        bn_dmq1.release();  // rsa own bn_dmq1
        bn_iqmp.release();  // rsa own bn_iqmp
    }
    __finally2 {}
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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            case EVP_PKEY_KEYMGMT:
                break;
#endif
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

        crypto_kty_t kty = crypto_kty_t::kty_unknown;
        crypt_datamap_t datamap;
        crypto_key::extract(pkey, public_key | private_key, kty, datamap, true);  // preserve leading zero octects

        switch (type) {
            case EVP_PKEY_HMAC:
                pkey_param_printf(crypt_item_t::item_hmac_k, datamap[item_hmac_k], stream, hex_part, indent);
                break;
            case EVP_PKEY_RSA:
            case EVP_PKEY_RSA2:
            case EVP_PKEY_RSA_PSS:
                pkey_param_printf(crypt_item_t::item_rsa_n, datamap[item_rsa_n], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_rsa_e, datamap[item_rsa_e], stream, hex_part, indent);

                if (is_private) {
                    pkey_param_printf(crypt_item_t::item_rsa_d, datamap[item_rsa_d], stream, hex_part, indent);

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
                    if (hint_curve->name_bp) {
                        stream->printf("%s ", hint_curve->name_bp);
                    }
                    if (hint_curve->name_wtls) {
                        stream->printf("%s ", hint_curve->name_wtls);
                    }
                    stream->printf("\n");
                }

                binary_t bin_x = datamap[item_ec_x];
                binary_t bin_y = datamap[item_ec_y];
                pkey_param_printf(crypt_item_t::item_ec_x, bin_x, stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_ec_y, bin_x, stream, hex_part, indent);
                {
                    binary_t pub;
                    pub.insert(pub.end(), 4);
                    pub.insert(pub.end(), bin_x.begin(), bin_x.end());
                    pub.insert(pub.end(), bin_y.begin(), bin_y.end());
                    pkey_param_printf(crypt_item_t::item_ec_pub, pub, stream, hex_part, indent);
                }
                if (is_private) {
                    pkey_param_printf(crypt_item_t::item_ec_d, datamap[item_ec_d], stream, hex_part, indent);
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

                pkey_param_printf(crypt_item_t::item_ec_x, datamap[item_ec_x], stream, hex_part, indent);
                if (is_private) {
                    pkey_param_printf(crypt_item_t::item_ec_d, datamap[item_ec_d], stream, hex_part, indent);
                }
            } break;
            case EVP_PKEY_DH: {
                auto dh = EVP_PKEY_get0_DH((EVP_PKEY*)pkey);
                int nid = DH_get_nid(dh);
                stream->printf(" %i\n", nid);

                pkey_param_printf(crypt_item_t::item_dh_pub, datamap[item_dh_y], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dh_p, datamap[item_dh_p], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dh_q, datamap[item_dh_q], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dh_g, datamap[item_dh_g], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dh_priv, datamap[item_dh_x], stream, hex_part, indent);
            } break;
            case EVP_PKEY_DSA: {
                auto dsa = EVP_PKEY_get0_DSA((EVP_PKEY*)pkey);

                pkey_param_printf(crypt_item_t::item_dsa_pub, datamap[item_dsa_y], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dsa_p, datamap[item_dsa_p], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dsa_q, datamap[item_dsa_q], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dsa_g, datamap[item_dsa_g], stream, hex_part, indent);
                pkey_param_printf(crypt_item_t::item_dsa_priv, datamap[item_dsa_x], stream, hex_part, indent);
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
