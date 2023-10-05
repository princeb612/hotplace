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
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
using namespace io;
namespace crypto {

return_t nidof_evp_pkey (EVP_PKEY* pkey, uint32& nid)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        nid = 0;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        nid = EVP_PKEY_id ((EVP_PKEY *) pkey);
        if (EVP_PKEY_EC == nid) {
            EC_KEY* ec = EVP_PKEY_get1_EC_KEY ((EVP_PKEY*) pkey);
            if (ec) {
                const EC_GROUP* group = EC_KEY_get0_group (ec);
                nid = EC_GROUP_get_curve_name (group);
                EC_KEY_free (ec);
            }
        }
        if (0 == nid) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

bool kindof_ecc (EVP_PKEY* pkey)
{
    bool test = false;

    if (pkey) {
        int type = EVP_PKEY_id (pkey);
        test = ((EVP_PKEY_EC == type) || (EVP_PKEY_ED25519 == type) || (EVP_PKEY_ED448 == type)
                || (EVP_PKEY_X25519 == type) || (EVP_PKEY_X448 == type));
    }
    return test;
}

bool kindof_ecc (crypto_key_t type)
{
    return (crypto_key_t::kty_ec == type) || (crypto_key_t::kty_okp == type);
}

const char* nameof_key_type (crypto_key_t type)
{
    const char* name = "";

    if (crypto_key_t::kty_hmac == type) {
        name = "oct";
    } else if (crypto_key_t::kty_rsa == type) {
        name = "RSA";
    } else if (crypto_key_t::kty_ec == type) {
        name = "EC";
    } else if (crypto_key_t::kty_okp == type) {
        name = "OKP";
    }
    return name;
}

crypto_key_t typeof_crypto_key (EVP_PKEY* pkey)
{
    crypto_key_t kty = crypto_key_t::kty_unknown;
    int type = EVP_PKEY_id ((EVP_PKEY *) pkey);

    switch (type) {
        case EVP_PKEY_HMAC:
            kty = crypto_key_t::kty_hmac;
            break;
        case EVP_PKEY_RSA:
            kty = crypto_key_t::kty_rsa;
            break;
        case EVP_PKEY_EC:
            kty = crypto_key_t::kty_ec;
            break;
        case EVP_PKEY_X25519:
        case EVP_PKEY_X448:
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
            kty = crypto_key_t::kty_okp;
            break;
        default:
            break;
    }
    return kty;
}

return_t is_private_key (EVP_PKEY* pkey, bool& result)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        result = false;

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        EVP_PKEY* key = (EVP_PKEY*) (pkey);
        int type = EVP_PKEY_id (key);

        switch (type) {
            case EVP_PKEY_HMAC:
                result = true;
                break;
            case EVP_PKEY_RSA:
                if (nullptr != RSA_get0_d (EVP_PKEY_get0_RSA (key))) {
                    result = true;
                }
                break;
            case EVP_PKEY_EC:
            {
                const BIGNUM* bn = EC_KEY_get0_private_key (EVP_PKEY_get0_EC_KEY (key));
                if (nullptr != bn) {
                    result = true;
                }
                break;
            }
            case EVP_PKEY_X25519:
            case EVP_PKEY_X448:
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
            {
                binary_t bin_d;
                size_t len_d = 256;
                bin_d.resize (len_d);
                int check = EVP_PKEY_get_raw_private_key ((EVP_PKEY*) pkey, &bin_d[0], &len_d);
                bin_d.resize (len_d);
                if (1 == check) {
                    result = true;
                }
                break;
            }
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static void pkey_param_printf (const char* msg, binary_t const& key, stream_t* stream, uint8 hex_part, uint8 indent)
{
    __try2
    {
        if (nullptr == stream) {
            __leave2;
        }

        if (msg) {
            printf ("%s\n", msg);
        }

        size_t size = key.size ();
        for (size_t i = 0; i < size; i++) {
            size_t module = i % hex_part;
            if (0 == module) {
                if (0 != i) {
                    stream->printf ("\n");
                }
                stream->fill (indent, ' ');
            }
            stream->printf ("%02x", key[i]);
            if (i + 1 != size) {
                stream->printf (":");
            }
        }
        stream->printf ("\n");
    }
    __finally2
    {
        // do nothing
    }
}

static void dump_key_openssl (EVP_PKEY * pkey, stream_t * stream, uint8 indent)
{
    __try2
    {
        if (nullptr == pkey || nullptr == stream) {
            __leave2;
        }

        bool is_private = false;
        is_private_key (pkey, is_private);

        BIO* bio = BIO_new (BIO_s_mem ());
        if (bio) {
            if (is_private) {
                EVP_PKEY_print_private (bio, pkey, indent, nullptr);
            } else {
                EVP_PKEY_print_public (bio, pkey, indent, nullptr);
            }

            char temp[16];
            int l = 0;
            while (1) {
                l = BIO_read (bio, temp, sizeof (temp));
                if (0 >= l) {
                    break;
                }
                stream->write (temp, l);
            }

            BIO_free (bio);
        }
    }
    __finally2
    {
        // do nothing
    }
}

/*
 * @brief   RSA
 * @desc
 *          reference http://stackoverflow.com/questions/24093272/how-to-load-a-private-key-from-a-jwk-into-openssl
 * @examples
 *          const RSA* rsa = EVP_PKEY_get0_RSA (pkey);
 *          ret = RSA_solve (rsa);
 *          if (errorcode_t::success == ret) {
 *              const RSA* rsa = EVP_PKEY_get0_RSA (pkey);
 *              RSA_solve ((RSA*) rsa);
 *
 *              const BIGNUM* bn_p = RSA_get0_p (rsa);
 *              const BIGNUM* bn_q = RSA_get0_q (rsa);
 *              const BIGNUM* bn_dp = RSA_get0_dmp1 (rsa);
 *              const BIGNUM* bn_dq = RSA_get0_dmq1 (rsa);
 *              const BIGNUM* bn_qi = RSA_get0_iqmp (rsa);
 *          }
 */
static return_t RSA_solve (RSA* rsa)
{
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

    __try2
    {
        if (nullptr == rsa) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const BIGNUM* bn_n = nullptr;
        const BIGNUM* bn_e = nullptr;
        const BIGNUM* bn_d = nullptr;
        RSA_get0_key (rsa, &bn_n, &bn_e, &bn_d);

        if (nullptr == bn_n || nullptr == bn_e || nullptr == bn_d) {
            ret = errorcode_t::bad_format;
            __leave2;
        }

        bn_ctx = BN_CTX_new ();
        n = BN_dup (bn_n);
        e = BN_dup (bn_e);
        d = BN_dup (bn_d);
        g = BN_new ();
        i = BN_new ();
        j = BN_new ();
        k = BN_new ();
        p = BN_new ();
        q = BN_new ();
        t = BN_new ();
        x = BN_new ();
        y = BN_new ();
        z = BN_new ();
        // g = 1
        BN_copy (g, BN_value_one ());

//step1:
        // k = e * d - 1
        BN_mul (k, e, d, bn_ctx);
        BN_sub (k, k, BN_value_one ());
        if (1 == BN_is_odd (k)) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

step2:
        BN_add_word (g, 2); // g += 2;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        while (1 != BN_check_prime (g, bn_ctx, nullptr)) {
#else
        while (1 != BN_is_prime_ex (g, BN_prime_checks, bn_ctx, nullptr)) {
#endif
            BN_add_word (g, 2);     // g += 2;
        }
        BN_copy (t, k);             // t = k

step3:
        if (1 == BN_is_odd (t)) {
            goto step2;
        }

        BN_rshift (t, t, 1);                // t >> 1;
        BN_mod_exp (x, g, t, n, bn_ctx);    // x = g ^ t mod n

//step4:
        if (BN_cmp (x, BN_value_one ()) <= 0) {
            goto step3; // x <= 1

        }
        BN_sub (z, x, BN_value_one ());
        BN_gcd (y, z, n, bn_ctx);       // y = gcd (x-1, n)
        if (BN_cmp (y, BN_value_one ()) <= 0) {
            goto step3;                 // y <= 1

        }
        BN_div (z, nullptr, n, y, bn_ctx);  // z = n / y

        int cmp = BN_cmp (y, z);
        BN_copy (p, (cmp >= 0) ? y : z);
        BN_copy (q, (cmp >= 0) ? z : y);

        RSA_set0_factors (rsa, BN_dup (p), BN_dup (q));

        BIGNUM* dmp1 = nullptr;
        BIGNUM* dmq1 = nullptr;
        BIGNUM* iqmp = nullptr;

        // dmp1 = d mod (p-1)
        BN_sub (i, p, BN_value_one ());
        BN_mod (j, d, i, bn_ctx);
        dmp1 = BN_dup (j);

        // dmq1 = d mod (q-1)
        BN_sub (i, q, BN_value_one ());
        BN_mod (j, d, i, bn_ctx);
        dmq1 = BN_dup (j);

        // iqmp = q^-1 mod p
        BN_mod_inverse (i, q, p, bn_ctx);
        iqmp = BN_dup (i);

        RSA_set0_crt_params (rsa, dmp1, dmq1, iqmp);
    }
    __finally2
    {
        if (bn_ctx) {
            BN_CTX_free (bn_ctx);
        }
        if (n) {
            BN_free (n);
        }
        if (e) {
            BN_free (e);
        }
        if (d) {
            BN_free (d);
        }
        if (g) {
            BN_free (g);
        }
        if (i) {
            BN_free (i);
        }
        if (j) {
            BN_free (j);
        }
        if (k) {
            BN_free (k);
        }
        if (p) {
            BN_free (p);
        }
        if (q) {
            BN_free (q);
        }
        if (t) {
            BN_free (t);
        }
        if (x) {
            BN_free (x);
        }
        if (y) {
            BN_free (y);
        }
        if (z) {
            BN_free (z);
        }
    }
    return ret;
}

return_t dump_key (EVP_PKEY* pkey, stream_t* stream, uint8 hex_part, uint8 indent)
{
    return_t ret = errorcode_t::success;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (nullptr == pkey || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        stream->clear ();

        int type = EVP_PKEY_id ((EVP_PKEY *) pkey);
        switch (type) {
            case EVP_PKEY_HMAC:
                stream->printf ("hmac");
                break;
            case EVP_PKEY_RSA:
                stream->printf ("RSA");
                break;
            case EVP_PKEY_EC:
                stream->printf ("EC");
                break;
            case EVP_PKEY_X25519:
                stream->printf ("X25519");
                break;
            case EVP_PKEY_X448:
                stream->printf ("X448");
                break;
            case EVP_PKEY_ED25519:
                stream->printf ("Ed25519");
                break;
            case EVP_PKEY_ED448:
                stream->printf ("Ed448");
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }

        if (errorcode_t::success != ret) {
            __leave2;
        }

        bool is_private = false;
        is_private_key (pkey, is_private);

        constexpr char constexpr_priv [] = "(private key)";
        constexpr char constexpr_pub  [] = "(public key)";

        stream->printf (" ");
        if (is_private) {
            stream->printf (constexpr_priv);
        } else {
            stream->printf (constexpr_pub);
        }
        stream->printf ("\n");

        crypto_key key;
        binary_t pub1;
        binary_t pub2;
        binary_t priv;
        key.get_key (pkey, pub1, pub2, priv, true); // preserve leading zero octects

        constexpr char constexpr_hmac   [] = "k";

        constexpr char constexpr_rsa_n  [] = "modulus (00:n)";
        constexpr char constexpr_rsa_e  [] = "public exponent (e)";
        constexpr char constexpr_rsa_d  [] = "private exponent (d)";

        constexpr char constexpr_rsa_p  [] = "prime1 (00:p)";
        constexpr char constexpr_rsa_q  [] = "prime2 (00:q)";
        constexpr char constexpr_rsa_dp [] = "exponent1 (dp)";
        constexpr char constexpr_rsa_dq [] = "exponent2 (00:dq)";
        constexpr char constexpr_rsa_qi [] = "coefficient (qi)";

        constexpr char constexpr_ec_crv [] = "%s (aka %s, %s)";
        constexpr char constexpr_ec_pub [] = "public (04:x:y)";
        constexpr char constexpr_ec_priv[] = "private (d)";

        switch (type) {
            case EVP_PKEY_HMAC:
                pkey_param_printf (constexpr_hmac, priv, stream, hex_part, indent);
                break;
            case EVP_PKEY_RSA:
                pub1.insert (pub1.begin (), 0);
                pkey_param_printf (constexpr_rsa_n, pub1, stream, hex_part, indent);
                pkey_param_printf (constexpr_rsa_e, pub2, stream, hex_part, indent);

                if (is_private) {
                    pkey_param_printf (constexpr_rsa_d, priv, stream, hex_part, indent);

                    const RSA* rsa = EVP_PKEY_get0_RSA (pkey);
                    RSA_solve ((RSA*) rsa);

                    const BIGNUM* bn_p = RSA_get0_p (rsa);
                    const BIGNUM* bn_q = RSA_get0_q (rsa);
                    const BIGNUM* bn_dp = RSA_get0_dmp1 (rsa);
                    const BIGNUM* bn_dq = RSA_get0_dmq1 (rsa);
                    const BIGNUM* bn_qi = RSA_get0_iqmp (rsa);
                    binary_t bin_p;
                    binary_t bin_q;
                    binary_t bin_dp;
                    binary_t bin_dq;
                    binary_t bin_qi;
                    bin_p.resize (BN_num_bytes (bn_p));
                    bin_q.resize (BN_num_bytes (bn_q));
                    bin_dp.resize (BN_num_bytes (bn_dp));
                    bin_dq.resize (BN_num_bytes (bn_dq));
                    bin_qi.resize (BN_num_bytes (bn_qi));
                    BN_bn2bin (bn_p, &bin_p[0]);
                    BN_bn2bin (bn_q, &bin_q[0]);
                    BN_bn2bin (bn_dp, &bin_dp[0]);
                    BN_bn2bin (bn_dq, &bin_dq[0]);
                    BN_bn2bin (bn_qi, &bin_qi[0]);

                    bin_p.insert (bin_p.begin (), 0);
                    bin_q.insert (bin_q.begin (), 0);
                    bin_dq.insert (bin_dq.begin (), 0);

                    pkey_param_printf (constexpr_rsa_p, bin_p, stream, hex_part, indent);
                    pkey_param_printf (constexpr_rsa_q, bin_q, stream, hex_part, indent);
                    pkey_param_printf (constexpr_rsa_dp, bin_dp, stream, hex_part, indent);
                    pkey_param_printf (constexpr_rsa_dq, bin_dq, stream, hex_part, indent);
                    pkey_param_printf (constexpr_rsa_qi, bin_qi, stream, hex_part, indent);
                }
                break;
            case EVP_PKEY_EC:
                stream->printf ("curve ");
                {
                    uint32 nid = 0;
                    nidof_evp_pkey (pkey, nid);
                    const hint_curve_t* hint_curve = advisor->hintof_curve_nid (nid);
                    if (hint_curve) {
                        stream->printf (constexpr_ec_crv, hint_curve->name, hint_curve->nameof_x9_62, hint_curve->nameof_sec);
                    }
                }

                pkey_param_printf ("x", pub1, stream, hex_part, indent);
                pkey_param_printf ("y", pub2, stream, hex_part, indent);
                {
                    binary_t pub;
                    pub.insert (pub.end (), 4);
                    pub.insert (pub.end (), pub1.begin (), pub1.end ());
                    pub.insert (pub.end (), pub2.begin (), pub2.end ());
                    pkey_param_printf (constexpr_ec_pub, pub, stream, hex_part, indent);
                }
                if (is_private) {
                    pkey_param_printf (constexpr_ec_priv, priv, stream, hex_part, indent);
                }
                break;
            case EVP_PKEY_X25519:
            case EVP_PKEY_X448:
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448:
                stream->printf ("curve ");
                {
                    uint32 nid = 0;
                    nidof_evp_pkey (pkey, nid);
                    const hint_curve_t* hint_curve = advisor->hintof_curve_nid (nid);
                    if (hint_curve) {
                        stream->printf ("%s\n", hint_curve->name);
                    }
                }

                pkey_param_printf ("x", pub1, stream, hex_part, indent);
                if (is_private) {
                    pkey_param_printf ("d", priv, stream, hex_part, indent);
                }
                break;
            default:
                break;
        }

        //dump_key_openssl (pkey, stream, 0);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

}
}  // namespace
