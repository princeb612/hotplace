/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>

namespace hotplace {
namespace crypto {

crypto_keychain::crypto_keychain ()
{
    // do nothing
}

crypto_keychain::~crypto_keychain ()
{
    // do nothing
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, size_t param, crypto_use_t use)
{
    return add_rsa (cryptokey, nullptr, nullptr, param, use);
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, const char* kid, size_t param, crypto_use_t use)
{
    return add_rsa (cryptokey, kid, nullptr, param, use);
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, const char* kid, const char* alg, size_t param, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pkey_context = nullptr;
    int ret_openssl = 1;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey_context = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, nullptr);
        if (nullptr == pkey_context) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_openssl = EVP_PKEY_keygen_init (pkey_context);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        /* EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_context, bits) */
        ret_openssl = EVP_PKEY_CTX_ctrl (pkey_context, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, param, nullptr);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ret_openssl = EVP_PKEY_keygen (pkey_context, &pkey);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        crypto_key_object_t key (pkey, use, kid, alg);
        key.set_keybits (param);

        ret = cryptokey->add (key);
    }
    __finally2
    {
        if (nullptr != pkey_context) {
            EVP_PKEY_CTX_free (pkey_context); // EVP_PKEY_free here !
        }
    }
    return ret;
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, const char* kid, jwa_t alg, size_t param, crypto_use_t use)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);

    return add_rsa (cryptokey, kid, hint ? hint->alg_name : nullptr, param, use);
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, const char* kid, const char* alg, binary_t n, binary_t e, binary_t d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    RSA* rsa = nullptr;
    int ret_openssl = 1;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == n.size () || 0 == e.size ()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        rsa = RSA_new ();
        if (nullptr == rsa) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        BIGNUM* bn_n = nullptr;
        BIGNUM* bn_e = nullptr;
        BIGNUM* bn_d = nullptr;

        bn_n = BN_bin2bn (&n[0], n.size (), nullptr);
        bn_e = BN_bin2bn (&e[0], e.size (), nullptr);
        if (0 != d.size ()) {
            bn_d = BN_bin2bn (&d[0], d.size (), nullptr);
        }

        RSA_set0_key (rsa, bn_n, bn_e, bn_d);

        pkey = EVP_PKEY_new ();
        ret_openssl = EVP_PKEY_assign_RSA (pkey, rsa);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        //RSA_solve (rsa);

        crypto_key_object_t key;
        key.pkey = pkey;
        key.use = use;
        if (kid) {
            key.kid = kid;
        }
        if (alg) {
            key.alg = alg;
        }

        cryptokey->add (key);
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free (pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, const char* kid, jwa_t alg, binary_t n, binary_t e, binary_t d, crypto_use_t use)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);

    return add_rsa (cryptokey, kid, hint ? hint->alg_name : nullptr, n, e, d, use);
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, const char* kid, const char* alg, binary_t n, binary_t e, binary_t d,
                                   binary_t p, binary_t q, binary_t dp, binary_t dq, binary_t qi, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    RSA* rsa = nullptr;
    int ret_openssl = 1;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (0 == n.size () || 0 == e.size ()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        rsa = RSA_new ();
        if (nullptr == rsa) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        BIGNUM* bn_n = nullptr;
        BIGNUM* bn_e = nullptr;
        BIGNUM* bn_d = nullptr;
        BIGNUM* bn_p = nullptr;
        BIGNUM* bn_q = nullptr;
        BIGNUM* bn_dmp1 = nullptr;
        BIGNUM* bn_dmq1 = nullptr;
        BIGNUM* bn_iqmp = nullptr;

        bn_n = BN_bin2bn (&n[0], n.size (), nullptr);
        bn_e = BN_bin2bn (&e[0], e.size (), nullptr);
        if (0 != d.size ()) {
            bn_d = BN_bin2bn (&d[0], d.size (), nullptr);
        }

        if (0 != p.size ()) {
            bn_p = BN_bin2bn (&p[0], p.size (), nullptr);
        }
        if (0 != q.size ()) {
            bn_q = BN_bin2bn (&q[0], q.size (), nullptr);
        }
        if (0 != dp.size ()) {
            bn_dmp1 = BN_bin2bn (&dp[0], dp.size (), nullptr);
        }
        if (0 != dq.size ()) {
            bn_dmq1 = BN_bin2bn (&dq[0], dq.size (), nullptr);
        }
        if (0 != qi.size ()) {
            bn_iqmp = BN_bin2bn (&qi[0], qi.size (), nullptr);
        }

        RSA_set0_key (rsa, bn_n, bn_e, bn_d);
        RSA_set0_factors (rsa, bn_p, bn_q);
        RSA_set0_crt_params (rsa, bn_dmp1, bn_dmq1, bn_iqmp);

        pkey = EVP_PKEY_new ();
        ret_openssl = EVP_PKEY_assign_RSA (pkey, rsa);
        if (ret_openssl <= 0) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        /* verify */
        ret_openssl = RSA_check_key (rsa);
        if (ret_openssl <= 0) {
            ret = errorcode_t::invalid_parameter;
            __leave2_trace_openssl (ret);
        }

        crypto_key_object_t key (pkey, use, kid, alg);
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        key.set_keybits (EVP_PKEY_get_bits (pkey));
#endif

        cryptokey->add (key);
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free (pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_rsa (crypto_key* cryptokey, const char* kid, jwa_t alg, binary_t n, binary_t e, binary_t d,
                                   binary_t p, binary_t q, binary_t dp, binary_t dq, binary_t qi, crypto_use_t use)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);

    return add_rsa (cryptokey, kid, hint ? hint->alg_name : nullptr, n, e, d, p, q, dp, dq, qi, use);
}

return_t crypto_keychain::add_ec (crypto_key* cryptokey, int nid, crypto_use_t use)
{
    return add_ec (cryptokey, nullptr, nullptr, nid, use);
}

return_t crypto_keychain::add_ec (crypto_key* cryptokey, const char* kid, int nid, crypto_use_t use)
{
    return add_ec (cryptokey, kid, nullptr, nid, use);
}

return_t crypto_keychain::add_ec (crypto_key* cryptokey, const char* kid, const char* alg, int nid, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    int ret_openssl = 0;
    EVP_PKEY* params = nullptr;
    EVP_PKEY_CTX* keyctx = nullptr;
    uint32 keybits = 0;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int type = 0;
        switch (nid) {
            case NID_X9_62_prime256v1:
                type = EVP_PKEY_EC;
                keybits = 256;
                break;
            case NID_secp384r1:
                type = EVP_PKEY_EC;
                keybits = 384;
                break;
            case NID_secp521r1:
                type = EVP_PKEY_EC;
                keybits = 512;
                break;
            case NID_X25519:
            case NID_ED25519:
                /*
                 *  # define EVP_PKEY_X25519 NID_X25519
                 *  # define EVP_PKEY_ED25519 NID_ED25519
                 */
                type = nid;
                keybits = 256;
                break;
            case NID_X448:
            case NID_ED448:
                /*
                 *  # define EVP_PKEY_X448 NID_X448
                 *  # define EVP_PKEY_ED448 NID_ED448
                 */
                type = nid;
                keybits = 448;
                break;
            default:
                type = nid;
                break;
        }

        ctx = EVP_PKEY_CTX_new_id (type, nullptr);
        if (EVP_PKEY_EC == type) {
            ret_openssl = EVP_PKEY_paramgen_init (ctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            ret_openssl = EVP_PKEY_CTX_set_ec_paramgen_curve_nid (ctx, nid);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            ret_openssl = EVP_PKEY_paramgen (ctx, &params);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            keyctx = EVP_PKEY_CTX_new (params, nullptr);
            if (nullptr == keyctx) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            ret_openssl = EVP_PKEY_keygen_init (keyctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            ret_openssl = EVP_PKEY_keygen (keyctx, &pkey);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            if (nullptr == pkey) { /* [openssl 3.0.3] return success but pkey is nullptr */
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            // set ASN.1 OPENSSL_EC_NAMED_CURVE flag for PEM export (PEM_write_bio_PUBKEY, PEM_write_bio_PrivateKey)
            EC_KEY_set_asn1_flag ((EC_KEY*) EVP_PKEY_get0_EC_KEY (pkey), OPENSSL_EC_NAMED_CURVE); // openssl 3.0 EVP_PKEY_get0 family return const key pointer
        } else {
            ret_openssl = EVP_PKEY_keygen_init (ctx);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
            ret_openssl = EVP_PKEY_keygen (ctx, &pkey);
            if (ret_openssl < 0) {
                ret = errorcode_t::internal_error;
                __leave2_trace (ret);
            }
        }

        if (pkey) {
            crypto_key_object_t key (pkey, use, kid, alg);
            key.set_keybits (keybits);
            ret = cryptokey->add (key);
        }
    }
    __finally2
    {
        if (keyctx) {
            EVP_PKEY_CTX_free (keyctx);
        }
        if (params) {
            EVP_PKEY_free (params);
        }

        if (ctx) {
            EVP_PKEY_CTX_free (ctx);
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec (crypto_key* cryptokey, int nid, binary_t x, binary_t y, binary_t d, crypto_use_t use)
{
    return add_ec (cryptokey, nullptr, nullptr, nid, x, y, d, use);
}

return_t crypto_keychain::add_ec (crypto_key* cryptokey, const char* kid, int nid, binary_t x, binary_t y, binary_t d, crypto_use_t use)
{
    return add_ec (cryptokey, kid, nullptr, nid, x, y, d, use);
}

return_t crypto_keychain::add_ec (crypto_key* cryptokey, const char* kid, jwa_t alg, int nid, binary_t x, binary_t y, binary_t d, crypto_use_t use)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);

    return add_ec (cryptokey, kid, hint ? hint->alg_name : nullptr, nid, x, y, d, use);
}

return_t crypto_keychain::add_ec (crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t x, binary_t y, binary_t d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    switch (nid) {
        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
            ret = add_ec_nid_EC (cryptokey, kid, alg, nid, x, y, d, use);
            break;
        case NID_X25519:
        case NID_X448:
        case NID_ED25519:
        case NID_ED448:
            ret = add_ec_nid_OKP (cryptokey, kid, alg, nid, x, d, use);
            break;
        default:
            ret = errorcode_t::request;
            break;
    }
    return ret;
}

return_t crypto_keychain::add_ec_nid_EC (crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t x, binary_t y, binary_t d, crypto_use_t use)
{
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

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bn_x = BN_bin2bn (&x[0], x.size (), nullptr);
        bn_y = BN_bin2bn (&y[0], y.size (), nullptr);
        if (d.size () > 0) {
            bn_d = BN_bin2bn (&d[0], d.size (), nullptr);
        }

        if (nullptr == bn_x && nullptr == bn_y) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        ec = EC_KEY_new_by_curve_name (nid);
        if (nullptr == ec) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        const EC_GROUP* group = EC_KEY_get0_group (ec);
        point = EC_POINT_new (group);
        if (nullptr == point) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        if (nullptr != bn_d) {
            ret_openssl = EC_KEY_set_private_key (ec, bn_d);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl (ret);
            }

            ret_openssl = EC_POINT_mul (group, point, bn_d, nullptr, nullptr, nullptr);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl (ret);
            }
        } else {
            ret_openssl = EC_POINT_set_affine_coordinates_GFp (group, point, bn_x, bn_y, nullptr);
            if (ret_openssl != 1) {
                ret = errorcode_t::internal_error;
                __leave2_trace_openssl (ret);
            }
        }

        ret_openssl = EC_KEY_set_public_key (ec, point);
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        pkey = EVP_PKEY_new ();
        EVP_PKEY_set1_EC_KEY (pkey, ec); // EC_KEY_up_ref
        if (ret_openssl != 1) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        crypto_key_object_t key (pkey, use, kid, alg);
        uint32 keybits = 0;
        switch (nid) {
            case NID_X9_62_prime256v1:
                keybits = 256;
                break;
            case NID_secp384r1:
                keybits = 384;
                break;
            case NID_secp521r1:
                keybits = 512;
                break;
        }
        key.set_keybits (keybits);

        cryptokey->add (key);
    }
    __finally2
    {
        if (ec) {
            EC_KEY_free (ec);
        }
        if (bn_x) {
            BN_clear_free (bn_x);
        }
        if (bn_y) {
            BN_clear_free (bn_y);
        }
        if (bn_d) {
            BN_clear_free (bn_d);
        }
        if (pub) {
            EC_POINT_free (pub);
        }
        if (point) {
            EC_POINT_free (point);
        }
        if (cfg) {
            BN_CTX_free (cfg);
        }

        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free (pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_ec_nid_OKP (crypto_key* cryptokey, const char* kid, const char* alg, int nid, binary_t x, binary_t d, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (d.size ()) {
            pkey = EVP_PKEY_new_raw_private_key (nid, nullptr, &d[0], d.size ());
        } else if (x.size ()) {
            pkey = EVP_PKEY_new_raw_public_key (nid, nullptr, &x[0], x.size ());
        }
        if (nullptr == pkey) {
            ret = errorcode_t::request;
            __leave2;
        }

        crypto_key_object_t key (pkey, use, kid, alg);
        uint32 keybits = 0;
        switch (nid) {
            case NID_X25519:
            case NID_X448:
                keybits = 256;
                break;
            case NID_ED25519:
            case NID_ED448:
                keybits = 448;
                break;
        }
        key.set_keybits (keybits);

        cryptokey->add (key);
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (pkey) {
                EVP_PKEY_free (pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, binary_t k, crypto_use_t use)
{
    return add_oct (cryptokey, nullptr, nullptr, k, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, binary_t k, crypto_use_t use)
{
    return add_oct (cryptokey, kid, nullptr, k, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, const char* alg, binary_t k, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        pkey = EVP_PKEY_new_mac_key (EVP_PKEY_HMAC, nullptr, &k[0], k.size ());
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        crypto_key_object_t key (pkey, use, kid, alg);
        key.set_keybits (k.size () << 3);

        ret = cryptokey->add (key);
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free (pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, jwa_t alg, binary_t k, crypto_use_t use)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);

    return add_oct (cryptokey, kid, hint ? hint->alg_name : nullptr, k, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, size_t size, crypto_use_t use)
{
    return add_oct (cryptokey, nullptr, nullptr, nullptr, size, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, size_t size, crypto_use_t use)
{
    return add_oct (cryptokey, kid, nullptr, nullptr, size, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, const char* alg, size_t size, crypto_use_t use)
{
    return add_oct (cryptokey, kid, alg, nullptr, size, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, jwa_t alg, size_t size, crypto_use_t use)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);

    return add_oct (cryptokey, kid, hint ? hint->alg_name : nullptr, size, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const byte_t* k, size_t size, crypto_use_t use)
{
    return add_oct (cryptokey, nullptr, nullptr, k, size, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, const byte_t* k, size_t size, crypto_use_t use)
{
    return add_oct (cryptokey, kid, nullptr, k, size, use);
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, const char* alg, const byte_t* k, size_t size, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    EVP_PKEY* pkey = nullptr;

    __try2
    {
        if (nullptr == cryptokey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (k) {
            pkey = EVP_PKEY_new_mac_key (EVP_PKEY_HMAC, nullptr, k, size);
        } else {
            openssl_prng r;
            binary_t temp;
            r.random (temp, size);
            pkey = EVP_PKEY_new_mac_key (EVP_PKEY_HMAC, nullptr, &temp[0], size);
        }
        if (nullptr == pkey) {
            ret = errorcode_t::internal_error;
            __leave2_trace_openssl (ret);
        }

        crypto_key_object_t key (pkey, use, kid, alg);
        key.set_keybits (size << 3);

        ret = cryptokey->add (key);
    }
    __finally2
    {
        if (errorcode_t::success != ret) {
            if (nullptr != pkey) {
                EVP_PKEY_free (pkey);
            }
        }
    }
    return ret;
}

return_t crypto_keychain::add_oct (crypto_key* cryptokey, const char* kid, jwa_t alg, const byte_t* k, size_t size, crypto_use_t use)
{
    crypto_advisor* advisor = crypto_advisor::get_instance ();
    const hint_jose_encryption_t* hint = advisor->hintof_jose_algorithm (alg);

    return add_oct (cryptokey, kid, hint ? hint->alg_name : nullptr, k, size, use);
}

}
}  // namespace
