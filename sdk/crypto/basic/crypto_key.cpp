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
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <fstream>

namespace hotplace {
namespace crypto {

crypto_key::crypto_key ()
{
    _shared.make_share (this);
}

crypto_key::~crypto_key ()
{
    clear ();
}

return_t crypto_key::load_pem (const char* buffer, int flags, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    BIO* bio_pub = BIO_new (BIO_s_mem ());
    BIO* bio_priv = BIO_new (BIO_s_mem ());

    __try2
    {
        if (nullptr == buffer) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t len = strlen (buffer);
        BIO_write (bio_pub, buffer, len);
        BIO_write (bio_priv, buffer, len);

        while (1) {
            EVP_PKEY* pkey_pub = nullptr;
            pkey_pub = PEM_read_bio_PUBKEY (bio_pub, nullptr, nullptr, nullptr);
            if (pkey_pub) {
                crypto_key_object_t key;
                key.pkey = pkey_pub;
                key.use = use;
                add (key);
            } else {
                break;
            }
        }

        while (1) {
            EVP_PKEY* pkey_priv = nullptr;
            pkey_priv = PEM_read_bio_PrivateKey (bio_priv, nullptr, nullptr, nullptr);
            if (pkey_priv) {
                crypto_key_object_t key;
                key.pkey = pkey_priv;
                key.use = use;
                add (key);
            } else {
                break;
            }
        }
    }
    __finally2
    {
        BIO_free_all (bio_pub);
        BIO_free_all (bio_priv);
    }
    return ret;
}

return_t crypto_key::load_pem_file (const char* file, int flags, crypto_use_t use)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::string buffer;
        std::ifstream fs (file);
        if (fs.is_open ()) {
            std::getline (fs, buffer, (char) fs.eof ());
        } else {
            ret = errorcode_t::failed;
            __leave2;
        }

        ret = load_pem (buffer.c_str (), flags, use);
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static void pem_writer (crypto_key_object_t* key, void* param)
{
    __try2
    {
        if (nullptr == key || nullptr == param) {
            __leave2;
        }

        BIO* out = (BIO*) param;
        EVP_PKEY* pkey = (EVP_PKEY *) key->pkey;
        int type = EVP_PKEY_id (pkey);

        if (EVP_PKEY_HMAC == type) {
            PEM_write_bio_PrivateKey (out, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        } else if (EVP_PKEY_RSA == type) {
            if (RSA_get0_d (EVP_PKEY_get0_RSA (pkey))) {
                PEM_write_bio_RSAPrivateKey (out, EVP_PKEY_get0_RSA (pkey), nullptr, nullptr, 0, nullptr, nullptr);
            } else {
                PEM_write_bio_RSAPublicKey (out, EVP_PKEY_get0_RSA (pkey));
            }
        } else if (kindof_ecc (key->pkey)) {
            const BIGNUM* bn = EC_KEY_get0_private_key (EVP_PKEY_get0_EC_KEY (pkey));
            if (bn) {
                PEM_write_bio_ECPrivateKey (out, EVP_PKEY_get0_EC_KEY (pkey), nullptr, nullptr, 0, nullptr, nullptr);
            } else {
                PEM_write_bio_EC_PUBKEY (out, EVP_PKEY_get0_EC_KEY (pkey));     // same PEM_write_bio_PUBKEY
            }
        }
    }
    __finally2
    {
        // do nothing
    }
}

return_t crypto_key::write_pem_file (const char* file, int flags)
{
    return_t ret = errorcode_t::success;
    BIO* out = nullptr;

    __try2
    {
        if (nullptr == file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        out = BIO_new (BIO_s_mem ());
        if (nullptr == out) {
            ret = errorcode_t::internal_error;
            __leave2;
        }

        for_each (pem_writer, out);

        binary_t buf;
        buf.resize (64);
        FILE* fp = fopen (file, "wt");
        if (fp) {
            int len = 0;
            while (1) {
                len = BIO_read (out, &buf[0], buf.size ());
                if (0 >= len) {
                    break;
                }
                fwrite (&buf[0], 1, len, fp);
            }
            fclose (fp);
        } else {
            ret = errorcode_t::failed;
            __leave2;
        }
    }
    __finally2
    {
        if (out) {
            BIO_free_all (out);
        }
    }
    return ret;
}

return_t crypto_key::add (crypto_key_object_t key, bool up_ref)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        _lock.enter ();

        if (nullptr == key.pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (crypto_use_t::use_unknown == (key.use & crypto_use_t::use_any)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_key_t type = typeof_crypto_key (key);
        if (crypto_key_t::kty_unknown == type) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) key.pkey); // increments a reference counter
        }

        _key_map.insert (std::make_pair (key.kid, key));
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret;
}

return_t crypto_key::add (EVP_PKEY* pkey, const char* kid, bool up_ref)
{
    return_t ret = errorcode_t::success;
    crypto_key_object_t key (pkey, crypto_use_t::use_any, kid, nullptr);

    ret = add (key, up_ref);
    return ret;
}

return_t crypto_key::add (EVP_PKEY* pkey, const char* kid, crypto_use_t use, bool up_ref)
{
    return_t ret = errorcode_t::success;
    crypto_key_object_t key (pkey, use, kid, nullptr);

    ret = add (key, up_ref);
    return ret;
}

return_t crypto_key::generate (crypto_key_t type, unsigned int param, const char* kid, crypto_use_t use)
{
    return_t ret = errorcode_t::success;
    crypto_keychain keyset;

    __try2
    {
        if (crypto_key_t::kty_hmac == type) {
            ret = keyset.add_oct (this, kid, param, use);
        } else if (crypto_key_t::kty_rsa == type) {
            ret = keyset.add_rsa (this, kid, param, use);
        } else if (crypto_key_t::kty_ec == type) {
            int nid = 0;
            switch (param) {
                case 256:
                    nid = NID_X9_62_prime256v1;
                    break;
                case 384:
                    nid = NID_secp384r1;
                    break;
                case 512: // ES512 .. human code readability
                case 521:
                    nid = NID_secp521r1;
                    break;
            }
            ret = keyset.add_ec (this, kid, nid, use);
        } else if (crypto_key_t::kty_okp == type) {
            int nid = 0;
            switch (param) {
                case 25519:
                    if (use & crypto_use_t::use_enc) {
                        nid = NID_X25519;
                    } else {
                        nid = NID_ED25519;
                    }
                    break;
                case 448:
                    if (use & crypto_use_t::use_enc) {
                        nid = NID_X448;
                    } else {
                        nid = NID_ED448;
                    }
                    break;
            }
            ret = keyset.add_ec (this, kid, nid, use);
        } else {
            ret = errorcode_t::not_supported;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

enum {
    SEARCH_KID  = 0x1,
    SEARCH_KTY  = 0x2,
    SEARCH_ALG  = 0x4,
    SEARCH_ALT  = 0x8,
};

static bool find_discriminant (crypto_key_object_t item, const char* kid, jwa_t alg, crypto_key_t kt, crypto_key_t alt, crypto_use_t use, uint32 flags)
{
    bool ret = false;

    __try2
    {
        bool cond_use = false;
        bool cond_alg = false;
        bool cond_kid = false;
        bool cond_kty = false;
        bool cond_alt = false;

        cond_use = (item.use & use);
        if (false == cond_use) {
            __leave2;
        }
        if (SEARCH_KID & flags) {
            cond_kid = (kid && (0 == strcmp (item.kid.c_str (), kid)));
            if (false == cond_kid) {
                __leave2;
            }
        }
        if (SEARCH_ALG & flags) {
            crypto_advisor* advisor = crypto_advisor::get_instance ();
            cond_alg = advisor->is_kindof (item.pkey, alg);
            if (false == cond_alg) {
                __leave2;
            }
        }
        if (SEARCH_KTY & flags) {
            cond_kty = (kt && is_kindof (item.pkey, kt));
            cond_alt = (alt && is_kindof (item.pkey, alt));
            if ((false == cond_kty) && (false == cond_alt)) {
                __leave2;
            }
        }

        ret = true;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static bool find_discriminant (crypto_key_object_t item, const char* kid, crypt_sig_t alg, crypto_key_t kt, crypto_key_t alt, crypto_use_t use, uint32 flags)
{
    bool ret = false;

    __try2
    {
        bool cond_use = false;
        bool cond_alg = false;
        bool cond_kid = false;
        bool cond_kty = false;

        cond_use = (item.use & use);
        if (false == cond_use) {
            __leave2;
        }
        if (SEARCH_KID & flags) {
            cond_kid = (kid && (0 == strcmp (item.kid.c_str (), kid)));
            if (false == cond_kid) {
                __leave2;
            }
        }
        if (SEARCH_ALG & flags) {
            crypto_advisor* advisor = crypto_advisor::get_instance ();
            cond_alg = advisor->is_kindof (item.pkey, alg);
            if (false == cond_alg) {
                __leave2;
            }
        }
        if (SEARCH_KTY & flags) {
            cond_kty = (kt && is_kindof (item.pkey, kt));
            if (false == cond_kty) {
                __leave2;
            }
        }

        ret = true;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static bool find_discriminant (crypto_key_object_t item, const char* kid, jws_t alg, crypto_key_t kt, crypto_key_t alt, crypto_use_t use, uint32 flags)
{
    bool ret = false;

    __try2
    {
        bool cond_use = false;
        bool cond_alg = false;
        bool cond_kid = false;
        bool cond_kty = false;

        cond_use = (item.use & use);
        if (false == cond_use) {
            __leave2;
        }
        if (SEARCH_KID & flags) {
            cond_kid = (kid && (0 == strcmp (item.kid.c_str (), kid)));
            if (false == cond_kid) {
                __leave2;
            }
        }
        if (SEARCH_ALG & flags) {
            crypto_advisor* advisor = crypto_advisor::get_instance ();
            cond_alg = advisor->is_kindof (item.pkey, alg);
            if (false == cond_alg) {
                __leave2;
            }
        }
        if (SEARCH_KTY & flags) {
            cond_kty = (kt && is_kindof (item.pkey, kt));
            if (false == cond_kty) {
                __leave2;
            }
        }

        ret = true;
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

static bool find_discriminant (crypto_key_object_t item, const char* kid, const char* alg, crypto_key_t kt, crypto_key_t alt, crypto_use_t use, uint32 flags)
{
    bool ret = false;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        if (alg) {
            const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);
            if (alg_info) {
                ret = find_discriminant (item, kid, (jwa_t) alg_info->type, kt, alt, use, flags);
                if (ret) {
                    __leave2;
                }
            }
            const hint_signature_t* sig_info = advisor->hintof_jose_signature (alg);
            if (sig_info) {
                ret = find_discriminant (item, kid, sig_info->jws_type, kt, alt, use, flags);
                if (ret) {
                    __leave2;
                }
            }
        } else {
            bool cond_use = false;
            bool cond_kid = false;
            bool cond_kty = false;

            cond_use = (item.use & use);
            if (false == cond_use) {
                __leave2;
            }
            if (SEARCH_KID & flags) {
                cond_kid = (kid && (0 == strcmp (item.kid.c_str (), kid)));
                if (false == cond_kid) {
                    __leave2;
                }
            }
            if (SEARCH_KTY & flags) {
                cond_kty = (kt && is_kindof (item.pkey, kt));
                if (false == cond_kty) {
                    __leave2;
                }
            }

            ret = true;
        }
    }
    __finally2
    {
        // do nothing
    }

    return ret;
}

EVP_PKEY* crypto_key::any (bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;

    __try2
    {
        _lock.enter ();

        if (_key_map.empty ()) {
            __leave2;
        }

        crypto_key_map_t::iterator iter = _key_map.begin ();
        crypto_key_object_t& item = iter->second;
        ret_value = item.pkey;

        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;

    __try2
    {
        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, crypto_key_t::kty_unknown, crypto_key_t::kty_unknown, use, 0);
            if (test) {
                ret_value = item.pkey;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (crypto_key_t kty, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;

    __try2
    {
        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, kty, crypto_key_t::kty_unknown, use, SEARCH_KTY);
            if (test) {
                ret_value = item.pkey;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (jwa_t alg, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        crypto_key_t kty = alg_info->kty;
        crypto_key_t alt = alg_info->alt;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, alg, kty, alt, use, SEARCH_ALG);
            if (test) {
                ret_value = item.pkey;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (crypt_sig_t sig, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_signature_t* alg_info = advisor->hintof_signature (sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        //crypto_key_t kty = alg_info->kty;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, sig, crypto_key_t::kty_unknown, crypto_key_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = item.pkey;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (jws_t sig, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_signature_t* alg_info = advisor->hintof_jose_signature (sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        //crypto_key_t kty = alg_info->kty;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, sig, crypto_key_t::kty_unknown, crypto_key_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = item.pkey;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (std::string& kid, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;

    __try2
    {
        kid.clear ();

        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, crypto_key_t::kty_unknown, crypto_key_t::kty_unknown, use, 0);
            if (test) {
                ret_value = item.pkey;
                kid = item.kid;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (std::string& kid, crypto_key_t kty, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;

    __try2
    {
        kid.clear ();

        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, kty, crypto_key_t::kty_unknown, use, SEARCH_KTY);
            if (test) {
                ret_value = item.pkey;
                kid = item.kid;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (std::string& kid, jwa_t alg, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        kid.clear ();

        _lock.enter ();

        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        crypto_key_t kty = alg_info->kty;
        crypto_key_t alt = alg_info->alt;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, alg, kty, alt, use, SEARCH_ALG | SEARCH_KTY | SEARCH_ALT);
            if (test) {
                ret_value = item.pkey;
                kid = item.kid;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (std::string& kid, crypt_sig_t sig, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        kid.clear ();

        _lock.enter ();

        const hint_signature_t* alg_info = advisor->hintof_signature (sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        //crypto_key_t kty = alg_info->kty;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, sig, crypto_key_t::kty_unknown, crypto_key_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = item.pkey;
                kid = item.kid;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::select (std::string& kid, jws_t sig, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        kid.clear ();

        _lock.enter ();

        const hint_signature_t* alg_info = advisor->hintof_jose_signature (sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        //crypto_key_t kty = alg_info->kty;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, sig, crypto_key_t::kty_unknown, crypto_key_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = item.pkey;
                kid = item.kid;
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::find (const char* kid, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;

    __try2
    {
        _lock.enter ();

        std::string k;
        if (kid) {
            k = kid;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound (k);
            upper_bound = _key_map.upper_bound (k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object_t& item = iter->second;
                bool test = find_discriminant (item, kid, nullptr, crypto_key_t::kty_unknown, crypto_key_t::kty_unknown, use, 0); // using map, so don't care SEARCH_KID
                if (test) {
                    ret_value = item.pkey;
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
            }
        } else {
            ret_value = select (use, up_ref);
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::find (const char* kid, crypto_key_t kt, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;

    __try2
    {
        _lock.enter ();

        std::string k;
        if (kid) {
            k = kid;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound (k);
            upper_bound = _key_map.upper_bound (k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object_t& item = iter->second;
                bool test = find_discriminant (item, kid, nullptr, kt, crypto_key_t::kty_unknown, use, SEARCH_KTY);
                if (test) {
                    ret_value = item.pkey;
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
            }
        } else {
            ret_value = select (kt, use, up_ref);
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::find (const char* kid, jwa_t alg, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm (alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        const char* alg_str = alg_info->alg_name;
        if (nullptr == alg_str) {
            __leave2;
        }

        std::string k;
        if (kid) {
            k = kid;

            crypto_key_t kt = alg_info->kty;
            crypto_key_t alt = alg_info->alt;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound (k);
            upper_bound = _key_map.upper_bound (k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object_t& item = iter->second;
                bool test = find_discriminant (item, kid, alg_str, kt, alt, use, SEARCH_ALG);
                if (test) {
                    ret_value = item.pkey;
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
            }
        } else {
            ret_value = select (alg, use, up_ref);
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::find (const char* kid, crypt_sig_t alg, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_signature_t* alg_info = advisor->hintof_signature (alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        const char* alg_str = alg_info->jws_name;
        if (nullptr == alg_str) {
            __leave2;
        }

        std::string k;
        if (kid) {
            k = kid;

            crypto_key_t kt = alg_info->kty;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound (k);
            upper_bound = _key_map.upper_bound (k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object_t& item = iter->second;
                bool test = find_discriminant (item, kid, alg_str, kt, crypto_key_t::kty_unknown, use, SEARCH_ALG);
                if (test) {
                    ret_value = item.pkey;
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
            }
        } else {
            ret_value = select (alg, use, up_ref);
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

EVP_PKEY* crypto_key::find (const char* kid, jws_t alg, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_signature_t* alg_info = advisor->hintof_jose_signature (alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        const char* alg_str = alg_info->jws_name;
        if (nullptr == alg_str) {
            __leave2;
        }

        std::string k;
        if (kid) {
            k = kid;

            crypto_key_t kt = alg_info->kty;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound (k);
            upper_bound = _key_map.upper_bound (k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object_t& item = iter->second;
                bool test = find_discriminant (item, kid, alg_str, kt, crypto_key_t::kty_unknown, use, SEARCH_ALG);
                if (test) {
                    ret_value = item.pkey;
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref ((EVP_PKEY*) ret_value); // increments a reference counter
            }
        } else {
            ret_value = select (alg, use, up_ref);
        }
    }
    __finally2
    {
        _lock.leave ();
    }
    return ret_value;
}

return_t crypto_key::get_public_key (EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2)
{
    return_t ret = errorcode_t::success;

    pub1.clear ();
    pub2.clear ();

    crypto_key_t type = crypto_key_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract (pkey, crypt_access_t::public_key, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_key_t::kty_hmac == type) {
            // do nothing
        } else if (crypto_key_t::kty_rsa == type) {
            iter = datamap.find (crypt_item_t::item_rsa_n);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_rsa_e);
            if (datamap.end () != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_key_t::kty_ec == type) {
            iter = datamap.find (crypt_item_t::item_ec_x);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_ec_y);
            if (datamap.end () != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_key_t::kty_okp == type) {
            iter = datamap.find (crypt_item_t::item_ec_x);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::get_private_key (EVP_PKEY* pkey, binary_t& priv)
{
    return_t ret = errorcode_t::success;

    priv.clear ();

    crypto_key_t type = crypto_key_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract (pkey, crypt_access_t::private_key, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_key_t::kty_hmac == type) {
            iter = datamap.find (crypt_item_t::item_hmac_k);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if (crypto_key_t::kty_rsa == type) {
            iter = datamap.find (crypt_item_t::item_rsa_d);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if ((crypto_key_t::kty_ec == type) || (crypto_key_t::kty_okp == type)) {
            iter = datamap.find (crypt_item_t::item_ec_d);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::get_key (EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2, binary_t& priv)
{
    crypto_key_t type = crypto_key_t::kty_unknown;

    return get_key (pkey, 1, type, pub1, pub2, priv);
}

return_t crypto_key::get_key (EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv)
{
    crypto_key_t type = crypto_key_t::kty_unknown;

    return get_key (pkey, flag, type, pub1, pub2, priv);
}

return_t crypto_key::get_key (EVP_PKEY* pkey, int flag, crypto_key_t& type,
                              binary_t& pub1, binary_t& pub2, binary_t& priv)
{
    return_t ret = errorcode_t::success;

    pub1.clear ();
    pub2.clear ();
    priv.clear ();
    type = crypto_key_t::kty_unknown;

    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;
    int flag_request = crypt_access_t::public_key;

    if (flag) {
        flag_request |= crypt_access_t::private_key;
    }
    ret = extract (pkey, flag_request, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_key_t::kty_hmac == type) {
            iter = datamap.find (crypt_item_t::item_hmac_k);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if (crypto_key_t::kty_rsa == type) {
            iter = datamap.find (crypt_item_t::item_rsa_n);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_rsa_e);
            if (datamap.end () != iter) {
                pub2 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_rsa_d);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if (crypto_key_t::kty_ec == type) {
            iter = datamap.find (crypt_item_t::item_ec_x);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_ec_y);
            if (datamap.end () != iter) {
                pub2 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_ec_d);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if (crypto_key_t::kty_okp == type) {
            iter = datamap.find (crypt_item_t::item_ec_x);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_ec_d);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::extract (EVP_PKEY* pkey, int flag, crypto_key_t& type, crypt_datamap_t& datamap)
{
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;

    __try2
    {
        datamap.clear ();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = typeof_crypto_key (pkey);
        if (crypto_key_t::kty_hmac == type) {
            if ((crypt_access_t::public_key | crypt_access_t::private_key) & flag) {
                size_t key_length = 0;
                binary_t bin_k;
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, nullptr, &key_length);
                bin_k.resize (key_length);
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, &bin_k [0], &key_length);

                datamap.insert (std::make_pair (crypt_item_t::item_hmac_k, bin_k));
            }
        } else if (crypto_key_t::kty_rsa == type) {
            const BIGNUM* n = nullptr;
            const BIGNUM* e = nullptr;
            const BIGNUM* d = nullptr;

            const RSA* rsa = EVP_PKEY_get0_RSA (pkey);
            RSA_get0_key (rsa, &n, &e, &d);
            if (crypt_access_t::public_key & flag) {
                if (n && e) {
                    int len_n = BN_num_bytes (n);
                    int len_e = BN_num_bytes (e);

                    binary_t bin_n;
                    binary_t bin_e;

                    bin_n.resize (len_n);
                    bin_e.resize (len_e);

                    BN_bn2bin (n, &bin_n[0]);
                    BN_bn2bin (e, &bin_e[0]);

                    datamap.insert (std::make_pair (crypt_item_t::item_rsa_n, bin_n));
                    datamap.insert (std::make_pair (crypt_item_t::item_rsa_e, bin_e));
                }
            }
            if (crypt_access_t::private_key & flag) {
                if (d) {
                    binary_t bin_d;
                    int len_d = BN_num_bytes (d);
                    bin_d.resize (len_d);
                    BN_bn2bin (d, &bin_d[0]);
                    datamap.insert (std::make_pair (crypt_item_t::item_rsa_d, bin_d));
                }
            }
        } else if (crypto_key_t::kty_ec == type) {
            BIGNUM* x = nullptr;
            BIGNUM* y = nullptr;
            EC_KEY* ec = nullptr;
            __try2
            {
                if (crypt_access_t::public_key & flag) {

                    x = BN_new ();
                    y = BN_new ();

                    ec = EVP_PKEY_get1_EC_KEY ((EVP_PKEY*) pkey);

                    const EC_GROUP* group = EC_KEY_get0_group (ec);
                    const EC_POINT *pub = EC_KEY_get0_public_key (ec);

                    ret_openssl = EC_POINT_get_affine_coordinates_GFp (group, pub, x, y, nullptr);
                    if (ret_openssl) {
                        int len_x = BN_num_bytes (x);
                        int len_y = BN_num_bytes (y);

                        binary_t bin_x;
                        binary_t bin_y;

                        bin_x.resize (len_x);
                        bin_y.resize (len_y);

                        BN_bn2bin (x, &bin_x[0]);
                        BN_bn2bin (y, &bin_y[0]);

                        datamap.insert (std::make_pair (crypt_item_t::item_ec_x, bin_x));
                        datamap.insert (std::make_pair (crypt_item_t::item_ec_y, bin_y));
                    }
                }
                if (crypt_access_t::private_key & flag) {
                    const BIGNUM* d = EC_KEY_get0_private_key (EVP_PKEY_get0_EC_KEY ((EVP_PKEY*) pkey));
                    if (d) {
                        int len_d = BN_num_bytes (d);
                        binary_t bin_d;
                        bin_d.resize (len_d);
                        BN_bn2bin (d, &bin_d[0]);

                        datamap.insert (std::make_pair (crypt_item_t::item_ec_d, bin_d));
                    }
                }
            }
            __finally2
            {
                if (ec) {
                    EC_KEY_free (ec);
                }
                if (x) {
                    BN_free (x);
                }
                if (y) {
                    BN_free (y);
                }
            }
        } else if (crypto_key_t::kty_okp == type) {
            binary_t buf;
            size_t bufsize = 256;
            buf.resize (bufsize);
            if (crypt_access_t::public_key & flag) {
                ret_openssl = EVP_PKEY_get_raw_public_key ((EVP_PKEY*) pkey, &buf[0], &bufsize);
                buf.resize (bufsize);
                if (1 == ret_openssl) {
                    datamap.insert (std::make_pair (crypt_item_t::item_ec_x, buf));
                }
            }
            if (crypt_access_t::private_key & flag) {
                ret_openssl = EVP_PKEY_get_raw_private_key ((EVP_PKEY*) pkey, &buf[0], &bufsize);
                buf.resize (bufsize);
                if (1 == ret_openssl) {
                    datamap.insert (std::make_pair (crypt_item_t::item_ec_d, buf));
                }
            }
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

void crypto_key::clear ()
{
    _lock.enter ();
    crypto_key_map_t::iterator iter;
    for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
        crypto_key_object_t& item = iter->second;

        if (item.pkey) {
            EVP_PKEY_free ((EVP_PKEY *) item.pkey);
        }
    }
    _key_map.clear ();
    _lock.leave ();
}

size_t crypto_key::size ()
{
    return _key_map.size ();
}

int crypto_key::addref ()
{
    return _shared.addref ();
}

int crypto_key::release ()
{
    return _shared.delref ();
}

void crypto_key::for_each (void (*fp_dump)(crypto_key_object_t*, void*), void* param)
{
    __try2
    {
        _lock.enter ();

        if (nullptr == fp_dump) {
            __leave2;
        }

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;

            (*fp_dump)(&item, param);
        }
    }
    __finally2
    {
        _lock.leave ();
    }
}

crypto_key_t typeof_crypto_key (crypto_key_object_t const& key)
{
    return typeof_crypto_key (key.pkey);
}

bool is_kindof (EVP_PKEY* pkey, crypto_key_t type)
{
    bool test = false;
    crypto_key_t kty = typeof_crypto_key (pkey);

    test = (kty == type);
    return test;
}

}
}  // namespace
