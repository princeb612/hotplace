/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

//#include <hotplace/sdk/crypto/openssl/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/openssl/crypto_key.hpp>
#include <hotplace/sdk/crypto/openssl/openssl_prng.hpp>
//#include <hotplace/sdk/crypto/openssl/openssl_sdk.hpp>
//#include <hotplace/sdk/io/string/string.hpp>

namespace hotplace {
namespace crypto {

crypto_key::crypto_key ()
{
    _shared.make_share (this);
}

crypto_key::~crypto_key ()
{
    clear ();
    // do nothing
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
        if (crypto_key_t::none_key == type) {
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
        if (crypto_key_t::hmac_key == type) {
            ret = keyset.add_oct (this, kid, param, use);
        } else if (crypto_key_t::rsa_key == type) {
            ret = keyset.add_rsa (this, kid, param, use);
        } else if (crypto_key_t::ec_key == type) {
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
        } else if (crypto_key_t::okp_key == type) {
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
            const hint_jose_signature_t* sig_info = advisor->hintof_jose_signature (alg);
            if (sig_info) {
                ret = find_discriminant (item, kid, sig_info->sig, kt, alt, use, flags);
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

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

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

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, crypto_key_t::none_key, crypto_key_t::none_key, use, 0);
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

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, kty, crypto_key_t::none_key, use, SEARCH_KTY);
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

EVP_PKEY* crypto_key::select (jws_t sig, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_jose_signature_t* alg_info = advisor->hintof_jose_signature (sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        //crypto_key_t kty = alg_info->kty;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, sig, crypto_key_t::none_key, crypto_key_t::none_key, use, SEARCH_ALG);
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

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        kid.clear ();

        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, crypto_key_t::none_key, crypto_key_t::none_key, use, 0);
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

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        kid.clear ();

        _lock.enter ();

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, nullptr, kty, crypto_key_t::none_key, use, SEARCH_KTY);
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

EVP_PKEY* crypto_key::select (std::string& kid, jws_t sig, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        kid.clear ();

        _lock.enter ();

        const hint_jose_signature_t* alg_info = advisor->hintof_jose_signature (sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        //crypto_key_t kty = alg_info->kty;

        crypto_key_map_t::iterator iter;
        for (iter = _key_map.begin (); iter != _key_map.end (); iter++) {
            crypto_key_object_t& item = iter->second;
            bool test = find_discriminant (item, nullptr, sig, crypto_key_t::none_key, crypto_key_t::none_key, use, SEARCH_ALG);
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

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

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
                bool test = find_discriminant (item, kid, nullptr, crypto_key_t::none_key, crypto_key_t::none_key, use, 0); // using map, so don't care SEARCH_KID
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

    //crypto_advisor* advisor = crypto_advisor::get_instance ();

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
                bool test = find_discriminant (item, kid, nullptr, kt, crypto_key_t::none_key, use, SEARCH_KTY);
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

EVP_PKEY* crypto_key::find (const char* kid, jws_t alg, crypto_use_t use, bool up_ref)
{
    EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance ();

    __try2
    {
        _lock.enter ();

        const hint_jose_signature_t* alg_info = advisor->hintof_jose_signature (alg);
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

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound (k);
            upper_bound = _key_map.upper_bound (k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object_t& item = iter->second;
                bool test = find_discriminant (item, kid, alg_str, kt, crypto_key_t::none_key, use, SEARCH_ALG);
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

    crypto_key_t type = crypto_key_t::none_key;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract (pkey, crypt_access_t::public_key, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_key_t::hmac_key == type) {
            // do nothing
        } else if (crypto_key_t::rsa_key == type) {
            iter = datamap.find (crypt_item_t::item_rsa_n);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_rsa_e);
            if (datamap.end () != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_key_t::ec_key == type) {
            iter = datamap.find (crypt_item_t::item_ec_x);
            if (datamap.end () != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find (crypt_item_t::item_ec_y);
            if (datamap.end () != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_key_t::okp_key == type) {
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

    crypto_key_t type = crypto_key_t::none_key;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract (pkey, crypt_access_t::private_key, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_key_t::hmac_key == type) {
            iter = datamap.find (crypt_item_t::item_hmac_k);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if (crypto_key_t::rsa_key == type) {
            iter = datamap.find (crypt_item_t::item_rsa_d);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if ((crypto_key_t::ec_key == type) || (crypto_key_t::okp_key == type)) {
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
    crypto_key_t type = crypto_key_t::none_key;

    return get_key (pkey, 1, type, pub1, pub2, priv);
}

return_t crypto_key::get_key (EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv)
{
    crypto_key_t type = crypto_key_t::none_key;

    return get_key (pkey, flag, type, pub1, pub2, priv);
}

return_t crypto_key::get_key (EVP_PKEY* pkey, int flag, crypto_key_t& type,
                              binary_t& pub1, binary_t& pub2, binary_t& priv)
{
    return_t ret = errorcode_t::success;

    pub1.clear ();
    pub2.clear ();
    priv.clear ();
    type = crypto_key_t::none_key;

    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;
    int flag_request = crypt_access_t::public_key;

    if (flag) {
        flag_request |= crypt_access_t::private_key;
    }
    ret = extract (pkey, flag_request, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_key_t::hmac_key == type) {
            iter = datamap.find (crypt_item_t::item_hmac_k);
            if (datamap.end () != iter) {
                priv = iter->second;
            }
        } else if (crypto_key_t::rsa_key == type) {
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
        } else if (crypto_key_t::ec_key == type) {
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
        } else if (crypto_key_t::okp_key == type) {
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
        if (crypto_key_t::hmac_key == type) {
            if ((crypt_access_t::public_key | crypt_access_t::private_key) & flag) {
                size_t key_length = 0;
                binary_t bin_k;
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, nullptr, &key_length);
                bin_k.resize (key_length);
                EVP_PKEY_get_raw_private_key ((EVP_PKEY *) pkey, &bin_k [0], &key_length);

                datamap.insert (std::make_pair (crypt_item_t::item_hmac_k, bin_k));
            }
        } else if (crypto_key_t::rsa_key == type) {
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
        } else if (crypto_key_t::ec_key == type) {
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
        } else if (crypto_key_t::okp_key == type) {
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

crypto_key_t typeof_crypto_key (crypto_key_object_t key)
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
