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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/system/critical_section.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace crypto {

crypto_key::crypto_key() { _shared.make_share(this); }

crypto_key::crypto_key(const crypto_key& object) {
    _shared.make_share(this);

    _key_map = object._key_map;

    for (auto& pair : _key_map) {
        crypto_key_object& keyobj = pair.second;
        EVP_PKEY_up_ref((EVP_PKEY*)keyobj.get_pkey());
    }
}
crypto_key::crypto_key(crypto_key&& object) {
    _shared.make_share(this);

#if __cplusplus >= 201703L  // c++17
    _key_map.merge(object._key_map);
#else
    _key_map = object._key_map;
    object._key_map.clear();
#endif
}

crypto_key::~crypto_key() { clear(); }

return_t crypto_key::add(crypto_key_object key, bool up_ref) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    __try2 {
        if (nullptr == key.get_pkey()) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (crypto_use_t::use_unknown == (key.get_desc().get_use() & crypto_use_t::use_any)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_kty_t type = typeof_crypto_key(key);
        if (crypto_kty_t::kty_unknown == type) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)key.get_pkey());  // increments a reference counter
        }

        _key_map.insert(std::make_pair(key.get_desc().get_kid_str(), key));
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            EVP_PKEY_free((EVP_PKEY*)key.get_pkey());
        }
    }
    return ret;
}

return_t crypto_key::add(EVP_PKEY* pkey, const char* kid, bool up_ref) {
    return_t ret = errorcode_t::success;
    crypto_key_object key(pkey, crypto_use_t::use_any, kid, nullptr);
    ret = add(key, up_ref);
    return ret;
}

return_t crypto_key::add(EVP_PKEY* pkey, const char* kid, crypto_use_t use, bool up_ref) {
    return_t ret = errorcode_t::success;
    crypto_key_object key(pkey, use, kid, nullptr);
    ret = add(key, up_ref);
    return ret;
}

return_t crypto_key::generate_oct(int nbits, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_keychain keyset;
    ret = keyset.add_oct(this, nbits, desc);
    return ret;
}

return_t crypto_key::generate_rsa(uint32 nid, int nbits, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_keychain keyset;
    ret = keyset.add_rsa(this, nid, nbits, desc);
    return ret;
}

return_t crypto_key::generate_ec(uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_keychain keyset;
    ret = keyset.add_ec(this, nid, desc);
    return ret;
}

return_t crypto_key::generate_dh(uint32 nid, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    crypto_keychain keyset;
    ret = keyset.add_dh(this, nid, desc);
    return ret;
}

enum {
    SEARCH_KID = 0x1,
    SEARCH_KTY = 0x2,
    SEARCH_ALG = 0x4,
    SEARCH_ALT = 0x8,
};

template <typename ALGORITHM>
bool find_discriminant(crypto_key_object item, const char* kid, ALGORITHM alg, crypto_kty_t kt, crypto_kty_t alt, crypto_use_t use, uint32 flags) {
    bool ret = false;

    __try2 {
        bool cond_use = false;
        bool cond_alg = false;
        bool cond_kid = false;
        bool cond_kty = false;

        cond_use = (item.get_desc().get_use() & use);
        if (false == cond_use) {
            __leave2;
        }
        if (SEARCH_KID & flags) {
            cond_kid = (kid && (0 == strcmp(item.get_desc().get_kid_cstr(), kid)));
            if (false == cond_kid) {
                __leave2;
            }
        }
        if (SEARCH_ALG & flags) {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            cond_alg = advisor->is_kindof(item.get_pkey(), alg);
            if (false == cond_alg) {
                __leave2;
            }
        }
        if (SEARCH_KTY & flags) {
            cond_kty = (kt && is_kindof(item.get_pkey(), kt));
            if (false == cond_kty) {
                if (crypto_kty_t::kty_unknown == alt) {
                    __leave2;
                } else {
                    cond_kty = (kt && is_kindof(item.get_pkey(), alt));
                    if (false == cond_kty) {
                        __leave2;
                    }
                }
            }
        }

        ret = true;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

static bool find_discriminant(crypto_key_object item, const char* kid, const char* alg, crypto_kty_t kt, crypto_kty_t alt, crypto_use_t use, uint32 flags) {
    bool ret = false;
    crypto_advisor* advisor = crypto_advisor::get_instance();

    __try2 {
        if (alg) {
            const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm(alg);
            if (alg_info) {
                ret = find_discriminant<jwa_t>(item, kid, (jwa_t)alg_info->type, kt, alt, use, flags);
                if (ret) {
                    __leave2;
                }
            }
            const hint_signature_t* sig_info = advisor->hintof_jose_signature(alg);
            if (sig_info) {
                ret = find_discriminant<jws_t>(item, kid, typeof_jws(sig_info), kt, alt, use, flags);
                if (ret) {
                    __leave2;
                }
            }
            const hint_cose_algorithm_t* cose_info = advisor->hintof_cose_algorithm(alg);
            if (cose_info) {
                ret = find_discriminant<cose_alg_t>(item, kid, cose_info->alg, kt, alt, use, flags);
                if (ret) {
                    __leave2;
                }
            }
        } else {
            bool cond_use = false;
            bool cond_kid = false;
            bool cond_kty = false;

            cond_use = (item.get_desc().get_use() & use);
            if (false == cond_use) {
                __leave2;
            }
            if (SEARCH_KID & flags) {
                cond_kid = (kid && (0 == strcmp(item.get_desc().get_kid_cstr(), kid)));
                if (false == cond_kid) {
                    __leave2;
                }
            }
            if (SEARCH_KTY & flags) {
                cond_kty = (kt && is_kindof(item.get_pkey(), kt));
                if (false == cond_kty) {
                    if (crypto_kty_t::kty_unknown == alt) {
                        __leave2;
                    } else {
                        cond_kty = (kt && is_kindof(item.get_pkey(), alt));
                        if (false == cond_kty) {
                            __leave2;
                        }
                    }
                }
            }

            ret = true;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

const EVP_PKEY* crypto_key::any(bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    critical_section_guard guard(_lock);
    __try2 {
        if (_key_map.empty()) {
            __leave2;
        }

        crypto_key_map_t::iterator iter = _key_map.begin();
        crypto_key_object& item = iter->second;
        ret_value = item.get_pkey();

        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    critical_section_guard guard(_lock);
    __try2 {
        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant(keyobj, nullptr, nullptr, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, 0);
            if (test) {
                ret_value = keyobj.get_pkey();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(crypto_kty_t kty, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    critical_section_guard guard(_lock);
    __try2 {
        crypto_kty_t alt = crypto_kty_t::kty_unknown;
        if (crypto_kty_t::kty_ec == kty) {
            alt = crypto_kty_t::kty_okp;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant(keyobj, nullptr, nullptr, kty, alt, use, SEARCH_KTY);
            if (test) {
                ret_value = keyobj.get_pkey();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(jwa_t alg, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm(alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        crypto_kty_t kty = alg_info->kty;
        crypto_kty_t alt = alg_info->alt;

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant<jwa_t>(keyobj, nullptr, alg, kty, alt, use, SEARCH_ALG);
            if (test) {
                ret_value = keyobj.get_pkey();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(crypt_sig_t sig, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        const hint_signature_t* alg_info = advisor->hintof_signature(sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant<crypt_sig_t>(keyobj, nullptr, sig, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = keyobj.get_pkey();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(jws_t sig, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        const hint_signature_t* alg_info = advisor->hintof_jose_signature(sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant<jws_t>(keyobj, nullptr, sig, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = keyobj.get_pkey();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(std::string& kid, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    critical_section_guard guard(_lock);
    __try2 {
        kid.clear();

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant(keyobj, nullptr, nullptr, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, 0);
            if (test) {
                ret_value = keyobj.get_pkey();
                kid = keyobj.get_desc().get_kid_str();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(std::string& kid, crypto_kty_t kty, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    critical_section_guard guard(_lock);
    __try2 {
        kid.clear();

        crypto_kty_t alt = crypto_kty_t::kty_unknown;
        if (crypto_kty_t::kty_ec == kty) {
            alt = crypto_kty_t::kty_okp;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant(keyobj, nullptr, nullptr, kty, alt, use, SEARCH_KTY);
            if (test) {
                ret_value = keyobj.get_pkey();
                kid = keyobj.get_desc().get_kid_str();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(std::string& kid, jwa_t alg, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        kid.clear();

        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm(alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        crypto_kty_t kty = alg_info->kty;
        crypto_kty_t alt = alg_info->alt;

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant<jwa_t>(keyobj, nullptr, alg, kty, alt, use, SEARCH_ALG | SEARCH_KTY | SEARCH_ALT);
            if (test) {
                ret_value = keyobj.get_pkey();
                kid = keyobj.get_desc().get_kid_str();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(std::string& kid, crypt_sig_t sig, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        kid.clear();

        const hint_signature_t* alg_info = advisor->hintof_signature(sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant<crypt_sig_t>(keyobj, nullptr, sig, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = keyobj.get_pkey();
                kid = keyobj.get_desc().get_kid_str();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(std::string& kid, jws_t sig, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        kid.clear();

        const hint_signature_t* alg_info = advisor->hintof_jose_signature(sig);
        if (nullptr == alg_info) {
            __leave2;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant<jws_t>(keyobj, nullptr, sig, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = keyobj.get_pkey();
                kid = keyobj.get_desc().get_kid_str();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::select(std::string& kid, cose_alg_t alg, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        kid.clear();

        const hint_cose_algorithm_t* alg_info = advisor->hintof_cose_algorithm(alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            bool test = find_discriminant<cose_alg_t>(keyobj, nullptr, alg, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, SEARCH_ALG);
            if (test) {
                ret_value = keyobj.get_pkey();
                kid = keyobj.get_desc().get_kid_str();
                break;
            }
        }
        if (nullptr == ret_value) {
            __leave2;
        }
        if (up_ref) {
            EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::find(const char* kid, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    critical_section_guard guard(_lock);
    __try2 {
        std::string k;
        if (kid) {
            k = kid;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound(k);
            upper_bound = _key_map.upper_bound(k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object& item = iter->second;
                bool test =
                    find_discriminant(item, kid, nullptr, crypto_kty_t::kty_unknown, crypto_kty_t::kty_unknown, use, 0);  // using map, so don't care SEARCH_KID
                if (test) {
                    ret_value = item.get_pkey();
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
            }
        } else {
            ret_value = select(use, up_ref);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::find(const char* kid, crypto_kty_t kt, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    critical_section_guard guard(_lock);
    __try2 {
        std::string k;
        if (kid) {
            k = kid;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound(k);
            upper_bound = _key_map.upper_bound(k);

            crypto_kty_t alt = crypto_kty_t::kty_unknown;
            if (crypto_kty_t::kty_ec == kt) {
                alt = crypto_kty_t::kty_okp;
            }

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object& item = iter->second;
                bool test = find_discriminant(item, kid, nullptr, kt, alt, use, SEARCH_KTY);
                if (test) {
                    ret_value = item.get_pkey();
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
            }
        } else {
            ret_value = select(kt, use, up_ref);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::find(const char* kid, jwa_t alg, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        const hint_jose_encryption_t* alg_info = advisor->hintof_jose_algorithm(alg);
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

            crypto_kty_t kt = alg_info->kty;
            crypto_kty_t alt = alg_info->alt;

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound(k);
            upper_bound = _key_map.upper_bound(k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object& item = iter->second;
                bool test = find_discriminant(item, kid, alg_str, kt, alt, use, SEARCH_ALG);
                if (test) {
                    ret_value = item.get_pkey();
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
            }
        } else {
            ret_value = select(alg, use, up_ref);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::find(const char* kid, crypt_sig_t alg, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        const hint_signature_t* alg_info = advisor->hintof_signature(alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        const char* alg_str = nameof_jws(alg_info);
        if (nullptr == alg_str) {
            __leave2;
        }

        std::string k;
        if (kid) {
            k = kid;

            crypto_kty_t kt = typeof_kty(alg_info);

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound(k);
            upper_bound = _key_map.upper_bound(k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object& item = iter->second;
                bool test = find_discriminant(item, kid, alg_str, kt, crypto_kty_t::kty_unknown, use, SEARCH_ALG);
                if (test) {
                    ret_value = item.get_pkey();
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
            }
        } else {
            ret_value = select(alg, use, up_ref);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const EVP_PKEY* crypto_key::find(const char* kid, jws_t alg, crypto_use_t use, bool up_ref) {
    const EVP_PKEY* ret_value = nullptr;
    crypto_advisor* advisor = crypto_advisor::get_instance();
    critical_section_guard guard(_lock);
    __try2 {
        const hint_signature_t* alg_info = advisor->hintof_jose_signature(alg);
        if (nullptr == alg_info) {
            __leave2;
        }

        const char* alg_str = nameof_jws(alg_info);
        if (nullptr == alg_str) {
            __leave2;
        }

        std::string k;
        if (kid) {
            k = kid;

            crypto_kty_t kt = typeof_kty(alg_info);

            crypto_key_map_t::iterator iter;
            crypto_key_map_t::iterator lower_bound;
            crypto_key_map_t::iterator upper_bound;
            lower_bound = _key_map.lower_bound(k);
            upper_bound = _key_map.upper_bound(k);

            for (iter = lower_bound; iter != upper_bound; iter++) {
                crypto_key_object& item = iter->second;
                bool test = find_discriminant(item, kid, alg_str, kt, crypto_kty_t::kty_unknown, use, SEARCH_ALG);
                if (test) {
                    ret_value = item.get_pkey();
                    break;
                }
            }
            if (nullptr == ret_value) {
                __leave2;
            }
            if (up_ref) {
                EVP_PKEY_up_ref((EVP_PKEY*)ret_value);  // increments a reference counter
            }
        } else {
            ret_value = select(alg, use, up_ref);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

return_t crypto_key::get_public_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2) {
    return_t ret = errorcode_t::success;

    pub1.clear();
    pub2.clear();

    crypto_kty_t type = crypto_kty_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract(pkey, crypt_access_t::public_key, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_kty_t::kty_oct == type) {
            // do nothing
        } else if (crypto_kty_t::kty_rsa == type) {
            iter = datamap.find(crypt_item_t::item_rsa_n);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_rsa_e);
            if (datamap.end() != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_kty_t::kty_ec == type) {
            iter = datamap.find(crypt_item_t::item_ec_x);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_ec_y);
            if (datamap.end() != iter) {
                pub2 = iter->second;
            }
        } else if (crypto_kty_t::kty_okp == type) {
            iter = datamap.find(crypt_item_t::item_ec_x);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::get_private_key(const EVP_PKEY* pkey, binary_t& priv) {
    return_t ret = errorcode_t::success;

    priv.clear();

    crypto_kty_t type = crypto_kty_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;

    ret = extract(pkey, crypt_access_t::private_key, type, datamap);
    if (errorcode_t::success == ret) {
        if (crypto_kty_t::kty_oct == type) {
            iter = datamap.find(crypt_item_t::item_hmac_k);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if (crypto_kty_t::kty_rsa == type) {
            iter = datamap.find(crypt_item_t::item_rsa_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if ((crypto_kty_t::kty_ec == type) || (crypto_kty_t::kty_okp == type)) {
            iter = datamap.find(crypt_item_t::item_ec_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    crypto_kty_t type = crypto_kty_t::kty_unknown;

    return get_key(pkey, 1, type, pub1, pub2, priv, preserve);
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, int flag, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    crypto_kty_t type = crypto_kty_t::kty_unknown;

    return get_key(pkey, flag, type, pub1, pub2, priv, preserve);
}

return_t crypto_key::get_key(const EVP_PKEY* pkey, int flag, crypto_kty_t& type, binary_t& pub1, binary_t& pub2, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;

    pub1.clear();
    pub2.clear();
    priv.clear();
    type = crypto_kty_t::kty_unknown;

    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;
    int flag_request = crypt_access_t::public_key;

    if (flag) {
        flag_request |= crypt_access_t::private_key;
    }
    ret = extract(pkey, flag_request, type, datamap, preserve);
    if (errorcode_t::success == ret) {
        if (crypto_kty_t::kty_oct == type) {
            iter = datamap.find(crypt_item_t::item_hmac_k);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if (crypto_kty_t::kty_rsa == type) {
            iter = datamap.find(crypt_item_t::item_rsa_n);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_rsa_e);
            if (datamap.end() != iter) {
                pub2 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_rsa_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if (crypto_kty_t::kty_ec == type) {
            iter = datamap.find(crypt_item_t::item_ec_x);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_ec_y);
            if (datamap.end() != iter) {
                pub2 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_ec_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if (crypto_kty_t::kty_okp == type) {
            iter = datamap.find(crypt_item_t::item_ec_x);
            if (datamap.end() != iter) {
                pub1 = iter->second;
            }
            iter = datamap.find(crypt_item_t::item_ec_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::get_privkey(const EVP_PKEY* pkey, crypto_kty_t& type, binary_t& priv, bool preserve) {
    return_t ret = errorcode_t::success;

    priv.clear();

    type = crypto_kty_t::kty_unknown;
    crypt_datamap_t datamap;
    crypt_datamap_t::iterator iter;
    int flag_request = crypt_access_t::private_key;

    ret = extract(pkey, flag_request, type, datamap, preserve);
    if (errorcode_t::success == ret) {
        if (crypto_kty_t::kty_oct == type) {
            iter = datamap.find(crypt_item_t::item_hmac_k);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if (crypto_kty_t::kty_rsa == type) {
            iter = datamap.find(crypt_item_t::item_rsa_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if (crypto_kty_t::kty_ec == type) {
            iter = datamap.find(crypt_item_t::item_ec_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        } else if (crypto_kty_t::kty_okp == type) {
            iter = datamap.find(crypt_item_t::item_ec_d);
            if (datamap.end() != iter) {
                priv = iter->second;
            }
        }
    }
    return ret;
}

return_t crypto_key::extract(const EVP_PKEY* pkey, int flag, crypto_kty_t& type, crypt_datamap_t& datamap, bool preserve) {
    return_t ret = errorcode_t::success;
    int ret_openssl = 1;

    __try2 {
        datamap.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        type = typeof_crypto_key(pkey);
        if (crypto_kty_t::kty_oct == type) {
            if ((crypt_access_t::public_key | crypt_access_t::private_key) & flag) {
                size_t key_length = 0;
                binary_t bin_k;
                EVP_PKEY_get_raw_private_key(pkey, nullptr, &key_length);
                bin_k.resize(key_length);
                EVP_PKEY_get_raw_private_key(pkey, &bin_k[0], &key_length);

                datamap.insert(std::make_pair(crypt_item_t::item_hmac_k, bin_k));
            }
        } else if (crypto_kty_t::kty_rsa == type) {
            const BIGNUM* n = nullptr;
            const BIGNUM* e = nullptr;
            const BIGNUM* d = nullptr;

            const RSA* rsa = EVP_PKEY_get0_RSA((EVP_PKEY*)pkey);
            RSA_get0_key(rsa, &n, &e, &d);
            if (crypt_access_t::public_key & flag) {
                if (n && e) {
                    int len_n = BN_num_bytes(n);
                    int len_e = BN_num_bytes(e);

                    binary_t bin_n;
                    binary_t bin_e;

                    bin_n.resize(len_n);
                    bin_e.resize(len_e);

                    BN_bn2bin(n, &bin_n[0]);
                    BN_bn2bin(e, &bin_e[0]);

                    datamap.insert(std::make_pair(crypt_item_t::item_rsa_n, bin_n));
                    datamap.insert(std::make_pair(crypt_item_t::item_rsa_e, bin_e));
                }
            }
            if (crypt_access_t::private_key & flag) {
                if (d) {
                    binary_t bin_d;
                    int len_d = BN_num_bytes(d);
                    bin_d.resize(len_d);
                    BN_bn2bin(d, &bin_d[0]);
                    datamap.insert(std::make_pair(crypt_item_t::item_rsa_d, bin_d));
                }
            }
        } else if (crypto_kty_t::kty_ec == type) {
            BIGNUM* x = nullptr;
            BIGNUM* y = nullptr;
            EC_KEY* ec = nullptr;
            __try2 {
                // preserve leading zero octets
                uint32 curve_size = 0;
                if (preserve) {
                    uint32 nid = 0;
                    nidof_evp_pkey(pkey, nid);
                    switch (nid) {
                        case NID_X9_62_prime256v1:
                            curve_size = 32;
                            break;
                        case NID_secp384r1:
                            curve_size = 48;
                            break;
                        case NID_secp521r1:
                            curve_size = 66;
                            break;
                    }
                }

                if (crypt_access_t::public_key & flag) {
                    x = BN_new();
                    y = BN_new();

                    ec = EVP_PKEY_get1_EC_KEY((EVP_PKEY*)pkey);

                    const EC_GROUP* group = EC_KEY_get0_group(ec);
                    const EC_POINT* pub = EC_KEY_get0_public_key(ec);

                    ret_openssl = EC_POINT_get_affine_coordinates(group, pub, x, y, nullptr);  // EC_POINT_get_affine_coordinates_GFp
                    if (ret_openssl) {
                        int len_x = BN_num_bytes(x);
                        int len_y = BN_num_bytes(y);

                        binary_t bin_x;
                        binary_t bin_y;

                        bin_x.resize(len_x);
                        bin_y.resize(len_y);

                        BN_bn2bin(x, &bin_x[0]);
                        BN_bn2bin(y, &bin_y[0]);

                        if (curve_size) {
                            if (curve_size > len_x) {
                                bin_x.insert(bin_x.begin(), curve_size - len_x, 0);
                            }
                            if (curve_size > len_y) {
                                bin_y.insert(bin_y.begin(), curve_size - len_y, 0);
                            }
                        }

                        datamap.insert(std::make_pair(crypt_item_t::item_ec_x, bin_x));
                        datamap.insert(std::make_pair(crypt_item_t::item_ec_y, bin_y));
                    }
                }
                if (crypt_access_t::private_key & flag) {
                    const BIGNUM* d = EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY((EVP_PKEY*)pkey));
                    if (d) {
                        int len_d = BN_num_bytes(d);

                        binary_t bin_d;

                        bin_d.resize(len_d);

                        BN_bn2bin(d, &bin_d[0]);

                        if (curve_size) {
                            if (curve_size > len_d) {
                                bin_d.insert(bin_d.begin(), curve_size - len_d, 0);
                            }
                        }

                        datamap.insert(std::make_pair(crypt_item_t::item_ec_d, bin_d));
                    }
                }
            }
            __finally2 {
                if (ec) {
                    EC_KEY_free(ec);
                }
                if (x) {
                    BN_free(x);
                }
                if (y) {
                    BN_free(y);
                }
            }
        } else if (crypto_kty_t::kty_okp == type) {
            // preserve leading zero octets
            uint32 curve_size = 0;
            if (preserve) {
                uint32 nid = 0;
                nidof_evp_pkey(pkey, nid);
                switch (nid) {
                    case NID_ED25519:
                    case NID_X25519:
                        curve_size = 32;
                        break;
                    case EVP_PKEY_ED448:
                    case EVP_PKEY_X448:
                        curve_size = 57;
                        break;
                }
            }

            if (crypt_access_t::public_key & flag) {
                binary_t bin_x;
                size_t len_x = curve_size ? curve_size : 256;
                bin_x.resize(len_x);
                ret_openssl = EVP_PKEY_get_raw_public_key(pkey, &bin_x[0], &len_x);
                bin_x.resize(len_x);

                if (curve_size) {
                    if (curve_size > len_x) {
                        bin_x.insert(bin_x.begin(), curve_size - len_x, 0);
                    }
                }

                if (1 == ret_openssl) {
                    datamap.insert(std::make_pair(crypt_item_t::item_ec_x, bin_x));
                }
            }
            if (crypt_access_t::private_key & flag) {
                binary_t bin_d;
                size_t len_d = curve_size ? curve_size : 256;
                bin_d.resize(len_d);
                ret_openssl = EVP_PKEY_get_raw_private_key(pkey, &bin_d[0], &len_d);
                bin_d.resize(len_d);

                if (curve_size) {
                    if (curve_size > len_d) {
                        bin_d.insert(bin_d.begin(), curve_size - len_d, 0);
                    }
                }

                if (1 == ret_openssl) {
                    datamap.insert(std::make_pair(crypt_item_t::item_ec_d, bin_d));
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void crypto_key::clear() {
    critical_section_guard guard(_lock);
    for (auto& pair : _key_map) {
        crypto_key_object& keyobj = pair.second;
        if (keyobj.get_pkey()) {
            EVP_PKEY_free((EVP_PKEY*)keyobj.get_pkey());
        }
    }
    _key_map.clear();
}

size_t crypto_key::size() { return _key_map.size(); }

return_t crypto_key::append(crypto_key* source) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        critical_section_guard guard(_lock);
        critical_section_guard guard_source(source->_lock);
        for (auto& pair : _key_map) {
            const std::string& name = pair.first;
            crypto_key_object& keyobj = pair.second;
            EVP_PKEY_up_ref((EVP_PKEY*)keyobj.get_pkey());
            _key_map.insert(std::make_pair(name, keyobj));
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

int crypto_key::addref() { return _shared.addref(); }

int crypto_key::release() { return _shared.delref(); }

void crypto_key::for_each(std::function<void(crypto_key_object*, void*)> fp_dump, void* param) {
    critical_section_guard guard(_lock);
    __try2 {
        if (nullptr == fp_dump) {
            __leave2;
        }

        for (auto& pair : _key_map) {
            crypto_key_object& keyobj = pair.second;
            fp_dump(&keyobj, param);
        }
    }
    __finally2 {
        // do nothing
    }
}

crypto_kty_t typeof_crypto_key(crypto_key_object& key) { return typeof_crypto_key(key.get_pkey()); }

}  // namespace crypto
}  // namespace hotplace
