/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/evp_key.hpp>

namespace hotplace {
namespace crypto {

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

const EVP_PKEY* crypto_key::choose(const std::string& kid, crypto_kty_t kty, return_t& code) {
    const EVP_PKEY* pkey = nullptr;
    code = errorcode_t::not_exist;

    if (kid.empty()) {
        std::string selected_kid;
        pkey = select(selected_kid, kty);
        if (pkey) {
            code = errorcode_t::inaccurate;
        }
    } else {
        pkey = find(kid.c_str(), kty);
        if (pkey) {
            code = errorcode_t::success;
        }
    }

    return pkey;
}

}  // namespace crypto
}  // namespace hotplace
