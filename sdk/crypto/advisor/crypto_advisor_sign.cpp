/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_advisor_sign.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/utility.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>

namespace hotplace {
namespace crypto {

hash_algorithm_t crypto_advisor::get_algorithm(signature_t sig) {
    hash_algorithm_t ret_value = hash_algorithm_t{};
    const hint_signature_t* item = nullptr;
    t_maphint<signature_t, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = item->alg;
    }
    return ret_value;
}

hash_algorithm_t crypto_advisor::get_algorithm(jws_t sig) {
    hash_algorithm_t ret_value = hash_algorithm_t{};
    const hint_signature_t* item = nullptr;
    t_maphint<jws_t, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = item->alg;
    }
    return ret_value;
}

const hint_signature_t* crypto_advisor::hintof_signature(signature_t sig) {
    const hint_signature_t* item = nullptr;
    t_maphint<signature_t, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    return item;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, signature_t sig) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        crypto_kty_t kty = kty_unknown;
        uint32 nid = 0;
        ktyof_evp_pkey(pkey, kty, nid);

        const hint_signature_t* hint = hintof_signature(sig);
        bool cond1 = (hint->sig == sig);
        if (false == cond1) {
            __leave2;
        }
        bool cond2 = (hint->kty == kty);
        if (false == cond2) {
            __leave2;
        }
        bool cond3 = false;
        for (uint32 i = 0; i < hint->count; i++) {
            if (hint->nid[i] == nid) {
                cond3 = true;
                break;
            }
        }
        test = (cond1 && cond2 && cond3);
    }
    __finally2 {}
    return test;
}

uint16 crypto_advisor::unitsizeof_ecdsa(hash_algorithm_t alg) {
    uint16 ret_value = 0;
    switch (alg) {
        case hash_algorithm_t::sha1:
            ret_value = 20;
            break;
        case hash_algorithm_t::sha2_224:
            ret_value = 28;
            break;
        case hash_algorithm_t::sha2_256:
            ret_value = 32;
            break;
        case hash_algorithm_t::sha2_384:
            ret_value = 48;
            break;
        case hash_algorithm_t::sha2_512:
            ret_value = 66;
            break;
        case hash_algorithm_t::sha2_512_224:
            ret_value = 28;
            break;
        case hash_algorithm_t::sha2_512_256:
            ret_value = 32;
            break;
        default:
            break;
    }
    return ret_value;
}

uint16 crypto_advisor::sizeof_ecdsa(hash_algorithm_t alg) { return unitsizeof_ecdsa(alg) << 1; }

uint16 crypto_advisor::sizeof_signature(signature_t sig) {
    uint16 ret_value = 0;
    auto hint = hintof_sigscheme(sig);
    if (hint) {
        ret_value = hint->size.signature;  // kty_ec, kty_okp, kty_mldsa, kty_slhdsa
        if (hint->kty == kty_ec) {
            ret_value <<= 1;
        }
    }
    return ret_value;
}

// hint_sigscheme_t
const hint_sigscheme_t* crypto_advisor::hintof_sigscheme(signature_t scheme) {
    const hint_sigscheme_t* item = nullptr;
    t_maphint<signature_t, const hint_sigscheme_t*> hint(_hint_signature_map);
    hint.find(scheme, &item);
    return item;
}

const hint_sigscheme_t* crypto_advisor::hintof_sigscheme(tls_sigscheme_t scheme) {
    const hint_sigscheme_t* item = nullptr;
    t_maphint<tls_sigscheme_t, const hint_sigscheme_t*> hint(_hint_sigscheme_map);
    hint.find(scheme, &item);
    return item;
}

const hint_sigscheme_t* crypto_advisor::hintof_sig_nid(uint32 nid) {
    const hint_sigscheme_t* item = nullptr;
    t_maphint<uint32, const hint_sigscheme_t*> hint(_hint_sigscheme_nid_map);
    hint.find(nid, &item);
    return item;
}

const hint_sigscheme_t* crypto_advisor::hintof_sigscheme(const char* name) {
    const hint_sigscheme_t* item = nullptr;
    if (name) {
        t_maphint<std::string, const hint_sigscheme_t*> hint(_hint_sigscheme_name_map);
        hint.find(name, &item);
    }
    return item;
}

const hint_sigscheme_t* crypto_advisor::hintof_sigscheme(const std::string& name) {
    const hint_sigscheme_t* item = nullptr;
    t_maphint<std::string, const hint_sigscheme_t*> hint(_hint_sigscheme_name_map);
    hint.find(name, &item);
    return item;
}

return_t crypto_advisor::for_each_sigscheme(std::function<void(tls_sigscheme_t, uint32)> f) {
    return_t ret = errorcode_t::success;
    for (size_t i = 0; i < sizeof_hint_sigschemes; ++i) {
        const auto& item = hint_sigschemes + i;
        auto spec = query_feature(item->name, advisor_feature_sigscheme);
        f(item->scheme, spec);
    }
    return ret;
}

return_t crypto_advisor::for_each_sigscheme(std::function<void(const hint_sigscheme_t*)> f) {
    return_t ret = errorcode_t::success;
    for (size_t i = 0; i < sizeof_hint_sigschemes; ++i) {
        const auto& item = hint_sigschemes + i;
        f(item);
    }
    return ret;
}

// hint_signature_t

sig_category_t categoryof(const hint_signature_t* hint) {
    sig_category_t type = sig_category_t{};
    if (hint) {
        type = hint->category;
    }
    return type;
}

signature_t typeof_sig(const hint_signature_t* hint) {
    signature_t type = signature_t{};
    if (hint) {
        type = hint->sig;
    }
    return type;
}

jws_t typeof_jws(const hint_signature_t* hint) {
    jws_t type = jws_unknown;
    if (hint) {
        type = hint->jws_type;
    }
    return type;
}

crypto_kty_t typeof_kty(const hint_signature_t* hint) {
    crypto_kty_t type = kty_unknown;
    if (hint) {
        type = hint->kty;
    }
    return type;
}

const char* nameof_jws(const hint_signature_t* hint) {
    const char* name = nullptr;
    if (hint) {
        name = hint->jws_name;
    }
    return name;
}

hash_algorithm_t typeof_alg(const hint_signature_t* hint) {
    hash_algorithm_t type = hash_algorithm_t{};
    if (hint) {
        type = hint->alg;
    }
    return type;
}

}  // namespace crypto
}  // namespace hotplace
