/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_advisor_jose.cpp
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

return_t crypto_advisor::for_each_jwa(std::function<void(const hint_jose_encryption_t*)> f) {
    return_t ret = errorcode_t::success;

    auto lambda = [&](const hint_jose_encryption_t& item) { return f(&item); };
    std::for_each(hint_jose_algorithms, hint_jose_algorithms + sizeof_hint_jose_algorithms, lambda);
    return ret;
}

return_t crypto_advisor::for_each_jwe(std::function<void(const hint_jose_encryption_t*)> f) {
    return_t ret = errorcode_t::success;

    auto lambda = [&](const hint_jose_encryption_t& item) { return f(&item); };
    std::for_each(hint_jose_encryptions, hint_jose_encryptions + sizeof_hint_jose_encryptions, lambda);
    return ret;
}

return_t crypto_advisor::for_each_jws(std::function<void(const hint_signature_t*)> f) {
    return_t ret = errorcode_t::success;

    auto lambda = [&](const hint_signature_t& item) { return f(&item); };
    std::for_each(hint_signatures, hint_signatures + sizeof_hint_signatures, lambda);
    return ret;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm(jwa_t alg) {
    const hint_jose_encryption_t* item = nullptr;
    t_maphint<jwa_t, const hint_jose_encryption_t*> hint(_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption(jwe_t enc) {
    const hint_jose_encryption_t* item = nullptr;
    t_maphint<jwe_t, const hint_jose_encryption_t*> hint(_enc_map);

    hint.find(enc, &item);
    return item;
}

const hint_signature_t* crypto_advisor::hintof_jose_signature(jws_t sig) {
    const hint_signature_t* item = nullptr;
    t_maphint<jws_t, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm(const char* alg) {
    const hint_jose_encryption_t* item = nullptr;

    if (alg) {
        t_maphint<std::string, const hint_jose_encryption_t*> hint(_alg_byname_map);
        hint.find(alg, &item);
    }

    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption(const char* enc) {
    const hint_jose_encryption_t* item = nullptr;

    if (enc) {
        t_maphint<std::string, const hint_jose_encryption_t*> hint(_enc_byname_map);
        hint.find(enc, &item);
    }

    return item;
}

const hint_signature_t* crypto_advisor::hintof_jose_signature(const char* sig) {
    const hint_signature_t* item = nullptr;

    if (sig) {
        t_maphint<std::string, const hint_signature_t*> hint(_sig_byname_map);
        hint.find(sig, &item);
    }
    return item;
}

const char* crypto_advisor::nameof_jose_algorithm(jwa_t alg) {
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_algorithm(alg);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_encryption(jwe_t enc) {
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_encryption(enc);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_signature(jws_t sig) {
    const char* name = nullptr;

    const hint_signature_t* item = hintof_jose_signature(sig);

    if (item) {
        name = item->jws_name;
    }
    return name;
}

return_t crypto_advisor::typeof_jose_algorithm(const char* alg, jwa_t& type) {
    return_t ret = errorcode_t::success;

    type = jwa_t::unknown;
    const hint_jose_encryption_t* item = hintof_jose_algorithm(alg);

    if (item) {
        type = item->u.alg.type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_encryption(const char* enc, jwe_t& type) {
    return_t ret = errorcode_t::success;

    type = jwe_t::unknown;
    const hint_jose_encryption_t* item = hintof_jose_encryption(enc);

    if (item) {
        type = item->u.enc.type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_signature(const char* sig, jws_t& type) {
    return_t ret = errorcode_t::success;

    type = jws_t::unknown;
    const hint_signature_t* item = hintof_jose_signature(sig);

    if (item) {
        type = (jws_t)item->jws_type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, jwa_t alg) {
    bool test = false;

    __try2 {
        const hint_jose_encryption_t* hint_enc = hintof_jose_algorithm(alg);
        if (nullptr == hint_enc) {
            __leave2;
        }

        crypto_kty_t kty = kty_unknown;
        uint32 nid = 0;
        ktyof_evp_pkey(pkey, kty, nid);

        bool cmp1 = (hint_enc->kty == kty);
        bool cmp2 = (hint_enc->alt == crypto_kty_t::kty_unknown) ? true : (hint_enc->alt == kty);
        test = (cmp1 || cmp2);
    }
    __finally2 {}
    return test;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, jws_t sig) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        crypto_kty_t kty = kty_unknown;
        uint32 nid = 0;
        ktyof_evp_pkey(pkey, kty, nid);

        const hint_signature_t* hint = hintof_jose_signature(sig);
        bool cond1 = (hint->jws_type == sig);
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

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, const char* alg) {
    bool test = false;

    __try2 {
        const hint_jose_encryption_t* hint_alg = hintof_jose_algorithm(alg);
        if (hint_alg) {
            if (hint_alg->htype == jose_hint_type_t::jwa) {
                test = is_kindof(pkey, hint_alg->u.alg.type);
                if (test) {
                    __leave2;
                }
            }
        }
        const hint_signature_t* hint_sig = hintof_jose_signature(alg);
        if (hint_sig) {
            test = is_kindof(pkey, hint_sig->jws_type);
            if (test) {
                __leave2;
            }
        }
    }
    __finally2 {}
    return test;
}

jws_t crypto_advisor::sigof(signature_t sig) {
    jws_t type = jws_t::unknown;
    t_maphint<signature_t, jws_t> hint(_sig2jws_map);

    hint.find(sig, &type);
    return type;
}

signature_t crypto_advisor::sigof(jws_t sig) {
    signature_t type = signature_t{};
    t_maphint<jws_t, signature_t> hint(_jws2sig_map);

    hint.find(sig, &type);
    return type;
}

// hint_jose_encryption_t

const char* nameof_alg(const hint_jose_encryption_t* hint) {
    const char* ret_value = nullptr;
    if (hint) {
        ret_value = hint->alg_name;
    }
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
