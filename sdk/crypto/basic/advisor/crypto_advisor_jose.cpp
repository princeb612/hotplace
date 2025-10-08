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
#include <hotplace/sdk/crypto/basic/evp_key.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_advisor::for_each_jwa(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    auto lambda = [&](const hint_jose_encryption_t& item) { return f(&item, user); };
    std::for_each(hint_jose_algorithms, hint_jose_algorithms + sizeof_hint_jose_algorithms, lambda);
    return ret;
}

return_t crypto_advisor::for_each_jwe(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    auto lambda = [&](const hint_jose_encryption_t& item) { return f(&item, user); };
    std::for_each(hint_jose_encryptions, hint_jose_encryptions + sizeof_hint_jose_encryptions, lambda);
    return ret;
}

return_t crypto_advisor::for_each_jws(std::function<void(const hint_signature_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    auto lambda = [&](const hint_signature_t& item) { return f(&item, user); };
    std::for_each(hint_signatures, hint_signatures + sizeof_hint_signatures, lambda);
    return ret;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm(jwa_t alg) {
    const hint_jose_encryption_t* item = nullptr;
    t_maphint<uint32, const hint_jose_encryption_t*> hint(_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption(jwe_t enc) {
    const hint_jose_encryption_t* item = nullptr;
    t_maphint<uint32, const hint_jose_encryption_t*> hint(_enc_map);

    hint.find(enc, &item);
    return item;
}

const hint_signature_t* crypto_advisor::hintof_jose_signature(jws_t sig) {
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_jose_sig_map);

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

    type = jwa_t::jwa_unknown;
    const hint_jose_encryption_t* item = hintof_jose_algorithm(alg);

    if (item) {
        type = (jwa_t)item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_encryption(const char* enc, jwe_t& type) {
    return_t ret = errorcode_t::success;

    type = jwe_t::jwe_unknown;
    const hint_jose_encryption_t* item = hintof_jose_encryption(enc);

    if (item) {
        type = (jwe_t)item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_signature(const char* sig, jws_t& type) {
    return_t ret = errorcode_t::success;

    type = jws_t::jws_unknown;
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
        crypto_kty_t kty = typeof_crypto_key(pkey);
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

        // uint32 type = EVP_PKEY_id (pkey);
        crypto_kty_t kty = typeof_crypto_key(pkey);
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);

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
            test = is_kindof(pkey, (jwa_t)hint_alg->type);
            if (test) {
                __leave2;
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

jws_t crypto_advisor::sigof(crypt_sig_t sig) {
    jws_t type = jws_t::jws_unknown;
    t_maphint<crypt_sig_t, jws_t> hint(_sig2jws_map);

    hint.find(sig, &type);
    return type;
}

crypt_sig_t crypto_advisor::sigof(jws_t sig) {
    crypt_sig_t type = crypt_sig_t::sig_unknown;
    t_maphint<jws_t, crypt_sig_t> hint(_jws2sig_map);

    hint.find(sig, &type);
    return type;
}

}  // namespace crypto
}  // namespace hotplace
