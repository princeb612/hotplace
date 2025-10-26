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
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>

namespace hotplace {
namespace crypto {

hash_algorithm_t crypto_advisor::get_algorithm(crypt_sig_t sig) {
    hash_algorithm_t ret_value = hash_algorithm_t::hash_alg_unknown;
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = item->alg;
    }
    return ret_value;
}

hash_algorithm_t crypto_advisor::get_algorithm(jws_t sig) {
    hash_algorithm_t ret_value = hash_algorithm_t::hash_alg_unknown;
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = item->alg;
    }
    return ret_value;
}

const hint_signature_t* crypto_advisor::hintof_signature(crypt_sig_t sig) {
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    return item;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, crypt_sig_t sig) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        // uint32 type = EVP_PKEY_id (pkey);
        crypto_kty_t kty = ktyof_evp_pkey(pkey);
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);

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

uint16 crypto_advisor::sizeof_ecdsa(crypt_sig_t sig) {
    uint16 ret_value = 0;
    switch (sig) {
        case sig_sha1:
            ret_value = 20 << 1;
            break;
        case sig_sha224:
            ret_value = 28 << 1;
            break;
        case sig_sha256:
            ret_value = 32 << 1;
            break;
        case sig_sha384:
            ret_value = 48 << 1;
            break;
        case sig_sha512:
            ret_value = 66 << 1;
            break;
    }
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
