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

namespace hotplace {
namespace crypto {

const EVP_MD* crypto_advisor::find_evp_md(hash_algorithm_t algorithm) {
    EVP_MD* ret_value = nullptr;
    t_maphint<uint32, EVP_MD*> hint(_md_map);

    hint.find(algorithm, &ret_value);
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md(crypt_sig_t sig) {
    const EVP_MD* ret_value = nullptr;
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = find_evp_md(item->alg);
    }
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md(jws_t sig) {
    const EVP_MD* ret_value = nullptr;
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    if (item) {
        ret_value = find_evp_md(item->alg);
    }
    return ret_value;
}

const EVP_MD* crypto_advisor::find_evp_md(const char* name) {
    const EVP_MD* ret_value = nullptr;

    if (name) {
        t_maphint<std::string, const hint_digest_t*> hint(_md_byname_map);
        const hint_digest_t* item = nullptr;
        hint.find(name, &item);
        if (item) {
            ret_value = _md_map[typeof_alg(item)];
        }
    }
    return ret_value;
}

const hint_digest_t* crypto_advisor::hintof_digest(hash_algorithm_t algorithm) {
    const hint_digest_t* ret_value = nullptr;
    t_maphint<uint32, const hint_digest_t*> hint(_md_fetch_map);

    hint.find(algorithm, &ret_value);
    return ret_value;
}

const hint_digest_t* crypto_advisor::hintof_digest(const char* name) {
    const hint_digest_t* ret_value = nullptr;

    __try2 {
        if (nullptr == name) {
            __leave2;
        }

        t_maphint<std::string, const hint_digest_t*> hint(_md_byname_map);
        hint.find(lowername(name).c_str(), &ret_value);
    }
    __finally2 {}
    return ret_value;
}

const char* crypto_advisor::nameof_md(hash_algorithm_t algorithm) {
    const char* ret_value = nullptr;
    const hint_digest_t* item = nullptr;
    t_maphint<uint32, const hint_digest_t*> hint(_md_fetch_map);

    hint.find(algorithm, &item);
    ret_value = nameof_alg(item);
    return ret_value;
}

return_t crypto_advisor::md_for_each(std::function<void(const char*, uint32, void*)> f, void* user) {
    return_t ret = errorcode_t::success;
    for (auto i = 0; i < sizeof_evp_md_methods; i++) {
        const hint_digest_t* item = evp_md_methods + i;
        f(nameof_alg(item), advisor_feature_md, user);
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
