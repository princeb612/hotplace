/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_advisor_digest.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

const EVP_MD* crypto_advisor::find_evp_md(hash_algorithm_t algorithm) {
    EVP_MD* ret_value = nullptr;
    auto iter = _md_fetch_map.find(algorithm);
    if (_md_fetch_map.end() != iter) {
        ret_value = iter->second.md;
    }
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

const EVP_MD* crypto_advisor::find_evp_md(const char* name) { return name ? find_evp_md(std::string(name)) : nullptr; }

const EVP_MD* crypto_advisor::find_evp_md(const std::string& name) {
    const EVP_MD* ret_value = nullptr;
    t_maphint<std::string, const hint_digest_t*> hint(_md_byname_map);
    const hint_digest_t* item = nullptr;
    hint.find(name, &item);
    if (item) {
        ret_value = _md_fetch_map[typeof_alg(item)].md;
    }
    return ret_value;
}

const hint_digest_t* crypto_advisor::hintof_digest(hash_algorithm_t algorithm) {
    const hint_digest_t* ret_value = nullptr;
    auto iter = _md_fetch_map.find(algorithm);
    if (_md_fetch_map.end() != iter) {
        ret_value = iter->second.hint;
    }
    return ret_value;
}

const hint_digest_t* crypto_advisor::hintof_digest(const char* name) { return name ? hintof_digest(std::string(name)) : nullptr; }

const hint_digest_t* crypto_advisor::hintof_digest(const std::string& name) {
    const hint_digest_t* ret_value = nullptr;
    t_maphint<std::string, const hint_digest_t*> hint(_md_byname_map);
    hint.find(lowername(name), &ret_value);
    return ret_value;
}

const char* crypto_advisor::nameof_md(hash_algorithm_t algorithm) {
    const char* ret_value = nullptr;
    md_fetch_block_t block;
    t_maphint<uint32, md_fetch_block_t> hint(_md_fetch_map);

    hint.find(algorithm, &block);
    ret_value = nameof_alg(block.hint);
    return ret_value;
}

return_t crypto_advisor::for_each_md(std::function<void(const char*, uint32, void*)> f, void* user) {
    return_t ret = errorcode_t::success;
    for (size_t i = 0; i < sizeof_evp_md_methods; i++) {
        const hint_digest_t* item = evp_md_methods + i;
        auto spec = query_feature(nameof_alg(item), advisor_feature_md);
        f(nameof_alg(item), spec, user);
    }
    return ret;
}

// hint_digest_t

hash_algorithm_t typeof_alg(const hint_digest_t* hint) {
    hash_algorithm_t ret_value = hash_algorithm_t::hash_alg_unknown;
    if (hint) {
        ret_value = hint->algorithm;
    }
    return ret_value;
}

const char* nameof_alg(const hint_digest_t* hint) {
    const char* ret_value = nullptr;
    if (hint) {
        ret_value = hint->fetchname;
    }
    return ret_value;
}

uint16 sizeof_digest(const hint_digest_t* hint) {
    uint16 ret_value = 0;
    if (hint) {
        ret_value = hint->digest_size;
    }
    return ret_value;
}

}  // namespace crypto
}  // namespace hotplace
