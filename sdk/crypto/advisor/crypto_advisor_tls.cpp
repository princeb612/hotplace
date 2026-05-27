/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_advisor_tls.cpp
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

const hint_curve_t* crypto_advisor::hintof_curve_tls_group(tls_group_t group) {
    const hint_curve_t* item = nullptr;
    t_maphint<tls_group_t, const hint_curve_t*> hint(_tls_group_curve_map);

    hint.find(group, &item);
    return item;
}

const hint_group_t* crypto_advisor::hintof_tls_group(tls_group_t group) {
    const hint_group_t* item = nullptr;
    t_maphint<tls_group_t, const hint_group_t*> hint(_tls_group_map);

    hint.find(group, &item);
    return item;
}

const hint_group_t* crypto_advisor::hintof_tls_group(const std::string& name) {
    const hint_group_t* item = nullptr;
    t_maphint<std::string, const hint_group_t*> hint(_tls_group_name_map);

    std::string key = name;
    std::transform(key.begin(), key.end(), key.begin(), tolower);
    hint.find(std::move(key), &item);  // ignore case
    return item;
}

void crypto_advisor::enum_tls_group(std::function<void(const hint_group_t*)> func) {
    if (func) {
        for (size_t i = 0; i < sizeof_hint_groups; i++) {
            auto item = hint_groups + i;
            func(item);
        }
    }
}

const hint_group_t* crypto_advisor::hintof_tls_group_nid(uint32 nid) {
    const hint_group_t* item = nullptr;
    t_maphint<uint32, const hint_group_t*> hint(_tls_group_nid_map);

    hint.find(nid, &item);
    return item;
}

return_t crypto_advisor::for_each_tls_group(std::function<void(tls_group_t, uint32)> f) {
    return_t ret = errorcode_t::success;
    for (size_t i = 0; i < sizeof_hint_groups; ++i) {
        const auto& item = hint_groups + i;
        auto spec = query_feature(item->name, advisor_feature_tlsgroup);
        f(item->group, spec);
    }
    return ret;
}

return_t crypto_advisor::for_each_tls_group(std::function<void(const hint_group_t*)> f) {
    return_t ret = errorcode_t::success;
    for (size_t i = 0; i < sizeof_hint_groups; ++i) {
        const auto& item = hint_groups + i;
        f(item);
    }
    return ret;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, tls_group_t group) {
    bool ret = false;
    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);
        // cf. multiplicity 1..*
        // - NID_brainpoolP256r1
        //   -  tls_group_t::brainpoolP256r1
        //   -  tls_group_t::brainpoolP256r1tls13
        auto hint = hintof_tls_group(group);  // multiplicity 1..1
        if (nullptr == hint) {
            __leave2;
        }
        if (tls_group_t{} == hint->group) {
            __leave2;
        }
        ret = (nid == hint->first.nid || nid == hint->second.nid);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
