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

const hint_curve_t* crypto_advisor::hintof_curve_tls_group(uint16 group) {
    const hint_curve_t* item = nullptr;
    t_maphint<uint16, const hint_curve_t*> hint(_tls_group_curve_map);

    hint.find(group, &item);
    return item;
}

const hint_group_t* crypto_advisor::hintof_tls_group_nid(uint32 nid) {
    const hint_group_t* item = nullptr;
    t_maphint<uint32, const hint_group_t*> hint(_tls_group_nid_map);

    hint.find(nid, &item);
    return item;
}

const hint_group_t* crypto_advisor::hintof_tls_group(uint16 group) {
    const hint_group_t* item = nullptr;
    t_maphint<uint16, const hint_group_t*> hint(_tls_group_map);

    hint.find(group, &item);
    return item;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, tls_named_group_t group) {
    bool ret = false;
    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);
        auto hint = hintof_tls_group_nid(nid);
        if (nullptr == hint) {
            __leave2;
        }
        if (tls_named_group_unknown == hint->group) {
            __leave2;
        }
        ret = (group == hint->group);
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
