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
#include <sdk/crypto/basic/evp_key.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_advisor::curve_for_each(std::function<void(const char*, uint32, void*)> f, void* user) {
    return_t ret = errorcode_t::success;
    for (auto i = 0; i < sizeof_hint_curves; i++) {
        const hint_curve_t* item = hint_curves + i;
        if (item->name) {
            f(item->name, advisor_feature_curve, user);
        }
    }
    return ret;
}

const hint_curve_t* crypto_advisor::hintof_curve_nid(uint32 nid) {
    const hint_curve_t* item = nullptr;
    t_maphint<uint32, const hint_curve_t*> hint(_curve_bynid_map);

    hint.find(nid, &item);
    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve_name(const char* name) {
    const hint_curve_t* item = nullptr;
    if (name) {
        t_maphint<std::string, const hint_curve_t*> hint(_curve_name_map);

        hint.find(name, &item);
    }
    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve(const char* curve) {
    const hint_curve_t* item = nullptr;

    if (curve) {
        t_maphint<std::string, const hint_curve_t*> hint(_nid_bycurve_map);
        hint.find(curve, &item);
    }

    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve_eckey(const EVP_PKEY* pkey) {
    const hint_curve_t* item = nullptr;
    if (pkey) {
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);
        item = hintof_curve_nid(nid);
    }
    return item;
}

return_t crypto_advisor::nidof_ec_curve(const char* curve, uint32& nid) {
    return_t ret = errorcode_t::success;

    __try2 {
        nid = 0;

        if (nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_curve_t* item = hintof_curve(curve);
        if (item) {
            nid = item->nid;
        } else {
            ret = errorcode_t::not_found;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::ktyof_ec_curve(const char* curve, uint32& kty) {
    return_t ret = errorcode_t::success;

    __try2 {
        kty = 0;

        if (nullptr == curve) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const hint_curve_t* item = hintof_curve(curve);
        if (item) {
            kty = item->kty;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::ktyof_ec_curve(const EVP_PKEY* pkey, std::string& kty) {
    return_t ret = errorcode_t::success;

    __try2 {
        kty.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);
        const hint_curve_t* item = hintof_curve_nid(nid);
        if (item) {
            ret = nameof_kty(item->kty, kty);
        } else {
            ret = errorcode_t::not_found;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t crypto_advisor::nameof_ec_curve(const EVP_PKEY* pkey, std::string& name) {
    return_t ret = errorcode_t::success;
    uint32 nid = 0;

    name.clear();

    if (kindof_ecc(pkey)) {
        nidof_evp_pkey(pkey, nid);

        const hint_curve_t* item = nullptr;
        t_maphint<uint32, const hint_curve_t*> hint(_curve_bynid_map);
        ret = hint.find(nid, &item);
        if (errorcode_t::success == ret) {
            if (item->name) {
                name = item->name;
            } else if (item->aka1) {
                name = item->aka1;
            } else if (item->aka2) {
                name = item->aka2;
            } else if (item->aka3) {
                name = item->aka3;
            }
        }
    }
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
