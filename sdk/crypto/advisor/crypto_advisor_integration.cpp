/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_advisor_tls.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>

namespace hotplace {
namespace crypto {

// integration in progress

return_t crypto_advisor::hintof_pkey(const EVP_PKEY* pkey, hint_advisor_t& hint) {
    return_t ret = errorcode_t::success;
    crypto_kty_t kty = kty_unknown;
    uint32 nid = 0;
    __try2 {
        hint.clear();

        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = ktyof_evp_pkey(pkey, kty, nid);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        hint.kty = kty;
        hint.nid = nid;

        ret = hintof_ossl_nid(nid, hint);
    }
    __finally2 {}
    return ret;
}

return_t crypto_advisor::hintof_name(const char* name, hint_advisor_t& hint) {
    return_t ret = errorcode_t::success;
    __try2 {
        hint.clear();

        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int nid = OBJ_txt2nid(name);
        if (nid) {
            //
        } else {
            auto feature = query_feature(name);
            if (advisor_feature_cipher & feature) {
            } else if (advisor_feature_md & feature) {
            } else if (advisor_feature_jwa & feature) {
            } else if (advisor_feature_jwe & feature) {
            } else if (advisor_feature_jws & feature) {
            } else if (advisor_feature_cose & feature) {
            } else if (advisor_feature_curve & feature) {
                const hint_curve_t* item = nullptr;
                t_maphint<std::string, const hint_curve_t*> curve_hint(_curve_name_map);
                ret = curve_hint.find(name, &item);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                nid = item->nid;
            }
        }

        if (nid) {
            ret = hintof_ossl_nid(nid, hint);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_advisor::hintof_ossl_nid(uint32 nid, hint_advisor_t& hint) {
    return_t ret = errorcode_t::success;

    hint.clear();

    auto kty = ktyof_ossl_nid(nid);

    hint.kty = kty;
    hint.nid = nid;

    t_maphint<crypto_kty_t, const hint_kty_name_t*> kty_map(_kty_names);
    kty_map.find(kty, &hint.hint_kty);

    t_maphint<uint32, const hint_curve_t*> curve_map(_curve_bynid_map);
    curve_map.find(nid, &hint.hint_curve);

    t_maphint<uint32, const hint_sigscheme_t*> sigscheme_nid_map(_hint_sigscheme_nid_map);
    sigscheme_nid_map.find(nid, &hint.hint_sigscheme);

    return ret;
}

std::string namesof(const hint_advisor_t* hint) {
    std::string res;
    if (hint) {
        const char* sn = OBJ_nid2sn(hint->nid);
        if (sn) {
            res += sn;
            res += " ";
        }

        auto hint_curve = hint->hint_curve;
        if (hint_curve) {
            res += "a.k.a. ";
            if (hint_curve->name_nist) {
                res += hint_curve->name_nist;
                res += " ";
            }
            if (hint_curve->name_x962) {
                res += hint_curve->name_x962;
                res += " ";
            }
            if (hint_curve->name_sec) {
                res += hint_curve->name_sec;
                res += " ";
            }
            if (hint_curve->name_bp) {
                res += hint_curve->name_bp;
                res += " ";
            }
            if (hint_curve->name_wtls) {
                res += hint_curve->name_wtls;
                res += " ";
            }
        }

        if (false == res.empty()) {
            res.pop_back();
        }
    }
    return res;
}

}  // namespace crypto
}  // namespace hotplace
