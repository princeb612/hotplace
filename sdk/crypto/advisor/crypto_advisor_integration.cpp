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
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        nid = EVP_PKEY_id(pkey);
        switch (nid) {
            case EVP_PKEY_HMAC: {
                kty = crypto_kty_t::kty_oct;
            } break;
            case EVP_PKEY_RSA:
            case EVP_PKEY_RSA2: {
                kty = crypto_kty_t::kty_rsa;
            } break;
            case EVP_PKEY_RSA_PSS: {
                kty = crypto_kty_t::kty_rsapss;
            } break;
            case EVP_PKEY_EC: {
                kty = crypto_kty_t::kty_ec;

                EC_KEY_ptr ec(EVP_PKEY_get1_EC_KEY((EVP_PKEY*)pkey));
                if (ec.get()) {
                    const EC_GROUP* group = EC_KEY_get0_group(ec.get());
                    nid = EC_GROUP_get_curve_name(group);
                } else {
                    ret = errorcode_t::internal_error;
                }
            } break;
            case EVP_PKEY_X25519:
            case EVP_PKEY_X448: {
                kty = crypto_kty_t::kty_okp;
            } break;
            case EVP_PKEY_ED25519:
            case EVP_PKEY_ED448: {
                kty = crypto_kty_t::kty_eddsa;
            } break;
            case EVP_PKEY_DH: {
                kty = crypto_kty_t::kty_dh;

                // nid = EVP_PKEY_get_base_id(pkey);
                DH_ptr dh(EVP_PKEY_get1_DH((EVP_PKEY*)pkey));
                if (dh.get()) {
                    int bits = BN_num_bits(DH_get0_p(dh.get()));
                    switch (bits) {
                        case 2048: {
                            nid = nid_ffdhe2048;
                        } break;
                        case 3072: {
                            nid = nid_ffdhe3072;
                        } break;
                        case 4096: {
                            nid = nid_ffdhe4096;
                        } break;
                        case 6144: {
                            nid = nid_ffdhe6144;
                        } break;
                        case 8192: {
                            nid = nid_ffdhe8192;
                        } break;
                        default: {
                        } break;
                    }
                }
            } break;
            case EVP_PKEY_DSA: {
                kty = crypto_kty_t::kty_dsa;
            } break;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            case (uint32)EVP_PKEY_KEYMGMT: {
                auto name = EVP_PKEY_get0_type_name(pkey);
                if (name) {
                    nid = OBJ_txt2nid(name);
                    switch (nid) {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
                        case NID_ML_KEM_512:
                        case NID_ML_KEM_768:
                        case NID_ML_KEM_1024: {
                            kty = crypto_kty_t::kty_mlkem;
                        } break;
                        case NID_ML_DSA_44:
                        case NID_ML_DSA_65:
                        case NID_ML_DSA_87: {
                            kty = crypto_kty_t::kty_mldsa;
                        } break;
#endif
                        default: {
                            // not supported
                        } break;
                    }
                }
            } break;
#endif
            default: {
            } break;
        }

        if (kty_unknown == kty || 0 == nid) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        hint.kty = kty;
        hint.nid = nid;

        t_maphint<crypto_kty_t, const hint_kty_name_t*> kty_map(_kty_names);
        kty_map.find(kty, &hint.hint_kty);

        t_maphint<uint32, const hint_curve_t*> curve_map(_curve_bynid_map);
        curve_map.find(nid, &hint.hint_curve);

        t_maphint<uint32, const hint_sigscheme_t*> sigscheme_nid_map(_hint_sigscheme_nid_map);
        sigscheme_nid_map.find(nid, &hint.hint_sigscheme);
    }
    __finally2 {}
    return ret;
}

return_t crypto_advisor::hintof_name(const char* name, hint_advisor_t& hint) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == name) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        int nid = OBJ_txt2nid(name);
        ret = hintof_ossl_nid(nid, hint);
    }
    __finally2 {}
    return ret;
}

return_t crypto_advisor::hintof_ossl_nid(uint32 nid, hint_advisor_t& hint) {
    return_t ret = errorcode_t::success;

    auto kty = ktyof_nid(nid);

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
