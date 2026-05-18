/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_advisor_key.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_advisor::nameof_kty(crypto_kty_t kty, std::string& name) {
    return_t ret = errorcode_t::success;
    __try2 {
        name.clear();

        auto iter = _kty_names.find(kty);
        if (_kty_names.end() == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        } else {
            const hint_kty_name_t* item = iter->second;
            name = item->name;
        }
    }
    __finally2 {}
    return ret;
}

const char* crypto_advisor::nameof_kty(crypto_kty_t kty) {
    const char* value = "";
    auto iter = _kty_names.find(kty);
    if (_kty_names.end() != iter) {
        const auto* item = iter->second;
        value = item->name;
    }
    return value;
}

crypto_kty_t crypto_advisor::ktyof_ossl_nid(uint32 nid) {
    crypto_kty_t kty = crypto_kty_t::kty_unknown;
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
        } break;
        case EVP_PKEY_X25519:
        case EVP_PKEY_X448:
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448: {
            kty = crypto_kty_t::kty_okp;
        } break;
        case EVP_PKEY_DH:
        case NID_ffdhe2048:
        case NID_ffdhe3072:
        case NID_ffdhe4096:
        case NID_ffdhe6144:
        case NID_ffdhe8192: {
            kty = crypto_kty_t::kty_dh;
        } break;
        case EVP_PKEY_DSA: {
            kty = crypto_kty_t::kty_dsa;
        } break;
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
        case NID_SLH_DSA_SHA2_128s:   // 1460
        case NID_SLH_DSA_SHA2_128f:   // 1461
        case NID_SLH_DSA_SHA2_192s:   // 1462
        case NID_SLH_DSA_SHA2_192f:   // 1463
        case NID_SLH_DSA_SHA2_256s:   // 1464
        case NID_SLH_DSA_SHA2_256f:   // 1465
        case NID_SLH_DSA_SHAKE_128s:  // 1466
        case NID_SLH_DSA_SHAKE_128f:  // 1467
        case NID_SLH_DSA_SHAKE_192s:  // 1468
        case NID_SLH_DSA_SHAKE_192f:  // 1469
        case NID_SLH_DSA_SHAKE_256s:  // 1470
        case NID_SLH_DSA_SHAKE_256f:  // 1471
        {
            kty = crypto_kty_t::kty_slhdsa;
        } break;
#endif
        default: {
            crypto_advisor* advisor = crypto_advisor::get_instance();
            auto hint = advisor->hintof_curve_nid(nid);
            if (hint) {
                kty = hint->kty;  // kty_ec, kty_okp
            }
        } break;
    }
    return kty;
}

return_t crypto_advisor::ktyof_evp_pkey(const EVP_PKEY* pkey, crypto_kty_t& kty, uint32& nid) {
    return_t ret = errorcode_t::success;
    __try2 {
        kty = kty_unknown;
        nid = 0;

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
                        case NID_SLH_DSA_SHA2_128s:
                        case NID_SLH_DSA_SHA2_128f:
                        case NID_SLH_DSA_SHA2_192s:
                        case NID_SLH_DSA_SHA2_192f:
                        case NID_SLH_DSA_SHA2_256s:
                        case NID_SLH_DSA_SHA2_256f:
                        case NID_SLH_DSA_SHAKE_128s:
                        case NID_SLH_DSA_SHAKE_128f:
                        case NID_SLH_DSA_SHAKE_192s:
                        case NID_SLH_DSA_SHAKE_192f:
                        case NID_SLH_DSA_SHAKE_256s:
                        case NID_SLH_DSA_SHAKE_256f: {
                            kty = crypto_kty_t::kty_slhdsa;
                        }
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
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace crypto
}  // namespace hotplace
