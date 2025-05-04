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

return_t crypto_advisor::cose_for_each(std::function<void(const char*, uint32, void*)> f, void* user) {
    return_t ret = errorcode_t::success;
    for (auto i = 0; i < sizeof_hint_cose_algorithms; i++) {
        const hint_cose_algorithm_t* item = hint_cose_algorithms + i;
        f(item->name, advisor_feature_cose, user);
    }
    return ret;
}

const hint_cose_algorithm_t* crypto_advisor::hintof_cose_algorithm(cose_alg_t alg) {
    const hint_cose_algorithm_t* item = nullptr;
    t_maphint<uint32, const hint_cose_algorithm_t*> hint(_cose_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_cose_algorithm_t* crypto_advisor::hintof_cose_algorithm(uint32 alg) {
    const hint_cose_algorithm_t* item = nullptr;
    t_maphint<uint32, const hint_cose_algorithm_t*> hint(_cose_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_cose_algorithm_t* crypto_advisor::hintof_cose_algorithm(const char* alg) {
    const hint_cose_algorithm_t* item = nullptr;

    if (alg) {
        t_maphint<std::string, const hint_cose_algorithm_t*> hint(_cose_algorithm_byname_map);
        hint.find(alg, &item);
    }

    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve(cose_ec_curve_t curve) {
    const hint_curve_t* item = nullptr;
    t_maphint<cose_ec_curve_t, const hint_curve_t*> hint(_cose_curve_map);

    hint.find(curve, &item);
    return item;
}

const char* crypto_advisor::nameof_cose_algorithm(cose_alg_t alg) {
    const char* name = nullptr;

    const hint_cose_algorithm_t* item = hintof_cose_algorithm(alg);

    if (item) {
        name = item->name;
    }
    return name;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, cose_alg_t alg) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }
        const hint_cose_algorithm_t* hint = hintof_cose_algorithm(alg);
        if (nullptr == hint) {
            __leave2;
        }
        crypto_kty_t kty = typeof_crypto_key(pkey);
        bool cmp1 = (hint->kty == kty);
        bool cmp2 = true;
        if (crypto_kty_t::kty_ec == kty) {
            uint32 nid = 0;
            nidof_evp_pkey(pkey, nid);
            cmp2 = (hint->eckey.nid == nid);
        }
        test = (cmp1 && cmp2);
    }
    __finally2 {
        // do nothing
    }
    return test;
}

cose_kty_t crypto_advisor::ktyof(crypto_kty_t kty) {
    cose_kty_t cose_kty = cose_kty_t::cose_kty_unknown;
    t_maphint<crypto_kty_t, cose_kty_t> hint(_kty2cose_map);

    hint.find(kty, &cose_kty);
    return cose_kty;
}

crypto_kty_t crypto_advisor::ktyof(cose_kty_t kty) {
    crypto_kty_t crypto_kty = crypto_kty_t::kty_unknown;
    t_maphint<cose_kty_t, crypto_kty_t> hint(_cose2kty_map);

    hint.find(kty, &crypto_kty);
    return crypto_kty;
}

crypt_category_t crypto_advisor::categoryof(cose_alg_t alg) {
    crypt_category_t category = crypt_category_t::crypt_category_not_classified;
    t_maphint<uint32, const hint_cose_algorithm_t*> hint(_cose_alg_map);

    const hint_cose_algorithm_t* item = nullptr;
    hint.find(alg, &item);
    if (item) {
        category = item->hint_group->category;
    }
    return category;
}

crypt_sig_t crypto_advisor::sigof(cose_alg_t sig) {
    crypt_sig_t type = crypt_sig_t::sig_unknown;
    t_maphint<cose_alg_t, crypt_sig_t> hint(_cose2sig_map);

    hint.find(sig, &type);
    return type;
}

cose_ec_curve_t crypto_advisor::curveof(uint32 nid) {
    cose_ec_curve_t curve = cose_ec_curve_t::cose_ec_unknown;
    t_maphint<uint32, cose_ec_curve_t> hint(_nid2curve_map);

    hint.find(nid, &curve);
    return curve;
}

uint32 crypto_advisor::curveof(cose_ec_curve_t curve) {
    uint32 nid = 0;
    t_maphint<cose_ec_curve_t, uint32> hint(_curve2nid_map);

    hint.find(curve, &nid);
    return nid;
}

}  // namespace crypto
}  // namespace hotplace
