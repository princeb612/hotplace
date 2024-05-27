/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/io/system/sdk.hpp>

namespace hotplace {
namespace crypto {

#define CRYPT_CIPHER_VALUE(a, m) ((a << 16) | m)

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
typedef struct _openssl_evp_cipher_method_older_t {
    const EVP_CIPHER* _cipher;
    hint_cipher_t method;
} openssl_evp_cipher_method_older_t;

const openssl_evp_cipher_method_older_t aes_wrap_methods[] = {
    {
        EVP_aes_128_wrap(),
        {
            crypt_algorithm_t::aes128,
            crypt_mode_t::wrap,
            "aes-128-wrap",
        },
    },
    {EVP_aes_192_wrap(),
     {
         crypt_algorithm_t::aes192,
         crypt_mode_t::wrap,
         "aes-192-wrap",
     }},
    {
        EVP_aes_256_wrap(),
        {
            crypt_algorithm_t::aes256,
            crypt_mode_t::wrap,
            "aes-256-wrap",
        },
    },
};
#endif

crypto_advisor crypto_advisor::_instance;

crypto_advisor* crypto_advisor::get_instance() { return &_instance; }

crypto_advisor::~crypto_advisor() { cleanup(); }

crypto_advisor::crypto_advisor() : _flag(0) { build_if_necessary(); }

return_t crypto_advisor::build_if_necessary() {
    return_t ret = errorcode_t::success;
    uint32 i = 0;

    if (0 == _flag) {
        for (i = 0; i < sizeof_hint_blockciphers; i++) {
            const hint_blockcipher_t* item = hint_blockciphers + i;
            _blockcipher_map.insert(std::make_pair(typeof_alg(item), item));
        }

        // openssl-3.0
        //   - use EVP_CIPHER_fetch/EVP_CIPHER_free, EVP_MD_fetch/EVP_MD_free
        // openssl-1.1.1
        //   - use EVP_get_cipherbyname, EVP_get_digestbyname (run-time)
        //     EVP_CIPHER* and EVP_MD* at extern const structure return nullptr (constexpr in compile-time)
        //   - not provided "aes-128-wrap", "aes-192-wrap", "aes-256-wrap"
        //     [FAIL] const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-128-wrap");
        //     [PASS] const EVP_CIPHER* cipher = crypto_advisor::get_instance()->find_evp_cipher("aes-128-wrap");

        for (i = 0; i < sizeof_evp_cipher_methods; i++) {
            const hint_cipher_t* item = evp_cipher_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(nullptr, nameof_alg(item), nullptr);
            if (evp_cipher) {
                _cipher_map.insert(std::make_pair(CRYPT_CIPHER_VALUE(typeof_alg(item), typeof_mode(item)), evp_cipher));
                _evp_cipher_map.insert(std::make_pair(evp_cipher, item));
            }
#else
            const EVP_CIPHER* evp_cipher = EVP_get_cipherbyname(nameof_alg(item));
            if (evp_cipher) {
                _cipher_map.insert(std::make_pair(CRYPT_CIPHER_VALUE(typeof_alg(item), typeof_mode(item)), (EVP_CIPHER*)evp_cipher));
                _evp_cipher_map.insert(std::make_pair(evp_cipher, item));
            }
#endif
            if (nullptr == evp_cipher) {
                __trace(errorcode_t::debug, "%s", nameof_alg(item));
            }

            _cipher_fetch_map.insert(std::make_pair(CRYPT_CIPHER_VALUE(typeof_alg(item), typeof_mode(item)), item));
            _cipher_byname_map.insert(std::make_pair(nameof_alg(item), item));
        }
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
        for (i = 0; i < RTL_NUMBER_OF(aes_wrap_methods); i++) {
            const openssl_evp_cipher_method_older_t* item = aes_wrap_methods + i;
            _cipher_map.insert(std::make_pair(CRYPT_CIPHER_VALUE(item->method.algorithm, item->method.mode), (EVP_CIPHER*)item->_cipher));
            _evp_cipher_map.insert(std::make_pair(item->_cipher, &item->method));
        }
#endif

        for (i = 0; i < sizeof_evp_md_methods; i++) {
            const hint_digest_t* item = evp_md_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
            EVP_MD* evp_md = EVP_MD_fetch(nullptr, nameof_alg(item), nullptr);
            if (evp_md) {
                _md_map.insert(std::make_pair(typeof_alg(item), evp_md));
            }
#else
            const EVP_MD* evp_md = EVP_get_digestbyname(nameof_alg(item));
            if (evp_md) {
                _md_map.insert(std::make_pair(typeof_alg(item), (EVP_MD*)evp_md));
            }
#endif
            if (nullptr == evp_md) {
                __trace(errorcode_t::debug, "%s", nameof_alg(item));
            }
            _md_fetch_map.insert(std::make_pair(typeof_alg(item), item));
            _md_byname_map.insert(std::make_pair(nameof_alg(item), item));
        }

        ERR_clear_error();  // errors while EVP_CIPHER_fetch, EVP_MD_fetch

        for (i = 0; i < sizeof_hint_jose_algorithms; i++) {
            const hint_jose_encryption_t* item = hint_jose_algorithms + i;
            _alg_map.insert(std::make_pair(item->type, item));
            if (item->alg_name) {
                _alg_byname_map.insert(std::make_pair(item->alg_name, item));
            }
        }
        for (i = 0; i < sizeof_hint_jose_encryptions; i++) {
            const hint_jose_encryption_t* item = hint_jose_encryptions + i;
            _enc_map.insert(std::make_pair(item->type, item));
            if (item->alg_name) {
                _enc_byname_map.insert(std::make_pair(item->alg_name, item));
            }
        }
        for (i = 0; i < sizeof_hint_signatures; i++) {
            const hint_signature_t* item = hint_signatures + i;
            _crypt_sig_map.insert(std::make_pair(item->sig_type, item));
            if (item->jws_name) {
                _sig_byname_map.insert(std::make_pair(item->jws_name, item));
            }
            if (item->jws_type) {
                _jose_sig_map.insert(std::make_pair(item->jws_type, item));
                _sig2jws_map.insert(std::make_pair(item->sig_type, item->jws_type));
            }
        }
        for (i = 0; i < sizeof_hint_signatures; i++) {
            const hint_signature_t* item = hint_signatures + i;
            for (uint midx = 0; midx < item->count; midx++) {
                _sig_bynid_map.insert(std::make_pair(item->nid[midx], item));
            }
        }
        for (i = 0; i < sizeof_hint_cose_algorithms; i++) {
            const hint_cose_algorithm_t* item = hint_cose_algorithms + i;
            _cose_alg_map.insert(std::make_pair(item->alg, item));
            _cose_algorithm_byname_map.insert(std::make_pair(item->name, item));
        }
        for (i = 0; i < sizeof_hint_curves; i++) {
            const hint_curve_t* item = hint_curves + i;
            if (item->name) {
                _nid_bycurve_map.insert(std::make_pair(item->name, item));
            }
            if (cose_ec_curve_t::cose_ec_unknown != item->cose_crv) {
                _cose_curve_map.insert(std::make_pair(item->cose_crv, item));
            }
            _curve_bynid_map.insert(std::make_pair(item->nid, item));
        }

        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_ec, cose_kty_t::cose_kty_ec2));
        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_oct, cose_kty_t::cose_kty_symm));
        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_okp, cose_kty_t::cose_kty_okp));
        _kty2cose_map.insert(std::make_pair(crypto_kty_t::kty_rsa, cose_kty_t::cose_kty_rsa));

        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_ec2, crypto_kty_t::kty_ec));
        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_symm, crypto_kty_t::kty_oct));
        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_okp, crypto_kty_t::kty_okp));
        _cose2kty_map.insert(std::make_pair(cose_kty_t::cose_kty_rsa, crypto_kty_t::kty_rsa));

        struct _sig2cose {
            crypt_sig_t sig;
            jws_t jws;
            cose_alg_t cose;
        };
        struct _sig2cose sig2cose[] = {
            {crypt_sig_t::sig_hs256, jws_t::jws_hs256, cose_alg_t::cose_hs256}, {crypt_sig_t::sig_hs384, jws_t::jws_hs384, cose_alg_t::cose_hs384},
            {crypt_sig_t::sig_hs512, jws_t::jws_hs512, cose_alg_t::cose_hs512}, {crypt_sig_t::sig_rs256, jws_t::jws_rs256, cose_alg_t::cose_rs256},
            {crypt_sig_t::sig_rs384, jws_t::jws_rs384, cose_alg_t::cose_rs384}, {crypt_sig_t::sig_rs512, jws_t::jws_rs512, cose_alg_t::cose_rs512},
            {crypt_sig_t::sig_es256, jws_t::jws_es256, cose_alg_t::cose_es256}, {crypt_sig_t::sig_es384, jws_t::jws_es384, cose_alg_t::cose_es384},
            {crypt_sig_t::sig_es512, jws_t::jws_es512, cose_alg_t::cose_es512}, {crypt_sig_t::sig_ps256, jws_t::jws_ps256, cose_alg_t::cose_ps256},
            {crypt_sig_t::sig_ps384, jws_t::jws_ps384, cose_alg_t::cose_ps384}, {crypt_sig_t::sig_ps512, jws_t::jws_ps512, cose_alg_t::cose_ps512},
            {crypt_sig_t::sig_eddsa, jws_t::jws_eddsa, cose_alg_t::cose_eddsa}, {crypt_sig_t::sig_es256k, jws_t::jws_unknown, cose_alg_t::cose_es256k},
            {crypt_sig_t::sig_rs1, jws_t::jws_unknown, cose_alg_t::cose_rs1},
        };
        struct _sig2cose cose2sig[] = {
            {crypt_sig_t::sig_hs256, jws_t::jws_hs256, cose_alg_t::cose_hs256_64},
        };
        for (i = 0; i < RTL_NUMBER_OF(sig2cose); i++) {
            _sig2jws_map.insert(std::make_pair(sig2cose[i].sig, sig2cose[i].jws));
            _jws2sig_map.insert(std::make_pair(sig2cose[i].jws, sig2cose[i].sig));
            if (cose_alg_t::cose_unknown != sig2cose[i].cose) {
                _sig2cose_map.insert(std::make_pair(sig2cose[i].sig, sig2cose[i].cose));
            }
            _cose2sig_map.insert(std::make_pair(sig2cose[i].cose, sig2cose[i].sig));
        }
        for (i = 0; i < RTL_NUMBER_OF(cose2sig); i++) {
            _cose2sig_map.insert(std::make_pair(cose2sig[i].cose, cose2sig[i].sig));
        }

        for (i = 0; i < sizeof_hint_curves; i++) {
            _nid2curve_map.insert(std::make_pair(hint_curves[i].nid, hint_curves[i].cose_crv));
            if (hint_curves[i].cose_crv) {
                _curve2nid_map.insert(std::make_pair(hint_curves[i].cose_crv, hint_curves[i].nid));
            }
        }

        _flag = 1;
    }
    return ret;
}

return_t crypto_advisor::cleanup() {
    return_t ret = errorcode_t::success;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    cipher_map_t::iterator iter_cipher;
    for (iter_cipher = _cipher_map.begin(); iter_cipher != _cipher_map.end(); iter_cipher++) {
        EVP_CIPHER_free(iter_cipher->second);
    }
    md_map_t::iterator iter_md;
    for (iter_md = _md_map.begin(); iter_md != _md_map.end(); iter_md++) {
        EVP_MD_free(iter_md->second);
    }
#endif

    return ret;
}

const hint_blockcipher_t* crypto_advisor::hintof_blockcipher(crypt_algorithm_t alg) {
    const hint_blockcipher_t* item = nullptr;
    t_maphint<uint32, const hint_blockcipher_t*> hint(_blockcipher_map);

    hint.find(alg, &item);
    return item;
}

const hint_blockcipher_t* crypto_advisor::hintof_blockcipher(const char* alg) {
    const hint_blockcipher_t* ret_value = nullptr;
    if (alg) {
        t_maphint<std::string, const hint_cipher_t*> hint(_cipher_byname_map);
        const hint_cipher_t* item = nullptr;
        hint.find(alg, &item);
        if (item) {
            ret_value = hintof_blockcipher(typeof_alg(item));
        }
    }
    return ret_value;
}

const hint_blockcipher_t* crypto_advisor::find_evp_cipher(const EVP_CIPHER* cipher) {
    const hint_blockcipher_t* blockcipher = nullptr;
    return_t ret = errorcode_t::success;

    __try2 {
        const hint_cipher_t* hint = nullptr;
        t_maphint<const EVP_CIPHER*, const hint_cipher_t*> hint_cipher(_evp_cipher_map);
        ret = hint_cipher.find(cipher, &hint);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        t_maphint<uint32, const hint_blockcipher_t*> hint_blockcipher(_blockcipher_map);
        hint_blockcipher.find(typeof_alg(hint), &blockcipher);
    }
    __finally2 {
        // do nothing
    }
    return blockcipher;
}

const EVP_CIPHER* crypto_advisor::find_evp_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode) {
    EVP_CIPHER* ret_value = nullptr;
    uint32 key = CRYPT_CIPHER_VALUE(algorithm, mode);
    t_maphint<uint32, EVP_CIPHER*> hint(_cipher_map);

    hint.find(key, &ret_value);
    return ret_value;
}

const EVP_CIPHER* crypto_advisor::find_evp_cipher(const char* name) {
    const EVP_CIPHER* ret_value = nullptr;

    if (name) {
        t_maphint<std::string, const hint_cipher_t*> hint(_cipher_byname_map);
        const hint_cipher_t* item = nullptr;
        hint.find(name, &item);
        if (item) {
            ret_value = _cipher_map[CRYPT_CIPHER_VALUE(typeof_alg(item), typeof_mode(item))];
        }
    }
    return ret_value;
}

const hint_cipher_t* crypto_advisor::hintof_cipher(const char* name) {
    const hint_cipher_t* ret_value = nullptr;
    __try2 {
        if (nullptr == name) {
            __leave2;
        }

        t_maphint<std::string, const hint_cipher_t*> hint(_cipher_byname_map);
        hint.find(name, &ret_value);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const hint_cipher_t* crypto_advisor::hintof_cipher(const EVP_CIPHER* cipher) {
    const hint_cipher_t* ret_value = nullptr;

    __try2 {
        if (nullptr == cipher) {
            __leave2;
        }

        t_maphint<const EVP_CIPHER*, const hint_cipher_t*> hint(_evp_cipher_map);
        hint.find(cipher, &ret_value);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

const char* crypto_advisor::nameof_cipher(crypt_algorithm_t algorithm, crypt_mode_t mode) {
    return_t ret = errorcode_t::success;
    const char* ret_value = nullptr;

    __try2 {
        uint32 key = CRYPT_CIPHER_VALUE(algorithm, mode);
        const hint_cipher_t* item = nullptr;
        t_maphint<uint32, const hint_cipher_t*> hint(_cipher_fetch_map);

        ret = hint.find(key, &item);
        ret_value = nameof_alg(item);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

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
        hint.find(name, &ret_value);
    }
    __finally2 {
        // do nothing
    }
    return ret_value;
}

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

const char* crypto_advisor::nameof_md(hash_algorithm_t algorithm) {
    const char* ret_value = nullptr;
    const hint_digest_t* item = nullptr;
    t_maphint<uint32, const hint_digest_t*> hint(_md_fetch_map);

    hint.find(algorithm, &item);
    ret_value = nameof_alg(item);
    return ret_value;
}

#if __cplusplus >= 201103L  // c++11
return_t crypto_advisor::jose_for_each_algorithm(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    std::for_each(hint_jose_algorithms, hint_jose_algorithms + sizeof_hint_jose_algorithms, [&](const hint_jose_encryption_t& item) { return f(&item, user); });
    return ret;
}

return_t crypto_advisor::jose_for_each_encryption(std::function<void(const hint_jose_encryption_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    std::for_each(hint_jose_encryptions, hint_jose_encryptions + sizeof_hint_jose_encryptions,
                  [&](const hint_jose_encryption_t& item) { return f(&item, user); });
    return ret;
}

return_t crypto_advisor::jose_for_each_signature(std::function<void(const hint_signature_t*, void*)> f, void* user) {
    return_t ret = errorcode_t::success;

    std::for_each(hint_signatures, hint_signatures + sizeof_hint_signatures, [&](const hint_signature_t& item) { return f(&item, user); });
    return ret;
}
#endif

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm(jwa_t alg) {
    const hint_jose_encryption_t* item = nullptr;
    t_maphint<uint32, const hint_jose_encryption_t*> hint(_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption(jwe_t enc) {
    const hint_jose_encryption_t* item = nullptr;
    t_maphint<uint32, const hint_jose_encryption_t*> hint(_enc_map);

    hint.find(enc, &item);
    return item;
}

const hint_signature_t* crypto_advisor::hintof_signature(crypt_sig_t sig) {
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_crypt_sig_map);

    hint.find(sig, &item);
    return item;
}

const hint_signature_t* crypto_advisor::hintof_jose_signature(jws_t sig) {
    const hint_signature_t* item = nullptr;
    t_maphint<uint32, const hint_signature_t*> hint(_jose_sig_map);

    hint.find(sig, &item);
    return item;
}

const hint_cose_algorithm_t* crypto_advisor::hintof_cose_algorithm(cose_alg_t alg) {
    const hint_cose_algorithm_t* item = nullptr;
    t_maphint<uint32, const hint_cose_algorithm_t*> hint(_cose_alg_map);

    hint.find(alg, &item);
    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve_nid(uint32 nid) {
    const hint_curve_t* item = nullptr;
    t_maphint<uint32, const hint_curve_t*> hint(_curve_bynid_map);

    hint.find(nid, &item);
    return item;
}

const hint_curve_t* crypto_advisor::hintof_curve(cose_ec_curve_t curve) {
    const hint_curve_t* item = nullptr;
    t_maphint<cose_ec_curve_t, const hint_curve_t*> hint(_cose_curve_map);

    hint.find(curve, &item);
    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_algorithm(const char* alg) {
    const hint_jose_encryption_t* item = nullptr;

    if (alg) {
        t_maphint<std::string, const hint_jose_encryption_t*> hint(_alg_byname_map);
        hint.find(alg, &item);
    }

    return item;
}

const hint_jose_encryption_t* crypto_advisor::hintof_jose_encryption(const char* enc) {
    const hint_jose_encryption_t* item = nullptr;

    if (enc) {
        t_maphint<std::string, const hint_jose_encryption_t*> hint(_enc_byname_map);
        hint.find(enc, &item);
    }

    return item;
}

const hint_signature_t* crypto_advisor::hintof_jose_signature(const char* sig) {
    const hint_signature_t* item = nullptr;

    if (sig) {
        t_maphint<std::string, const hint_signature_t*> hint(_sig_byname_map);
        hint.find(sig, &item);
    }
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

const hint_curve_t* crypto_advisor::hintof_curve(const char* curve) {
    const hint_curve_t* item = nullptr;

    if (curve) {
        t_maphint<std::string, const hint_curve_t*> hint(_nid_bycurve_map);
        hint.find(curve, &item);
    }

    return item;
}

const char* crypto_advisor::nameof_jose_algorithm(jwa_t alg) {
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_algorithm(alg);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_encryption(jwe_t enc) {
    const char* name = nullptr;

    const hint_jose_encryption_t* item = hintof_jose_encryption(enc);

    if (item) {
        name = item->alg_name;
    }
    return name;
}

const char* crypto_advisor::nameof_jose_signature(jws_t sig) {
    const char* name = nullptr;

    const hint_signature_t* item = hintof_jose_signature(sig);

    if (item) {
        name = item->jws_name;
    }
    return name;
}

const char* crypto_advisor::nameof_cose_algorithm(cose_alg_t alg) {
    const char* name = nullptr;

    const hint_cose_algorithm_t* item = hintof_cose_algorithm(alg);

    if (item) {
        name = item->name;
    }
    return name;
}

return_t crypto_advisor::typeof_jose_algorithm(const char* alg, jwa_t& type) {
    return_t ret = errorcode_t::success;

    type = jwa_t::jwa_unknown;
    const hint_jose_encryption_t* item = hintof_jose_algorithm(alg);

    if (item) {
        type = (jwa_t)item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_encryption(const char* enc, jwe_t& type) {
    return_t ret = errorcode_t::success;

    type = jwe_t::jwe_unknown;
    const hint_jose_encryption_t* item = hintof_jose_encryption(enc);

    if (item) {
        type = (jwe_t)item->type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
}

return_t crypto_advisor::typeof_jose_signature(const char* sig, jws_t& type) {
    return_t ret = errorcode_t::success;

    type = jws_t::jws_unknown;
    const hint_signature_t* item = hintof_jose_signature(sig);

    if (item) {
        type = (jws_t)item->jws_type;
    } else {
        ret = errorcode_t::not_found;
    }
    return ret;
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
            for (uint32 i = 0; i < sizeof_hint_kty_names; i++) {
                const hint_kty_name_t* k = hint_kty_names + i;
                if (k->kty == item->kty) {
                    kty = k->name;
                    break;
                }
            }
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
            name = item->name;
        }
    }
    return ret;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, const char* alg) {
    bool test = false;

    __try2 {
        const hint_jose_encryption_t* hint_alg = hintof_jose_algorithm(alg);
        if (hint_alg) {
            test = is_kindof(pkey, (jwa_t)hint_alg->type);
            if (test) {
                __leave2;
            }
        }
        const hint_signature_t* hint_sig = hintof_jose_signature(alg);
        if (hint_sig) {
            test = is_kindof(pkey, hint_sig->jws_type);
            if (test) {
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, jwa_t alg) {
    bool test = false;

    __try2 {
        const hint_jose_encryption_t* hint_enc = hintof_jose_algorithm(alg);
        if (nullptr == hint_enc) {
            __leave2;
        }
        crypto_kty_t kty = typeof_crypto_key(pkey);
        bool cmp1 = (hint_enc->kty == kty);
        bool cmp2 = (hint_enc->alt == crypto_kty_t::kty_unknown) ? true : (hint_enc->alt == kty);
        test = (cmp1 || cmp2);
    }
    __finally2 {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, crypt_sig_t sig) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        // uint32 type = EVP_PKEY_id (pkey);
        crypto_kty_t kty = typeof_crypto_key(pkey);
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);

        const hint_signature_t* hint = hintof_signature(sig);
        bool cond1 = (hint->sig_type == sig);
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
    __finally2 {
        // do nothing
    }
    return test;
}

bool crypto_advisor::is_kindof(const EVP_PKEY* pkey, jws_t sig) {
    bool test = false;

    __try2 {
        if (nullptr == pkey) {
            __leave2;
        }

        // uint32 type = EVP_PKEY_id (pkey);
        crypto_kty_t kty = typeof_crypto_key(pkey);
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);

        const hint_signature_t* hint = hintof_jose_signature(sig);
        bool cond1 = (hint->jws_type == sig);
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
    __finally2 {
        // do nothing
    }
    return test;
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

jws_t crypto_advisor::sigof(crypt_sig_t sig) {
    jws_t type = jws_t::jws_unknown;
    t_maphint<crypt_sig_t, jws_t> hint(_sig2jws_map);

    hint.find(sig, &type);
    return type;
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

crypt_sig_t crypto_advisor::sigof(jws_t sig) {
    crypt_sig_t type = crypt_sig_t::sig_unknown;
    t_maphint<jws_t, crypt_sig_t> hint(_jws2sig_map);

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
