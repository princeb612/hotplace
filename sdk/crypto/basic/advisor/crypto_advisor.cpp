/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>

namespace hotplace {
namespace crypto {

crypto_advisor crypto_advisor::_instance;

crypto_advisor* crypto_advisor::get_instance() {
    _instance.load();
    return &_instance;
}

crypto_advisor::crypto_advisor() : _flag(0) {}

crypto_advisor::~crypto_advisor() { cleanup(); }

return_t crypto_advisor::load() {
    return_t ret = errorcode_t::success;
    if (0 == _flag) {
        critical_section_guard guard(_lock);
        if (0 == _flag) {
            build();
            _flag = 1;
        }
    }
    return ret;
}

return_t crypto_advisor::build() {
    return_t ret = errorcode_t::success;

    uint32 i = 0;
    unsigned long osslver = OpenSSL_version_num();
#if defined DEBUG
    if (istraceable(trace_category_crypto)) {
        trace_debug_event(trace_category_crypto, trace_event_openssl_info, "openssl version %x\n", osslver);
    }
#endif

    auto set_feature = [&](const std::string& key, uint32 feature) -> void {
        auto pib = _features.insert({key, feature});
        if (false == pib.second) {         // already exist
            pib.first->second |= feature;  // iterator->second points feature
        }
    };

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
            _cipher_map.insert(std::make_pair(CRYPTO_SCHEME16(typeof_alg(item), typeof_mode(item)), evp_cipher));
            _evp_cipher_map.insert(std::make_pair(evp_cipher, item));
        }
#else
        const EVP_CIPHER* evp_cipher = EVP_get_cipherbyname(nameof_alg(item));
        if (evp_cipher) {
            _cipher_map.insert(std::make_pair(CRYPTO_SCHEME16(typeof_alg(item), typeof_mode(item)), (EVP_CIPHER*)evp_cipher));
            _evp_cipher_map.insert(std::make_pair(evp_cipher, item));
        }
#endif
        if (nullptr == evp_cipher) {
#if defined DEBUG
            if (istraceable(trace_category_crypto, loglevel_debug)) {
                // __trace(errorcode_t::debug, "%s", nameof_alg(item));
                trace_debug_event(trace_category_crypto, trace_event_openssl_nosupport, "no %s\n", nameof_alg(item));
            }
#endif
        }

        _cipher_fetch_map.insert(std::make_pair(CRYPTO_SCHEME16(typeof_alg(item), typeof_mode(item)), item));
        _cipher_byname_map.insert(std::make_pair(nameof_alg(item), item));

        if (evp_cipher) {
            set_feature(nameof_alg(item), advisor_feature_cipher);
        }

        _cipher_scheme_map.insert({item->scheme, item});
    }

    for (i = 0; i < sizeof_aes_wrap_methods; i++) {
        const openssl_evp_cipher_method_older_t* item = aes_wrap_methods + i;
        if (osslver < 0x30000000L) {
            _cipher_map.insert(std::make_pair(CRYPTO_SCHEME16(item->method.algorithm, item->method.mode), (EVP_CIPHER*)item->_cipher));
            _evp_cipher_map.insert(std::make_pair(item->_cipher, &item->method));
        }

        set_feature(item->method.fetchname, advisor_feature_cipher);  // workaround for openssl-1.1.1 - EVP_CIPHER_fetch("aes-128-wrap") return nullptr
        set_feature(item->method.fetchname, advisor_feature_wrap);
    }

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
#if defined DEBUG
            if (istraceable(trace_category_crypto, loglevel_debug)) {
                // __trace(errorcode_t::debug, "%s", nameof_alg(item));
                trace_debug_event(trace_category_crypto, trace_event_openssl_nosupport, "no %s\n", nameof_alg(item));
            }
#endif
        }
        _md_fetch_map.insert(std::make_pair(typeof_alg(item), item));
        _md_byname_map.insert(std::make_pair(nameof_alg(item), item));

        if (evp_md) {
            set_feature(nameof_alg(item), advisor_feature_md);
        }
    }

    ERR_clear_error();  // errors while EVP_CIPHER_fetch, EVP_MD_fetch

    for (i = 0; i < sizeof_hint_jose_algorithms; i++) {
        const hint_jose_encryption_t* item = hint_jose_algorithms + i;
        _alg_map.insert(std::make_pair(item->type, item));
        if (item->alg_name) {
            _alg_byname_map.insert(std::make_pair(item->alg_name, item));
        }

        set_feature(item->alg_name, advisor_feature_jwa);
    }
    for (i = 0; i < sizeof_hint_jose_encryptions; i++) {
        const hint_jose_encryption_t* item = hint_jose_encryptions + i;
        _enc_map.insert(std::make_pair(item->type, item));
        if (item->alg_name) {
            _enc_byname_map.insert(std::make_pair(item->alg_name, item));
        }

        set_feature(item->alg_name, advisor_feature_jwe);
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

        set_feature(item->jws_name, advisor_feature_jws);
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

        set_feature(item->name, advisor_feature_cose);
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

        if (item->name) {
            set_feature(item->name, advisor_feature_curve);
            _curve_name_map.insert({item->name, item});
        }
        if (item->tlsgroup) {
            _tls_group_map.insert({item->tlsgroup, item});
        }
        if (item->aka1) {
            _curve_name_map.insert({item->aka1, item});
        }
        if (item->aka2) {
            _curve_name_map.insert({item->aka2, item});
        }
        if (item->aka3) {
            _curve_name_map.insert({item->aka3, item});
        }
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

    for (i = 0; i < sizeof_hint_kty_names; i++) {
        auto item = hint_kty_names + i;
        if (item->name) {
            _kty_names.insert({item->kty, item});
        }
    }

    {
        struct mapdata {
            const char* feature;
            unsigned long version;
        } _table[] = {
            // scrypt 3.0
            {"scrypt", 0x30000000},
            // argon 3.2
            {"argon2d", 0x30200000},
            {"argon2i", 0x30200000},
            {"argon2id", 0x30200000},
        };
        for (auto item : _table) {
            _features.insert({item.feature, advisor_feature_version});
            _versions.insert({item.feature, item.version});
        }
    }
    {
        _ae_names.insert({tls_mac_then_encrypt, "mac_then_encrypt"});   // TLS
        _ae_names.insert({jose_encrypt_then_mac, "encrypt_then_mac"});  // JOSE
        _ae_names.insert({tls_encrypt_then_mac, "encrypt_then_mac"});   // TLS
    }

    return ret;
}

return_t crypto_advisor::cleanup() {
    return_t ret = errorcode_t::success;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    for (auto& pair : _cipher_map) {
        EVP_CIPHER_free(pair.second);
    }
    for (auto& pair : _md_map) {
        EVP_MD_free(pair.second);
    }
#endif

    return ret;
}

bool crypto_advisor::query_feature(const char* feature, uint32 spec) {
    bool ret = false;
    if (feature) {
        std::string key = feature;
        auto iter = _features.find(key);
        if (_features.end() != iter) {
            const uint32& flags = iter->second;
            if (advisor_feature_version & flags) {
                unsigned long osslver = OpenSSL_version_num();
                auto ver = _versions[key];
                ret = (osslver >= ver);
            } else if (spec) {
                ret = (flags & spec);
            } else {
                ret = true;
            }
        }
    }
    return ret;
}

bool crypto_advisor::check_minimum_version(unsigned long osslver) {
    unsigned long ver = OpenSSL_version_num();
    return (ver >= osslver) ? true : false;
}

void crypto_advisor::get_cookie_secret(uint8 key, size_t secret_size, binary_t& secret) {
    auto iter = _cookie_secret.find(key);
    if (_cookie_secret.end() == iter) {
        openssl_prng prng;
        prng.random(secret, secret_size);
        _cookie_secret.insert({key, secret});
    } else {
        secret = iter->second;
    }
}

std::string crypto_advisor::nameof_authenticated_encryption(uint16 code) {
    std::string value;
    auto iter = _ae_names.find(code);
    if (_ae_names.end() != iter) {
        value = iter->second;
    }
    return value;
}

}  // namespace crypto
}  // namespace hotplace
