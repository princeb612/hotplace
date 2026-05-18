/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_advisor.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>

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
#if defined DEBUG
    if (istraceable(trace_category_crypto)) {
        unsigned long osslver = OpenSSL_version_num();
        trace_debug_event(trace_category_crypto, trace_event_openssl_info, [&](basic_stream& dbs) -> void { dbs.println("openssl version %x", osslver); });
    }
#endif

    auto set_feature = [&](const std::string& key, uint32 feature) -> void {
        auto pib = _features.emplace(key, feature);
        if (false == pib.second) {         // already exist
            pib.first->second |= feature;  // iterator->second points feature
        }
    };

    for (i = 0; i < sizeof_hint_blockciphers; ++i) {
        auto item = hint_blockciphers + i;
        _blockcipher_map.emplace(typeof_alg(item), item);
    }

    // openssl-3.0
    //   - use EVP_CIPHER_fetch/EVP_CIPHER_free, EVP_MD_fetch/EVP_MD_free
    // openssl-1.1.1
    //   - use EVP_get_cipherbyname, EVP_get_digestbyname (run-time)
    //     EVP_CIPHER* and EVP_MD* at extern const structure return nullptr (constexpr in compile-time)
    //   - not provided "aes-128-wrap", "aes-192-wrap", "aes-256-wrap"
    //     [FAIL] const EVP_CIPHER* cipher = EVP_get_cipherbyname("aes-128-wrap");
    //     [PASS] const EVP_CIPHER* cipher = crypto_advisor::get_instance()->find_evp_cipher("aes-128-wrap");

    for (i = 0; i < sizeof_evp_cipher_methods; ++i) {
        auto item = evp_cipher_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(nullptr, nameof_alg(item), nullptr);
        if (evp_cipher) {
            _cipher_fetch_map.emplace(item->scheme, cipher_fetch_block_t(evp_cipher, item));
            _evp_cipher_map.emplace(evp_cipher, item);
        }
#else
        const EVP_CIPHER* evp_cipher = EVP_get_cipherbyname(nameof_alg(item));
        if (evp_cipher) {
            _cipher_fetch_map.emplace(CRYPTO_SCHEME16(typeof_alg(item), typeof_mode(item)), cipher_fetch_block_t((EVP_CIPHER*)evp_cipher, item));
            _evp_cipher_map.emplace(evp_cipher, item);
        }
#endif
#if defined DEBUG
        if (istraceable(trace_category_crypto, loglevel_debug)) {
            // __trace(errorcode_t::debug, "%s", nameof_alg(item));
            if (nullptr == evp_cipher) {
                trace_debug_event(trace_category_crypto, trace_event_openssl_nosupport, [&](basic_stream& dbs) -> void { dbs.println("no %s", nameof_alg(item)); });
            } else {
                trace_debug_event(trace_category_crypto, trace_event_openssl_info, [&](basic_stream& dbs) -> void { dbs.println("%s", nameof_alg(item)); });
            }
        }
#endif

        _cipher_byname_map.emplace(nameof_alg(item), item);

        if (evp_cipher) {
            set_feature(nameof_alg(item), advisor_feature_cipher);
        }

        _cipher_scheme_map.emplace(item->scheme, item);
    }

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    // workaround for openssl-1.1.1 - EVP_CIPHER_fetch("aes-128-wrap") return nullptr
    for (i = 0; i < sizeof_ossl1_aes_wrap_methods; ++i) {
        auto item = ossl1_aes_wrap_methods + i;
        if (item->_cipher) {
            cipher_fetch_block_t block((EVP_CIPHER*)item->_cipher, &item->hint);
            // distinguish between crypto_scheme_aes_128_gcm and crypto_scheme_tls_aes_128_gcm
            _cipher_fetch_map.emplace(CRYPTO_SCHEME16(item->hint.algorithm, item->hint.mode), std::move(block));
            _evp_cipher_map.emplace(item->_cipher, &item->hint);

            set_feature(item->hint.fetchname, advisor_feature_wrap);
        }
    }
#endif

    for (i = 0; i < sizeof_evp_md_methods; ++i) {
        auto item = evp_md_methods + i;
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
        EVP_MD* evp_md = EVP_MD_fetch(nullptr, nameof_alg(item), nullptr);
        if (evp_md) {
            _md_fetch_map.emplace(item->algorithm, md_fetch_block_t(evp_md, item));
        }
#else
        const EVP_MD* evp_md = EVP_get_digestbyname(nameof_alg(item));
        if (evp_md) {
            _md_fetch_map.emplace(typeof_alg(item), md_fetch_block_t((EVP_MD*)evp_md, item));
        }
#endif
        if (nullptr == evp_md) {
#if defined DEBUG
            if (istraceable(trace_category_crypto, loglevel_debug)) {
                // __trace(errorcode_t::debug, "%s", nameof_alg(item));
                trace_debug_event(trace_category_crypto, trace_event_openssl_nosupport, [&](basic_stream& dbs) -> void { dbs.println("no %s", nameof_alg(item)); });
            }
#endif
        }
        _md_byname_map.emplace(nameof_alg(item), item);
        if (item->altname) {
            _md_byname_map.emplace(item->altname, item);  // see query_feature
        }

        if (evp_md) {
            set_feature(nameof_alg(item), advisor_feature_md);
            if (item->altname) {
                set_feature(item->altname, advisor_feature_md);
            }
        }
    }

    ERR_clear_error();  // errors while EVP_CIPHER_fetch, EVP_MD_fetch

    for (i = 0; i < sizeof_hint_jose_algorithms; ++i) {
        auto item = hint_jose_algorithms + i;
        _alg_map.emplace(item->type, item);
        if (item->alg_name) {
            _alg_byname_map.emplace(item->alg_name, item);
        }

        set_feature(item->alg_name, advisor_feature_jwa);
    }
    for (i = 0; i < sizeof_hint_jose_encryptions; ++i) {
        auto item = hint_jose_encryptions + i;
        _enc_map.emplace(item->type, item);
        if (item->alg_name) {
            _enc_byname_map.emplace(item->alg_name, item);
        }

        set_feature(item->alg_name, advisor_feature_jwe);
    }
    for (i = 0; i < sizeof_hint_signatures; ++i) {
        auto item = hint_signatures + i;
        _crypt_sig_map.emplace(item->sig, item);
        if (item->jws_name) {
            _sig_byname_map.emplace(item->jws_name, item);
        }
        if (item->jws_type) {
            _jose_sig_map.emplace(item->jws_type, item);
            _sig2jws_map.emplace(item->sig, item->jws_type);
        }
        for (uint midx = 0; midx < item->count; midx++) {
            _sig_bynid_map.emplace(item->nid[midx], item);
        }

        _sig2jws_map.emplace(item->sig, item->jws_type);
        _jws2sig_map.emplace(item->jws_type, item->sig);
        if (cose_alg_t::cose_unknown != item->cosealg) {
            _sig2cose_map.emplace(item->sig, item->cosealg);
        }
        _cose2sig_map.emplace(item->cosealg, item->sig);

        set_feature(item->jws_name, advisor_feature_jws);
    }
    struct _sig2cose {
        signature_t sig;
        jws_t jws;
        cose_alg_t cose;
    };
    struct _sig2cose cose2sig[] = {
        {signature_t::sig_hs256, jws_t::jws_hs256, cose_alg_t::cose_hs256_64},
    };
    for (i = 0; i < RTL_NUMBER_OF(cose2sig); ++i) {
        _cose2sig_map.emplace(cose2sig[i].cose, cose2sig[i].sig);
    }

    for (i = 0; i < sizeof_hint_sigschemes; ++i) {
        auto item = hint_sigschemes + i;
        _hint_sigscheme_map.emplace(item->scheme, item);
        _hint_sigscheme_nid_map.emplace(item->nid, item);
        _hint_sigscheme_name_map.emplace(item->name, item);
        set_feature(item->name, advisor_feature_sigscheme);
    }
    for (i = 0; i < sizeof_hint_cose_algorithms; ++i) {
        auto item = hint_cose_algorithms + i;
        _cose_alg_map.emplace(item->alg, item);
        _cose_algorithm_byname_map.emplace(item->name, item);

        set_feature(item->name, advisor_feature_cose);
    }
    for (i = 0; i < sizeof_hint_curves; ++i) {
        auto item = hint_curves + i;

        if (item->name_nist) {
            _nid_bycurve_map.emplace(item->name_nist, item);
        }
        if (cose_ec_curve_t::cose_ec_unknown != item->cose_crv) {
            _cose_curve_map.emplace(item->cose_crv, item);
        }
        _curve_bynid_map.emplace(item->id, item);

        // see query_feature
        {
            bool support_ec2 = false;

            if (kty_ec == item->kty) {
                EC_KEY_ptr ec = EC_KEY_ptr(EC_KEY_new_by_curve_name(item->id));
                if (ec.get()) {
                    support_ec2 = true;
                } else {
                    ERR_clear_error();
                }
                // end of ec
            } else if (kty_okp == item->kty) {
                EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(item->id, nullptr));
                if (ctx.get()) {
                    support_ec2 = true;
                } else {
                    ERR_clear_error();
                }
                // end of ctx
            }

            if (support_ec2) {
                if (item->name_nist) {
                    set_feature(item->name_nist, advisor_feature_curve);
                }
                if (item->name_x962) {
                    set_feature(item->name_x962, advisor_feature_curve);
                }
                if (item->name_sec) {
                    set_feature(item->name_sec, advisor_feature_curve);
                }
                if (item->name_bp) {
                    set_feature(item->name_bp, advisor_feature_curve);
                }
                if (item->name_wtls) {
                    set_feature(item->name_wtls, advisor_feature_curve);
                }
            }
        }
        if (item->tlsgroup) {
            _tls_group_curve_map.emplace(item->tlsgroup, item);
        }
        if (item->name_nist) {
            _curve_name_map.emplace(item->name_nist, item);
        }
        if (item->name_x962) {
            _curve_name_map.emplace(item->name_x962, item);
        }
        if (item->name_sec) {
            _curve_name_map.emplace(item->name_sec, item);
        }
        if (item->name_bp) {
            _curve_name_map.emplace(item->name_bp, item);
        }
        if (item->name_wtls) {
            _curve_name_map.emplace(item->name_wtls, item);
        }
        _nid2curve_map.emplace(item->id, item);
    }

    _kty2cose_map.emplace(crypto_kty_t::kty_ec, cose_kty_t::cose_kty_ec2);
    _kty2cose_map.emplace(crypto_kty_t::kty_oct, cose_kty_t::cose_kty_symm);
    _kty2cose_map.emplace(crypto_kty_t::kty_okp, cose_kty_t::cose_kty_okp);
    _kty2cose_map.emplace(crypto_kty_t::kty_rsa, cose_kty_t::cose_kty_rsa);

    _cose2kty_map.emplace(cose_kty_t::cose_kty_ec2, crypto_kty_t::kty_ec);
    _cose2kty_map.emplace(cose_kty_t::cose_kty_symm, crypto_kty_t::kty_oct);
    _cose2kty_map.emplace(cose_kty_t::cose_kty_okp, crypto_kty_t::kty_okp);
    _cose2kty_map.emplace(cose_kty_t::cose_kty_rsa, crypto_kty_t::kty_rsa);

    for (i = 0; i < sizeof_hint_kty_names; ++i) {
        auto item = hint_kty_names + i;
        if (item->name) {
            _kty_names.emplace(item->kty, item);
        }
    }

    for (i = 0; i < sizeof_hint_groups; ++i) {
        auto item = hint_groups + i;
        if (tls_group_unknown != item->group) {
            _tls_group_map.emplace(item->group, item);
            if (0 == (tls_flag_hybrid & item->flags)) {
                _tls_group_nid_map.emplace(item->first.nid, item);
            }
        }
        if (item->name) {
            std::string key = item->name;
            std::transform(key.begin(), key.end(), key.begin(), tolower);  // ignore case
            _tls_group_name_map.emplace(std::move(key), item);

            set_feature(item->name, advisor_feature_tlsgroup);
        }
    }

    {
        struct mapdata {
            const char* feature;
            unsigned long version;
        } _table[] = {
            // 3.0 scrypt
            {"scrypt", 0x30000000},
            // 3.2 argon
            {"argon2d", 0x30200000},
            {"argon2i", 0x30200000},
            {"argon2id", 0x30200000},
            // 3.5 ML-KEM
            {"ML-KEM-512", 0x30500000},
            {"ML-KEM-768", 0x30500000},
            {"ML-KEM-1024", 0x30500000},
            {"SecP256r1MLKEM768", 0x30500000},
            {"X25519MLKEM768", 0x30500000},
            {"SecP384r1MLKEM1024", 0x30500000},
        };
        for (auto item : _table) {
            _features.emplace(item.feature, advisor_feature_version);
            _versions.emplace(item.feature, item.version);
        }
    }
    {
        _ae_names.emplace(tls_mac_then_encrypt, "mac_then_encrypt");   // TLS
        _ae_names.emplace(jose_encrypt_then_mac, "encrypt_then_mac");  // JOSE
        _ae_names.emplace(tls_encrypt_then_mac, "encrypt_then_mac");   // TLS
    }

    return ret;
}

return_t crypto_advisor::cleanup() {
    return_t ret = errorcode_t::success;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    critical_section_guard guard(_lock);
    for (auto& pair : _cipher_fetch_map) {
        auto& cipher = pair.second.cipher;
        EVP_CIPHER_free(cipher);
    }
    _cipher_fetch_map.clear();
    for (auto& pair : _md_fetch_map) {
        auto& md = pair.second.md;
        EVP_MD_free(md);
    }
    _md_fetch_map.clear();
#endif

    return ret;
}

uint32 crypto_advisor::query_feature(const char* feature, uint32 spec) {
    uint32 ret = 0;
    if (feature) {
        ret = query_feature(std::string(feature), spec);
    }
    return ret;
}

uint32 crypto_advisor::query_feature(const std::string& feature, uint32 spec) {
    uint32 ret = 0;
    auto iter = _features.find(feature);
    if (_features.end() != iter) {
        const uint32& flags = iter->second;
        if (advisor_feature_version & flags) {
            unsigned long osslver = OpenSSL_version_num();
            auto ver = _versions[feature];
            ret = (osslver >= ver);
        } else if (spec) {
            ret = (flags & spec);
        } else {
            ret = flags;
        }
    }
    return ret;
}

bool crypto_advisor::check_minimum_version(unsigned long osslver) {
    unsigned long ver = OpenSSL_version_num();
    return (ver >= osslver) ? true : false;
}

void crypto_advisor::for_each_features(std::function<void(const char* name, uint32 spec)> fn) {
    if (fn) {
        for (auto item : _features) {
            fn(item.first.c_str(), item.second);
        }
    }
}

void crypto_advisor::get_cookie_secret(uint8 key, size_t secret_size, binary_t& secret) {
    auto iter = _cookie_secret.find(key);
    if (_cookie_secret.end() == iter) {
        openssl_prng prng;
        prng.random(secret, secret_size);
        _cookie_secret.emplace(key, secret);
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
