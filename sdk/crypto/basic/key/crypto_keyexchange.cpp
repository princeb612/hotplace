/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/dump_memory.hpp>  // dump_notrunc
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_key.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keyexchange.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_pqc.hpp>

namespace hotplace {
namespace crypto {

crypto_keyexchange::crypto_keyexchange(tls_group_t group) : _group(group) { _shared.make_share(this); }

crypto_keyexchange::~crypto_keyexchange() {}

return_t crypto_keyexchange::keygen(crypto_key* key, const char* kid, binary_t& share) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto group = get_group();

        ret = keygen(group, key, kid);
        if (success != ret) {
            __leave2;
        }

        ret = keyshare(group, key, kid, share);
        if (success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::exchange(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto group = get_group();

        crypto_key ephemeral;
        ret = exchange(group, key, &ephemeral, kid, "pub", share, sharedsecret);
        if (success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::encaps(const binary_t& share, binary_t& keycapsule, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto group = get_group();

        ret = encaps(group, share, keycapsule, sharedsecret);
        if (success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::decaps(crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto group = get_group();

        ret = decaps(group, key, kid, share, sharedsecret);
        if (success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

tls_group_t crypto_keyexchange::get_group() { return _group; }

return_t crypto_keyexchange::keygen(tls_group_t group, crypto_key* key, const char* kid) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto nid = hint->first.nid;
        auto kty = hint->first.kty;

        auto pkey = key->find_nid(kid, nid);
        if (pkey) {
            ret = already_exist;
            __leave2;
        }

        // keygen
        crypto_keychain keychain;
        keydesc desc(kid);
        ret = keychain.add(key, nid, desc);
        if (success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            // keygen
            const auto& hybrid = hint->second;
            ret = keychain.add(key, hybrid.nid, desc);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::keyshare(tls_group_t group, crypto_key* key, const char* kid, binary_t& share) {
    return_t ret = errorcode_t::success;
    __try2 {
        share.clear();

        if (nullptr == key) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto nid = hint->first.nid;
        auto kty = hint->first.kty;

        // keygen
        crypto_keychain keychain;
        binary_t bin_privkey;  // dummy

        auto prk = key->find_nid(kid, nid);
        ret = key->get_key(prk, public_key, share, bin_privkey, true);
        if (success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            // keygen
            const auto& hybrid = hint->second;

            /**
             * public key
             *   case kty_ec: uncompressed format
             *   default: raw format
             */
            binary_t hshare;
            auto hkey = key->find_nid(kid, hybrid.nid);
            ret = key->get_key(hkey, public_key, hshare, bin_privkey, true);
            if (success != ret) {
                __leave2;
            }
            binary_append(share, hshare);
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::keystore(tls_group_t group, crypto_key* storage, const char* kid, const binary_t& share) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == storage) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        if (hint->first.keysize + hint->second.keysize != share.size()) {
            ret = bad_data;
            __leave2;
        }

        auto nid = hint->first.nid;
        auto kty = hint->first.kty;
        size_t keysize = hint->first.keysize;

        crypto_keychain keychain;
        binary_t bin_privkey;  // dummy
        keydesc desc(kid);
        switch (kty) {
            case kty_dh: {
                ret = keychain.add_dh(storage, nid, share, bin_privkey, desc);
            } break;
            case kty_ec: {
                ret = keychain.add_ec_uncompressed(storage, nid, &share[0], keysize, nullptr, 0, desc);
            } break;
            case kty_okp: {
                ret = keychain.add_okp(storage, nid, &share[0], keysize, nullptr, 0, desc);
            } break;
            case kty_mlkem: {
                ret = keychain.add_mlkem_pub(storage, nid, &share[0], keysize, key_encoding_pub_raw, desc);
            } break;
            default: {
                ret = bad_request;
            } break;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            const auto& hybrid = hint->second;
            switch (hybrid.kty) {
                case kty_okp: {
                    ret = keychain.add_okp(storage, hybrid.nid, &share[keysize], hybrid.keysize, nullptr, 0, desc);
                } break;
                case kty_mlkem: {
                    ret = keychain.add_mlkem_pub(storage, hybrid.nid, &share[keysize], hybrid.keysize, key_encoding_pub_raw, desc);
                } break;
                default: {
                    ret = bad_request;
                } break;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::exchange(tls_group_t group, crypto_key* key, crypto_key* ephemeral, const char* kid, const char* epkid, const binary_t& share,
                                      binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == key || nullptr == ephemeral || nullptr == kid || nullptr == epkid) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        if (keyexchange_ecdhe != hint->exch) {
            ret = bad_request;
            __leave2;
        }

        ret = keystore(group, ephemeral, epkid, share);
        if (success != ret) {
            __leave2;
        }

        // ECDH
        auto prk = key->find(kid, group);
        auto pbk = ephemeral->find(epkid, group);
        ret = dh_key_agreement(prk, pbk, sharedsecret);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::exchange(tls_group_t group, crypto_key* key, crypto_key* ephemeral, const char* kid, const char* epkid, const char* shareid,
                                      binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == key || nullptr == ephemeral || nullptr == kid || nullptr == epkid) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        if (keyexchange_ecdhe != hint->exch) {
            ret = bad_request;
            __leave2;
        }

        // ECDH
        auto prk = key->find(kid, group);
        auto pbk = ephemeral->find(epkid, group);
        ret = dh_key_agreement(prk, pbk, sharedsecret);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::encaps(tls_group_t group, const binary_t& share, binary_t& keycapsule, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        if (keyexchange_mlkem != hint->exch) {
            ret = bad_request;
            __leave2;
        }

        crypto_key key;
        crypto_keychain keychain;
        openssl_pqc pqc;

        const char* kid = "clientshare";
        const char* epkid = "epk";

        ret = keystore(group, &key, kid, share);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        const auto& first = hint->first;
        const auto& second = hint->second;

        binary_t kc;
        binary_t ss;

        switch (first.kty) {
            case kty_mlkem: {
                auto pkey = key.find_nid(kid, first.nid);
                ret = pqc.encapsule(nullptr, pkey, kc, ss);
            } break;
            case kty_ec: {
                ret = keychain.add(&key, first.nid, keydesc(epkid));  // hybrid
            } break;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            /**
             * kty_ec || kty_mlkem
             *   tls_group_secp256r1mlkem768
             *   tls_group_secp384r1mlkem1024
             * kty_mlkem || kty_okp
             *   tls_group_x25519mlkem768
             */

            auto hkey = key.find_nid(kid, second.nid);
            switch (second.kty) {
                case kty_mlkem: {
                    ret = pqc.encapsule(nullptr, hkey, kc, ss);
                } break;
                case kty_okp: {
                    keychain.add(&key, second.nid, keydesc(epkid));
                } break;
                default: {
                    ret = not_supported;
                } break;
            }

            binary_t hybrid_kc;
            binary_t hybrid_ss;
            auto prk = key.find(epkid);
            auto pbk = key.find_nid(kid, (kty_mlkem == first.kty) ? second.nid : first.nid);

#if defined DEBUG
            if (istraceable(trace_category_crypto, loglevel_debug)) {
                trace_debug_event(trace_category_crypto, trace_event_keyexchange, [&](basic_stream& dbs) -> void {
                    dbs.println("\e[1;33mepk\e[0m");
                    dump_key(prk, &dbs, 15, 4, dump_notrunc);
                });
            }
#endif

            ret = dh_key_agreement(prk, pbk, hybrid_ss);
            if (success != ret) {
                __leave2;
            }

            binary_t bin_privkey;  // dummy
            key.get_key(prk, public_key, hybrid_kc, bin_privkey, true);

            switch (first.kty) {
                case kty_ec: {
                    kc.insert(kc.begin(), hybrid_kc.begin(), hybrid_kc.end());
                    ss.insert(ss.begin(), hybrid_ss.begin(), hybrid_ss.end());
                } break;
                case kty_mlkem: {
                    binary_append(kc, hybrid_kc);
                    binary_append(ss, hybrid_ss);
                } break;
                default: {
                    ret = not_supported;
                } break;
            }
        }

        keycapsule = std::move(kc);
        sharedsecret = std::move(ss);
    }
    __finally2 {}
    return ret;
}

return_t crypto_keyexchange::decaps(tls_group_t group, crypto_key* key, const char* kid, const binary_t& share, binary_t& sharedsecret) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto advisor = crypto_advisor::get_instance();
        auto hint = advisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        if (keyexchange_mlkem != hint->exch) {
            ret = bad_request;
            __leave2;
        }

        const auto& first = hint->first;
        const auto& second = hint->second;
        size_t expect_size = (kty_mlkem == first.kty) ? first.capsulesize + second.keysize : first.keysize + second.capsulesize;
        if (expect_size != share.size()) {
            ret = bad_data;
            __leave2;
        }

        const char* sskid = "servershare";

        crypto_key tempkey;
        crypto_keychain keychain;
        openssl_pqc pqc;
        binary_t ss;
        auto capsulesize = first.capsulesize;
        auto keysize = first.keysize;
        keydesc desc(sskid);

        switch (first.kty) {
            case kty_mlkem: {
                auto pkey = key->find_nid(kid, first.nid);
                ret = pqc.decapsule(nullptr, pkey, &share[0], capsulesize, ss);
            } break;
            case kty_ec: {
                ret = keychain.add_ec_uncompressed(&tempkey, first.nid, &share[0], keysize, nullptr, 0, desc);
            } break;
            default: {
                ret = not_supported;
            } break;
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            switch (second.kty) {
                case kty_mlkem: {
                    auto pkey = key->find_nid(kid, second.nid);
                    ret = pqc.decapsule(nullptr, pkey, &share[keysize], second.capsulesize, ss);
                } break;
                case kty_okp: {
                    ret = keychain.add_okp(&tempkey, second.nid, &share[capsulesize], second.keysize, nullptr, 0, desc);
                } break;
                default: {
                    ret = not_supported;
                } break;
            }
            if (errorcode_t::success != ret) {
                __leave2;
            }

            auto ecnid = (kty_mlkem == first.kty) ? second.nid : first.nid;
            auto prk = key->find_nid(kid, ecnid);
            auto pbk = tempkey.find_nid(sskid, ecnid);

#if defined DEBUG
            if (istraceable(trace_category_crypto, loglevel_debug)) {
                trace_debug_event(trace_category_crypto, trace_event_keyexchange, [&](basic_stream& dbs) -> void {
                    dbs.println("\e[1;33m%s\e[0m", kid);
                    dump_key(prk, &dbs, 15, 4, dump_notrunc);
                    dbs.println("\e[1;33m%s\e[0m", sskid);
                    dump_key(pbk, &dbs, 15, 4, dump_notrunc);
                });
            }
#endif

            binary_t hybrid_ss;
            ret = dh_key_agreement(prk, pbk, hybrid_ss);
            if (success != ret) {
                __leave2;
            }

            switch (group) {
                case tls_group_secp256r1mlkem768:
                case tls_group_secp384r1mlkem1024: {
                    ss.insert(ss.begin(), hybrid_ss.begin(), hybrid_ss.end());
                } break;
                case tls_group_x25519mlkem768: {
                    binary_append(ss, hybrid_ss);
                } break;
            }
        }

        sharedsecret = std::move(ss);
    }
    __finally2 {}
    return ret;
}

void crypto_keyexchange::addref() { _shared.addref(); }

void crypto_keyexchange::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
