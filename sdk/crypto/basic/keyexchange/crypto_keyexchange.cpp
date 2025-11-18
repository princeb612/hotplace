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

        auto nid = hint->nid;
        auto kty = hint->kty;

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
            auto hnid = hint->hnid;
            ret = keychain.add(key, hnid, desc);
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

        auto nid = hint->nid;
        auto kty = hint->kty;

        // keygen
        crypto_keychain keychain;

        binary_t bin_privkey;
        auto prk = key->find_nid(kid, nid);
        ret = key->get_key(prk, public_key, share, bin_privkey, true);
        if (success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            // keygen
            auto hnid = hint->hnid;
            // ret = keychain.add(key, hnid, keydesc(kid));

            /**
             * public key
             *   case kty_ec: uncompressed format
             *   default: raw format
             */
            binary_t hshare;
            auto hkey = key->find_nid(kid, hnid);
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
        // auto flags = hint->flags;
        // if (0 == (tls_flag_support & flags)) {
        //     ret = errorcode_t::not_supported;
        //     __leave2;
        // }

        auto nid = hint->nid;
        auto kty = hint->kty;

        crypto_keychain keychain;
        binary_t bin_privkey;
        switch (kty) {
            case kty_dh: {
                ret = keychain.add_dh(storage, nid, share, bin_privkey, keydesc(kid));
            } break;
            case kty_ec: {
                ret = keychain.add_ec_uncompressed(storage, nid, share, bin_privkey, keydesc(kid));
            } break;
            case kty_okp: {
                ret = keychain.add_okp(storage, nid, share, bin_privkey, keydesc(kid));
            } break;
            case kty_mlkem: {
                ret = keychain.add_mlkem_pub(storage, nid, share, key_encoding_pub_raw, keydesc(kid));
            } break;
            default: {
                ret = bad_request;
            } break;
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
    EVP_PKEY* pkey = nullptr;
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

        auto keysize = hint->keysize;
        auto hkeysize = hint->hkeysize;
        auto expect_share = keysize + hkeysize;
        if (expect_share != share.size()) {
            ret = unexpected;
            __leave2;
        }

        const char* name = nullptr;
        const char* hname = nullptr;
        switch (group) {
            case tls_group_mlkem512: {
                name = "ML-KEM-512";
            } break;
            case tls_group_secp256r1mlkem768: {
                name = "ML-KEM-768";
                hname = "secp256r1";
            } break;
            case tls_group_mlkem768: {
                name = "ML-KEM-768";
            } break;
            case tls_group_x25519mlkem768: {
                name = "ML-KEM-768";
                hname = "x25519";
            } break;
            case tls_group_mlkem1024: {
                name = "ML-KEM-1024";
            } break;
            case tls_group_secp384r1mlkem1024: {
                name = "ML-KEM-1024";
                hname = "secp384r1";
            } break;
            default: {
                ret = not_supported;
            }
        }
        if (success != ret) {
            __leave2;
        }

        openssl_pqc pqc;
        binary_t kc;
        binary_t ss;
        ret = pqc.decode(nullptr, name, &pkey, &share[0], keysize, key_encoding_pub_raw);
        if (success != ret) {
            __leave2;
        }
        ret = pqc.encapsule(nullptr, pkey, kc, ss);
        if (success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            crypto_key tempkey;
            crypto_keychain keychain;
            auto hkty = hint->hkty;
            auto hnid = hint->hnid;

            binary_t bin_pubkey;
            binary_t bin_privkey;
            binary_append(bin_pubkey, &share[keysize], hkeysize);

            switch (hkty) {
                case kty_ec: {
                    keychain.add_ec_uncompressed(&tempkey, hnid, bin_pubkey, bin_privkey, keydesc("pub"));
                } break;
                case kty_okp: {
                    keychain.add_okp(&tempkey, hnid, bin_pubkey, bin_privkey, keydesc("pub"));
                } break;
            }

            keychain.add(&tempkey, hnid, keydesc("epk"));

#if defined DEBUG
            if (istraceable(trace_category_crypto, loglevel_debug)) {
                trace_debug_event(trace_category_crypto, trace_event_keyexchange, [&](basic_stream& dbs) -> void {
                    dbs.println("\e[1;33mtemporary keys\e[0m");
                    tempkey.for_each([&](crypto_key_object* obj, void*) -> void {
                        dbs.println("\e[1;32m> kid \"%s\"\e[0m", obj->get_desc().get_kid_cstr());
                        dump_key(obj->get_pkey(), &dbs, 15, 4, dump_notrunc);
                    });
                });
            }
#endif

            binary_t hybrid_kc;
            binary_t hybrid_ss;
            auto prk = tempkey.find("epk");
            auto pbk = tempkey.find("pub");
            ret = dh_key_agreement(prk, pbk, hybrid_ss);
            if (success != ret) {
                __leave2;
            }

            tempkey.get_key(prk, public_key, hybrid_kc, bin_privkey, true);
            binary_append(kc, hybrid_kc);
            binary_append(ss, hybrid_ss);
        }

        keycapsule = std::move(kc);
        sharedsecret = std::move(ss);
    }
    __finally2 {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
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

        auto capsulesize = hint->capsulesize;
        auto hkeysize = hint->hkeysize;
        auto expect_share = capsulesize + hkeysize;
        if (expect_share != share.size()) {
            ret = unexpected;
            __leave2;
        }

        crypto_key pubkey;
        openssl_pqc pqc;
        binary_t ss;
        auto nid = hint->nid;
        auto kty = hint->kty;

        auto pkey = key->find_nid(kid, nid);
        ret = pqc.decapsule(nullptr, pkey, &share[0], capsulesize, ss);
        if (success != ret) {
            __leave2;
        }

        if (tls_flag_hybrid & hint->flags) {
            auto hkty = hint->hkty;
            auto hnid = hint->hnid;
            auto hkeysize = hint->hkeysize;

            crypto_key tempkey;
            crypto_keychain keychain;

            binary_t bin_pubkey;
            binary_t bin_privkey;
            binary_append(bin_pubkey, &share[capsulesize], hkeysize);

            switch (hkty) {
                case kty_ec: {
                    keychain.add_ec_uncompressed(&tempkey, hnid, bin_pubkey, bin_privkey, keydesc("pub"));
                } break;
                case kty_okp: {
                    keychain.add_okp(&tempkey, hnid, bin_pubkey, bin_privkey, keydesc("pub"));
                } break;
            }

#if defined DEBUG
            if (istraceable(trace_category_crypto, loglevel_debug)) {
                trace_debug_event(trace_category_crypto, trace_event_keyexchange, [&](basic_stream& dbs) -> void {
                    dbs.println("\e[1;33mtemporary keys\e[0m");
                    tempkey.for_each([&](crypto_key_object* obj, void*) -> void {
                        dbs.println("\e[1;32m> kid \"%s\"\e[0m", obj->get_desc().get_kid_cstr());
                        dump_key(obj->get_pkey(), &dbs, 15, 4, dump_notrunc);
                    });
                });
            }
#endif

            auto prk = key->find_nid(kid, hnid);
            auto pbk = tempkey.find_nid("pub", hnid);

            binary_t hybrid_ss;
            ret = dh_key_agreement(prk, pbk, hybrid_ss);
            if (success != ret) {
                __leave2;
            }

            binary_append(ss, hybrid_ss);
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
