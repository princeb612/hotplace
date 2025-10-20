/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_keychain.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/openssl_pqc.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_key_share_entry[] = "key share entry";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_group[] = "group";
constexpr char constexpr_pubkey_len[] = "public key len";
constexpr char constexpr_pubkey[] = "public key";

tls_extension_key_share::tls_extension_key_share(tls_handshake* handshake) : tls_extension(tls_ext_key_share, handshake) {}

tls_extension_key_share::~tls_extension_key_share() {}

return_t tls_extension_key_share::add(uint16 group) { return errorcode_t::success; }

return_t tls_extension_key_share::add(const std::string& group) { return errorcode_t::success; }

return_t tls_extension_key_share::add(uint16 group, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_curve_tls_group(group);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto flags = hint->flags;
        if (0 == (tls_flag_support & flags)) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto kty = hint->kty;
        auto nid = hint->nid;
        auto hkty = hint->hkty;
        auto hnid = hint->hnid;

        if (from_server == dir) {
            if (tls_flag_pqc & flags) {
                kty = kty_unknown;  // refer PQC encaps
                if (tls_flag_hybrid & flags) {
                    // add hybrid keypair only
                } else {
                    // do nothing
                    __leave2;
                }
            }
        }

        auto session = get_handshake()->get_session();

        std::string privkid;
        std::string pubkid;
        if (from_client == dir) {
            privkid = KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE;
            pubkid = KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC;
        } else {
            privkid = KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE;
            pubkid = KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC;
        }

        auto& protection = session->get_tls_protection();
        auto& keyshare = protection.get_keyexchange();

        // add key into session-level key collections
        auto lambda_add = [&](crypto_kty_t type, uint32 osslnid) -> void {
            return_t test = success;
            if (kty_unknown != type) {
                crypto_keychain keychain;
                keydesc desc(privkid);
                switch (type) {
                    case kty_ec:
                    case kty_okp: {
                        ret = keychain.add_ec2(&keyshare, osslnid, desc);
                    } break;
                    case kty_dh: {
                        ret = keychain.add_dh(&keyshare, osslnid, desc);
                    } break;
                    case kty_mlkem: {
                        ret = keychain.add_mlkem(&keyshare, osslnid, desc);
                    } break;
                    default: {
                        ret = do_nothing;
                    } break;
                }
                if (success == ret) {
                    auto pkey = keyshare.find_group(desc.get_kid_cstr(), group);
                    keyshare.add((EVP_PKEY*)pkey, pubkid.c_str(), true);

#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                            tls_advisor* tlsadvisor = tls_advisor::get_instance();
                            dbs.println("\e[1;32m+ add keypair %s (group %s kty %s)\e[0m", desc.get_kid_cstr(), tlsadvisor->supported_group_name(group).c_str(),
                                        advisor->nameof_kty(kty));
                        });
                    }
#endif
                }
            }
        };

        lambda_add(kty, nid);
        lambda_add(hkty, hnid);
    }
    __finally2 {}
    return ret;
}

void tls_extension_key_share::clear() {}

return_t tls_extension_key_share::add(const std::string& group, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto code = tlsadvisor->supported_group_code(group);
    ret = add(code, dir);
    return ret;
}

return_t tls_extension_key_share::add_pubkey(uint16 group, const binary_t& pubkey, const keydesc& desc, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_handshake()->get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto& protection = session->get_tls_protection();
        auto& keyshare = protection.get_keyexchange();

        crypto_keychain keychain;
        auto hint = tlsadvisor->hintof_curve_tls_group(group);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto kty = hint->kty;
        auto nid = hint->nid;
        switch (kty) {
            case kty_ec: {
                ret = keychain.add_ec_uncompressed(&keyshare, nid, pubkey, binary_t(), desc);
            } break;
            case kty_okp: {
                ret = keychain.add_okp(&keyshare, nid, pubkey, binary_t(), desc);
            } break;
            case kty_dh: {
                ret = keychain.add_dh(&keyshare, nid, pubkey, binary_t(), desc);
            } break;
            case kty_mlkem: {
                if (from_client == dir) {
                    ret = keychain.add_mlkem_pub(&keyshare, nid, pubkey, key_encoding_pub_raw, desc);
                } else if (from_server == dir) {
                    //
                }
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }
        if (errorcode_t::success == ret) {
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();
                    dbs.println("\e[1;32m+ add pub key %s (group %s kty %s)\e[0m", desc.get_kid_cstr(), tlsadvisor->supported_group_name(group).c_str(),
                                advisor->nameof_kty(kty));
                });
            }
#endif
        }
    }
    __finally2 {}
    return ret;
}

std::string tls_extension_key_share::get_kid() { return ""; }

tls_extension_client_key_share::tls_extension_client_key_share(tls_handshake* handshake) : tls_extension_key_share(handshake) {}

tls_extension_client_key_share::~tls_extension_client_key_share() {}

return_t tls_extension_client_key_share::add(uint16 group) { return tls_extension_key_share::add(group, from_client); }

return_t tls_extension_client_key_share::add(const std::string& group) { return tls_extension_key_share::add(group, from_client); }

void tls_extension_client_key_share::clear() {
    auto session = get_handshake()->get_session();
    auto& protection = session->get_tls_protection();
    auto& keyshare = protection.get_keyexchange();

    keyshare.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
    keyshare.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);
}

return_t tls_extension_client_key_share::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 8446 4.2.8.  Key Share
        // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_dhe_ke)

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();
        size_t limit = endpos_extension();
        uint16 len = 0;

        //  struct {
        //      NamedGroup group;
        //      opaque key_exchange<1..2^16-1>;
        //  } KeyShareEntry;

        //  struct {
        //      KeyShareEntry client_shares<0..2^16-1>;
        //  } KeyShareClientHello;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_len);
            pl.read(stream, limit, pos);
            len = pl.t_value_of<uint16>(constexpr_len);
        }

        protection.get_protection_context().clear_keyshare_groups();

        while (pos < limit) {
            uint16 group = 0;
            binary_t pubkey;
            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_group)       //
                   << new payload_member(uint16(0), true, constexpr_pubkey_len)  //
                   << new payload_member(binary_t(), constexpr_pubkey);          //
                pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
                pl.read(stream, limit, pos);

                group = pl.t_value_of<uint16>(constexpr_group);
                pl.get_binary(constexpr_pubkey, pubkey);

                add_pubkey(group, pubkey, keydesc(get_kid()), dir);

                protection.get_protection_context().add_keyshare_group(group);
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    tls_advisor* tlsadvisor = tls_advisor::get_instance();

                    auto session = get_handshake()->get_session();
                    auto& protection = session->get_tls_protection();
                    auto& keyexchange = protection.get_keyexchange();
                    auto hint_group = tlsadvisor->hintof_curve_tls_group(group);

                    dbs.println("   > %s %i(0x%04x)", constexpr_len, len, len);
                    dbs.println("    > %s", constexpr_key_share_entry);
                    dbs.println("     > %s 0x%04x (%s)", constexpr_group, group, tlsadvisor->supported_group_name(group).c_str());
                    dbs.println("     > %s %04x(%i)", constexpr_pubkey_len, pubkey.size(), pubkey.size());
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(pubkey, &dbs, 16, 7, 0x0, dump_notrunc);
                    }
                    dbs.println("       %s", base16_encode(pubkey).c_str());
                });
            }
#endif
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_client_key_share::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();

        if (tls_flow_hello_retry_request == protection.get_flow()) {
            clear();
            add(session->get_session_info(from_server).get_keyvalue().get(session_key_share_group));
        }

        protection.get_protection_context().clear_keyshare_groups();

        binary_t bin_keyshare;
        auto& keyexchange = protection.get_keyexchange();
        keyexchange.for_each([&](crypto_key_object* obj, void* user) -> void {
            if (KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE == obj->get_desc().get_kid_str()) {
                auto pkey = obj->get_pkey();

                binary_t pubkey;
                auto kty = ktyof_evp_pkey(pkey);
                if (kty_ec == kty) {
                    binary_t privkey;
                    keyexchange.ec_uncompressed_key(pkey, pubkey, privkey);
                } else if (kty_okp == kty) {
                    binary_t temp;
                    binary_t privkey;
                    keyexchange.get_key(pkey, pubkey, temp, privkey, true);
                } else if (kty_mlkem == kty) {
                    binary_t temp;
                    keyexchange.get_public_key(pkey, pubkey, temp);
                }
                uint16 group = 0;
                uint16 pubkeylen = pubkey.size();
                uint32 nid = 0;
                nidof_evp_pkey(pkey, nid);
                auto hint = tlsadvisor->hintof_tls_group_nid(nid);
                if (hint) {
                    group = hint->code;
                }

                payload pl;
                pl << new payload_member(uint16(group), true, constexpr_group)           //
                   << new payload_member(uint16(pubkeylen), true, constexpr_pubkey_len)  //
                   << new payload_member(pubkey, constexpr_pubkey);
                pl.write(bin_keyshare);

                protection.get_protection_context().add_keyshare_group(group);
            }
        });

        {
            binary_t bin_keysharelen;
            binary_append(bin_keysharelen, uint16(bin_keyshare.size()), hton16);
            bin_keyshare.insert(bin_keyshare.begin(), bin_keysharelen.begin(), bin_keysharelen.end());
            bin = std::move(bin_keyshare);
        }
    }
    __finally2 {}
    return ret;
}

std::string tls_extension_client_key_share::get_kid() { return KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC; }

tls_extension_server_key_share::tls_extension_server_key_share(tls_handshake* handshake) : tls_extension_key_share(handshake) {}

tls_extension_server_key_share::~tls_extension_server_key_share() {}

return_t tls_extension_server_key_share::add(uint16 group) { return tls_extension_key_share::add(group, from_server); }

return_t tls_extension_server_key_share::add(const std::string& group) { return tls_extension_key_share::add(group, from_server); }

void tls_extension_server_key_share::clear() {
    auto session = get_handshake()->get_session();
    auto& protection = session->get_tls_protection();
    auto& keyshare = protection.get_keyexchange();

    keyshare.erase(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE);
    keyshare.erase(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC);
}

return_t tls_extension_server_key_share::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_handshake()->get_session();
        uint16 group = 0;
        binary_t pubkey;
        uint16 pubkeylen = 0;
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        {
            //  struct {
            //      KeyShareEntry server_share;
            //  } KeyShareServerHello;
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_group)       //
               << new payload_member(uint16(0), true, constexpr_pubkey_len)  //
               << new payload_member(binary_t(), constexpr_pubkey);          //
            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
            pl.read(stream, endpos_extension(), pos);

            // RFC 8448 5.  HelloRetryRequest
            // if (0 == pubkeylen) hello_retry_request

            group = pl.t_value_of<uint16>(constexpr_group);
            pubkeylen = pl.t_value_of<uint16>(constexpr_pubkey_len);
            pl.get_binary(constexpr_pubkey, pubkey);

            auto hint = tlsadvisor->hintof_curve_tls_group(group);
            auto kty = hint ? hint->kty : kty_unknown;

            if (pubkeylen) {
                auto& protection = session->get_tls_protection();
                switch (kty) {
                    case kty_mlkem: {
                        openssl_pqc pqc;
                        binary_t shared_secret;
                        auto pkey_priv = protection.get_keyexchange().find_group(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE, group);
                        pqc.decapsule(nullptr, pkey_priv, pubkey, shared_secret);
                        protection.get_secrets().assign(tls_context_shared_secret, shared_secret);
                    } break;
                    case kty_unknown: {
                    } break;
                    default: {
                        // RFC 8446 the server's share MUST be in the same group as one of the client's shares.
                        add_pubkey(group, pubkey, keydesc(get_kid()), dir);
                    }
                }
            }

            // HRR
            session->get_session_info(from_server).get_keyvalue().set(session_key_share_group, group);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                dbs.println("   > %s 0x%04x (%s)", constexpr_group, group, tlsadvisor->supported_group_name(group).c_str());
                if (pubkeylen) {
                    dbs.println("   > %s %i", constexpr_pubkey_len, pubkeylen);
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(pubkey, &dbs, 16, 5, 0x0, dump_notrunc);
                    }
                    dbs.println("     %s", base16_encode(pubkey).c_str());
                } else {
                    dbs.println("     \e[1;33mHelloRetryRequest\e[0m");
                }
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_server_key_share::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto tlsadvisor = tls_advisor::get_instance();
        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();
        auto& keyexchange = protection.get_keyexchange();
        uint16 group_enforced = session->get_keyvalue().get(session_conf_enforce_key_share_group);
        auto group = group_enforced ? group_enforced : protection.get_protection_context().get0_keyshare_group();
        auto hint_group = tlsadvisor->hintof_curve_tls_group(group);
        bool correct_group = true;
        auto kty_group = kty_unknown;
        uint32 nid = 0;
        if (hint_group) {
            kty_group = hint_group->kty;
            nid = hint_group->nid;
        } else {
            correct_group = false;
        }

        auto pkey_svr = keyexchange.find_group(get_kid().c_str(), group);
        auto pkey_cli = protection.get_keyexchange().find_group(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC, group);

        if (kty_mlkem == kty_group) {
            // encapsulate
        } else {
            if (nullptr == pkey_svr) {
                correct_group = false;
            } else {
                // RFC 8446 2.1.  Incorrect DHE Share
                // do HRR

                uint32 nid_pkey_cli = 0;
                uint32 nid_pkey_svr = 0;
                nidof_evp_pkey(pkey_cli, nid_pkey_cli);
                nidof_evp_pkey(pkey_svr, nid_pkey_svr);

                if (nid_pkey_cli && nid_pkey_svr && (nid_pkey_svr == nid_pkey_cli)) {
                    // do nothing
                } else {
                    correct_group = false;
                }
            }
        }

        binary_t pubkey;
        uint16 pubkeylen = 0;
        if (correct_group) {
            auto kty = ktyof_evp_pkey(pkey_svr);
            if (kty_ec == kty) {
                binary_t privkey;
                keyexchange.ec_uncompressed_key(pkey_svr, pubkey, privkey);
            } else if (kty_okp == kty) {
                binary_t temp;
                binary_t privkey;
                keyexchange.get_key(pkey_svr, pubkey, temp, privkey, true);
            } else if (kty_mlkem == kty_group) {
                binary_t temp;
                keyexchange.get_public_key(pkey_cli, pubkey, temp);
                binary_t sharedsecret;
                openssl_pqc pqc;
                pqc.encapsule(nullptr, pkey_cli, pubkey, sharedsecret);
                // TODO move to tls_protection::calc
                protection.get_secrets().assign(tls_context_shared_secret, sharedsecret);
#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void { dbs.println("   > encaps"); });
                }
#endif
            }
            pubkeylen = pubkey.size();
        }

        payload pl;
        pl << new payload_member(uint16(group), true, constexpr_group)           //
           << new payload_member(uint16(pubkeylen), true, constexpr_pubkey_len)  //
           << new payload_member(pubkey, constexpr_pubkey);
        auto lambda_hook = [&](payload* pl, payload_member* member) -> void {
            // if do_helloretryrequest is false, do HelloRetryRequest
            pl->set_group(constexpr_pubkey_len, correct_group);
            pl->set_group(constexpr_pubkey, correct_group);
        };
        pl.set_condition(constexpr_group, lambda_hook);
        pl.write(bin);

#if defined DEBUG
        if (hint_group) {
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension,
                                  [&](basic_stream& dbs) -> void { dbs.println("   > group %s %s", hint_group->name, base16_encode(pubkey).c_str()); });
            }
        }
#endif
    }
    __finally2 {}
    return ret;
}

std::string tls_extension_server_key_share::get_kid() { return KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC; }

return_t tls_extension_server_key_share::add_keyshare() {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_handshake()->get_session();
        auto advisor = crypto_advisor::get_instance();
        auto tlsadvisor = tls_advisor::get_instance();
        auto& protection = session->get_tls_protection();
        uint16 group_enforced = session->get_keyvalue().get(session_conf_enforce_key_share_group);

        if (group_enforced) {
            add(group_enforced);
        } else {
            auto group = protection.get_protection_context().get0_keyshare_group();
            auto hint = tlsadvisor->hintof_curve_tls_group(group);
            if (nullptr == hint) {
                ret = not_supported;
                __leave2_trace(ret);
            }
            ret = add(group);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
