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
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
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

        auto session = get_handshake()->get_session();

        const char* privkid = nullptr;
        const char* pubkid = nullptr;
        if (from_client == dir) {
            privkid = KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE;
            pubkid = KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC;
        } else {
            privkid = KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE;
            pubkid = KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC;
        }

        auto& protection = session->get_tls_protection();
        auto& keyshare = protection.get_key();

        crypto_keyexchange keyexchange;
        ret = keyexchange.keygen((tls_group_t)group, &keyshare, privkid);
        if (success != ret) {
            __leave2;
        }
        auto pkey = keyshare.find_group(privkid, group);
        ret = keyshare.add((EVP_PKEY*)pkey, pubkid, true);
        if (success != ret) {
            __leave2;
        }

        protection.get_protection_context().add_keyshare_group(group);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                dbs.println("\e[1;32m+ add keypair %s (group %s)\e[0m", privkid, tlsadvisor->nameof_group(group).c_str());
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

void tls_extension_key_share::clear() {}

return_t tls_extension_key_share::add(const std::string& group, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto code = tlsadvisor->valueof_group(group);
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
        auto& keyshare = protection.get_key();

        crypto_keyexchange keyexchange;
        ret = keyexchange.keystore((tls_group_t)group, &keyshare, desc.get_kid_cstr(), pubkey);
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                dbs.println("\e[1;32m+ add pub key %s (group %s)\e[0m", desc.get_kid_cstr(), tlsadvisor->nameof_group(group).c_str());
            });
        }
#endif
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
    auto& keyshare = protection.get_key();

    keyshare.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
    keyshare.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);
    protection.get_protection_context().clear_keyshare_groups();
}

return_t tls_extension_client_key_share::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 8446 4.2.8.  Key Share
        // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_dhe_ke)

        auto advisor = crypto_advisor::get_instance();
        auto tlsadvisor = tls_advisor::get_instance();
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

            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_group)       //
               << new payload_member(uint16(0), true, constexpr_pubkey_len)  //
               << new payload_member(binary_t(), constexpr_pubkey);          //
            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
            pl.read(stream, limit, pos);

            group = pl.t_value_of<uint16>(constexpr_group);
            pl.get_binary(constexpr_pubkey, pubkey);

            protection.get_protection_context().add_keyshare_group(group);

            add_pubkey(group, pubkey, keydesc(get_kid()), dir);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    auto session = get_handshake()->get_session();
                    auto& protection = session->get_tls_protection();
                    auto& tlskey = protection.get_key();
                    auto hint_group = advisor->hintof_tls_group(group);

                    dbs.println("   > %s %i(0x%04x)", constexpr_len, len, len);
                    dbs.println("    > %s", constexpr_key_share_entry);
                    dbs.println("     > %s 0x%04x (%s)", constexpr_group, group, tlsadvisor->nameof_group(group).c_str());
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

        auto& tlskey = protection.get_key();
        binary_t bin_keyshare;

        protection.get_protection_context().for_each_keyshare_groups([&](uint16 group, bool*) -> void {
            binary_t pubkey;

            crypto_keyexchange keyexchange;
            keyexchange.keyshare((tls_group_t)group, &tlskey, KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE, pubkey);

#if defined DEBUG
            if (istraceable(trace_category_net, loglevel_debug)) {
                trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                    dbs.println("%s", tlsadvisor->nameof_group(group).c_str());
                    dump_memory(pubkey, &dbs, 16, 7, 0x0, dump_notrunc);
                });
            }
#endif
            if (false == pubkey.empty()) {
                payload pl;
                pl << new payload_member(uint16(group), true, constexpr_group)               //
                   << new payload_member(uint16(pubkey.size()), true, constexpr_pubkey_len)  //
                   << new payload_member(pubkey, constexpr_pubkey);
                pl.write(bin_keyshare);
            }
        });

        binary_t bin_keysharelen;
        binary_append(bin_keysharelen, uint16(bin_keyshare.size()), hton16);
        bin_keyshare.insert(bin_keyshare.begin(), bin_keysharelen.begin(), bin_keysharelen.end());
        bin = std::move(bin_keyshare);
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
    auto& keyshare = protection.get_key();

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
        auto advisor = crypto_advisor::get_instance();
        auto tlsadvisor = tls_advisor::get_instance();

        auto& protection = session->get_tls_protection();
        protection.get_secrets().erase(tls_context_shared_secret);

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

            auto hint = advisor->hintof_tls_group(group);

            if (pubkeylen) {
                crypto_keyexchange keyexchange;
                auto& tlskey = protection.get_key();
                binary_t shared_secret;
                if (tls_flag_pqc & hint->flags) {
                    keyexchange.decaps((tls_group_t)group, &tlskey, KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE, pubkey, shared_secret);
                    protection.get_secrets().assign(tls_context_shared_secret, shared_secret);
                } else {
                    // RFC 8446 the server's share MUST be in the same group as one of the client's shares.
                    add_pubkey(group, pubkey, keydesc(get_kid()), dir);
                    // and then ECDHE, HRR (see calc)
                }
            }

            // HRR
            session->get_session_info(from_server).get_keyvalue().set(session_key_share_group, group);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void {
                dbs.println("   > %s 0x%04x (%s)", constexpr_group, group, tlsadvisor->nameof_group(group).c_str());
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
        auto& tlskey = protection.get_key();
        uint16 group_enforced = session->get_keyvalue().get(session_conf_enforce_key_share_group);
        auto group = group_enforced ? group_enforced : protection.get_protection_context().get0_keyshare_group();
        auto hint_group = advisor->hintof_tls_group(group);
        bool correct_group = true;
        bool iskindof_mlkem = false;
        if (hint_group) {
            iskindof_mlkem = (tls_flag_pqc & hint_group->flags);
        } else {
            correct_group = false;
        }

        if (iskindof_mlkem) {
            // encapsulate
        } else {
            auto pkey_svr = tlskey.find_group(get_kid().c_str(), group);
            auto pkey_cli = protection.get_key().find_group(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC, group);

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
            crypto_keyexchange keyexchange;
            binary_t share;
            binary_t keycapsule;

            if (iskindof_mlkem) {
                keyexchange.keyshare((tls_group_t)group, &tlskey, KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC, share);

                binary_t sharedsecret;
                keyexchange.encaps((tls_group_t)group, share, keycapsule, sharedsecret);
                protection.get_secrets().assign(tls_context_shared_secret, sharedsecret);
#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    trace_debug_event(trace_category_net, trace_event_tls_extension, [&](basic_stream& dbs) -> void { dbs.println("   > encaps"); });
                }
#endif
                pubkey = std::move(keycapsule);
            } else {
                keyexchange.keyshare((tls_group_t)group, &tlskey, KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC, share);
                pubkey = std::move(share);
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
            auto hint = advisor->hintof_tls_group(group);
            if (nullptr == hint) {
                ret = not_supported;
                __leave2;
            }
            ret = add(group);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
