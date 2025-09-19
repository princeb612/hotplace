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

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_tls_group(group);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        crypto_keychain keychain;
        keydesc desc(privkid);
        auto kty = hint->kty;
        auto nid = hint->nid;
        switch (kty) {
            case kty_ec:
            case kty_okp: {
                ret = keychain.add_ec(&keyshare, nid, desc);
            } break;
            case kty_dh: {
                ret = keychain.add_dh(&keyshare, nid, desc);
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }

        auto pkey = keyshare.find(desc.get_kid_cstr());
        keyshare.add((EVP_PKEY*)pkey, pubkid.c_str(), true);
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

return_t tls_extension_key_share::add_pubkey(uint16 group, const binary_t& pubkey, const keydesc& desc) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_handshake()->get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto& keyshare = protection.get_keyexchange();

        crypto_keychain keychain;
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_tls_group(group);
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
            default: {
                ret = errorcode_t::not_supported;
            } break;
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

                add_pubkey(group, pubkey, keydesc(get_kid()));
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                basic_stream dbs;
                tls_advisor* tlsadvisor = tls_advisor::get_instance();

                auto session = get_handshake()->get_session();
                auto& protection = session->get_tls_protection();
                auto& keyexchange = protection.get_keyexchange();
                auto hint_group = tlsadvisor->hintof_tls_group(group);

                dbs.println("   > %s %i(0x%04x)", constexpr_len, len, len);
                dbs.println("    > %s", constexpr_key_share_entry);
                dbs.println("     > %s 0x%04x (%s)", constexpr_group, group, tlsadvisor->supported_group_name(group).c_str());
                dbs.println("     > %s %04x(%i)", constexpr_pubkey_len, pubkey.size(), pubkey.size());
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(pubkey, &dbs, 16, 7, 0x0, dump_notrunc);
                }
                dbs.println("       %s", base16_encode(pubkey).c_str());

                trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
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
        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();

        if (tls_flow_hello_retry_request == protection.get_flow()) {
            clear();
            add(session->get_session_info(from_server).get_keyvalue().get(session_key_share_group));
        }

        auto& keyexchange = protection.get_keyexchange();
        auto pkey = keyexchange.find(get_kid().c_str());
        if (nullptr == pkey) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        binary_t pubkey;
        auto kty = typeof_crypto_key(pkey);
        if (kty_ec == kty) {
            binary_t privkey;
            keyexchange.ec_uncompressed_key(pkey, pubkey, privkey);
        } else if (kty_okp == kty) {
            binary_t temp;
            binary_t privkey;
            keyexchange.get_key(pkey, pubkey, temp, privkey, true);
        }
        uint16 group = 0;
        uint16 pubkeylen = pubkey.size();
        uint32 nid = 0;
        nidof_evp_pkey(pkey, nid);
        switch (kty) {
            case kty_ec:
            case kty_okp: {
                auto hint = advisor->hintof_curve_nid(nid);
                if (hint) {
                    group = tlsgroupof(hint);
                }
            } break;
        }
        if (0 == group) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        payload pl;
        pl << new payload_member(uint16(4 + pubkeylen), true, constexpr_len)     //
           << new payload_member(uint16(group), true, constexpr_group)           //
           << new payload_member(uint16(pubkeylen), true, constexpr_pubkey_len)  //
           << new payload_member(pubkey, constexpr_pubkey);
        pl.write(bin);
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

            // RFC 8446 the server's share MUST be in the same group as one of the client's shares.
            add_pubkey(group, pubkey, keydesc(get_kid()));

            // HRR
            session->get_session_info(from_server).get_keyvalue().set(session_key_share_group, group);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            dbs.println("   > %s 0x%04x (%s)", constexpr_group, group, tlsadvisor->supported_group_name(group).c_str());
            if (pubkeylen) {
                dbs.println("   > %s %i", constexpr_pubkey_len, pubkeylen);
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(pubkey, &dbs, 16, 5, 0x0, dump_notrunc);
                }
                dbs.println("     %s", base16_encode(pubkey).c_str());
            }

            trace_debug_event(trace_category_net, trace_event_tls_extension, &dbs);
        }
#endif

        {
            // _group = group;
            // _pubkey = std::move(pubkey);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_extension_server_key_share::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto session = get_handshake()->get_session();
        auto& protection = session->get_tls_protection();
        auto& keyexchange = protection.get_keyexchange();
        auto pkey = keyexchange.find(get_kid().c_str());
        if (nullptr == pkey) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        // RFC 8446 2.1.  Incorrect DHE Share
        bool is_correct_dhe_share = true;
        {
            auto cli_keyshare = protection.get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);

            uint32 cli_nid_keyshare = 0;
            uint32 svr_nid_keyshare = 0;
            nidof_evp_pkey(cli_keyshare, cli_nid_keyshare);
            nidof_evp_pkey(pkey, svr_nid_keyshare);

            if (cli_nid_keyshare && svr_nid_keyshare && (svr_nid_keyshare == cli_nid_keyshare)) {
                //
            } else {
                is_correct_dhe_share = false;
            }
        }

        binary_t pubkey;
        uint16 pubkeylen = 0;
        uint16 group = 0;
        {
            auto kty = typeof_crypto_key(pkey);
            if (kty_ec == kty) {
                binary_t privkey;
                keyexchange.ec_uncompressed_key(pkey, pubkey, privkey);
            } else if (kty_okp == kty) {
                binary_t temp;
                binary_t privkey;
                keyexchange.get_key(pkey, pubkey, temp, privkey, true);
            }
            pubkeylen = pubkey.size();

            uint32 nid = 0;
            nidof_evp_pkey(pkey, nid);
            switch (kty) {
                case kty_ec:
                case kty_okp: {
                    auto hint = advisor->hintof_curve_nid(nid);
                    if (hint) {
                        group = tlsgroupof(hint);
                    }
                } break;
            }
            if (0 == group) {
                group = 0x001d;  // x25519, RFC 8446 8446 9.1 MUST
                is_correct_dhe_share = false;
            }
        }

        payload pl;
        pl << new payload_member(uint16(group), true, constexpr_group)           //
           << new payload_member(uint16(pubkeylen), true, constexpr_pubkey_len)  //
           << new payload_member(pubkey, constexpr_pubkey);
        auto lambda_hook = [&](payload* pl, payload_member* member) -> void {
            // if is_correct_dhe_share is false, do HelloRetryRequest
            pl->set_group(constexpr_pubkey_len, is_correct_dhe_share);
            pl->set_group(constexpr_pubkey, is_correct_dhe_share);
        };
        pl.set_condition(constexpr_group, lambda_hook);
        pl.write(bin);
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
            auto cli_keyshare = protection.get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);
            if (nullptr == cli_keyshare) {
                ret = errorcode_t::invalid_context;
                __leave2;
            }

            auto kty = typeof_crypto_key(cli_keyshare);
            uint32 nid = 0;
            nidof_evp_pkey(cli_keyshare, nid);

            auto hint = tlsadvisor->hintof_tls_group_nid(nid);
            if (hint) {
                auto group = hint->code;
                if (group) {
                    add(group);
                }
            } else {
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
