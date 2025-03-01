/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_protection.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_key_share_entry[] = "key share entry";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_group[] = "group";
constexpr char constexpr_pubkey_len[] = "public key len";
constexpr char constexpr_pubkey[] = "public key";

tls_extension_key_share::tls_extension_key_share(tls_session* session) : tls_extension(tls1_ext_key_share, session) {}

return_t tls_extension_key_share::add(uint16 group) { return errorcode_t::success; }

return_t tls_extension_key_share::add(const std::string& group) { return errorcode_t::success; }

return_t tls_extension_key_share::add(uint16 group, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        std::string privkid;
        std::string pubkid;
        if (from_client == dir) {
            privkid = KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE;
            pubkid = KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC;
        } else {
            privkid = KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE;
            pubkid = KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        auto& protection = session->get_tls_protection();
        auto& keyshare = protection.get_keyexchange();

        keydesc desc(privkid);
        crypto_keychain keychain;

        switch (group) {
            case 0x0017: /* secp256r1 */ {
                ret = keychain.add_ec(&keyshare, NID_X9_62_prime256v1, desc);
            } break;
            case 0x0018: /* secp384r1 */ {
                ret = keychain.add_ec(&keyshare, NID_secp384r1, desc);
            } break;
            case 0x0019: /* secp521r1 */ {
                ret = keychain.add_ec(&keyshare, NID_secp521r1, desc);
            } break;
            case 0x001d: /* x25519 */ {
                ret = keychain.add_ec(&keyshare, NID_X25519, desc);
            } break;
            case 0x001e: /* x448 */ {
                ret = keychain.add_ec(&keyshare, NID_X448, desc);
            } break;
            case 0x0100: /* ffdhe2048 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe2048, desc);
            } break;
            case 0x0101: /* ffdhe3072 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe3072, desc);
            } break;
            case 0x0102: /* ffdhe4096 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe4096, desc);
            } break;
            case 0x0103: /* ffdhe6144 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe6144, desc);
            } break;
            case 0x0104: /* ffdhe8192 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe8192, desc);
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
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto& keyshare = protection.get_keyexchange();

        crypto_keychain keychain;
        switch (group) {
            case 0x0017: /* secp256r1 */ {
                ret = keychain.add_ec_uncompressed(&keyshare, NID_X9_62_prime256v1, pubkey, binary_t(), desc);
            } break;
            case 0x0018: /* secp384r1 */ {
                ret = keychain.add_ec_uncompressed(&keyshare, NID_secp384r1, pubkey, binary_t(), desc);
            } break;
            case 0x0019: /* secp521r1 */ {
                ret = keychain.add_ec_uncompressed(&keyshare, NID_secp521r1, pubkey, binary_t(), desc);
            } break;
            case 0x001d: /* x25519 */ {
                ret = keychain.add_okp(&keyshare, NID_X25519, pubkey, binary_t(), desc);
            } break;
            case 0x001e: /* x448 */ {
                ret = keychain.add_okp(&keyshare, NID_X448, pubkey, binary_t(), desc);
            } break;
            case 0x0100: /* ffdhe2048 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe2048, pubkey, binary_t(), desc);
            } break;
            case 0x0101: /* ffdhe3072 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe3072, pubkey, binary_t(), desc);
            } break;
            case 0x0102: /* ffdhe4096 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe4096, pubkey, binary_t(), desc);
            } break;
            case 0x0103: /* ffdhe6144 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe6144, pubkey, binary_t(), desc);
            } break;
            case 0x0104: /* ffdhe8192 */ {
                ret = keychain.add_dh(&keyshare, NID_ffdhe8192, pubkey, binary_t(), desc);
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

std::string tls_extension_key_share::get_kid() { return ""; }

tls_extension_client_key_share::tls_extension_client_key_share(tls_session* session) : tls_extension_key_share(session) {}

return_t tls_extension_client_key_share::add(uint16 group) { return tls_extension_key_share::add(group, from_client); }

return_t tls_extension_client_key_share::add(const std::string& group) { return tls_extension_key_share::add(group, from_client); }

void tls_extension_client_key_share::clear() {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& keyshare = protection.get_keyexchange();

    keyshare.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
    keyshare.erase(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);
}

return_t tls_extension_client_key_share::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 8446 4.2.8.  Key Share
        // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_dhe_ke)

        uint16 len = 0;
        uint16 group = 0;

        //  struct {
        //      NamedGroup group;
        //      opaque key_exchange<1..2^16-1>;
        //  } KeyShareEntry;

        //  struct {
        //      KeyShareEntry client_shares<0..2^16-1>;
        //  } KeyShareClientHello;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_len) << new payload_member(uint16(0), true, constexpr_group)
               << new payload_member(uint16(0), true, constexpr_pubkey_len) << new payload_member(binary_t(), constexpr_pubkey);
            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
            pl.read(stream, endpos_extension(), pos);

            len = pl.t_value_of<uint16>(constexpr_len);
            group = pl.t_value_of<uint16>(constexpr_group);
            binary_t pubkey;
            pl.get_binary(constexpr_pubkey, pubkey);

            add_pubkey(group, pubkey, keydesc(get_kid()));
        }

        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            auto session = get_session();
            auto& protection = session->get_tls_protection();
            auto& keyexchange = protection.get_keyexchange();
            auto pkey = keyexchange.find(get_kid().c_str());

            binary_t pubkey;
            uint32 nid = 0;
            auto kty = typeof_crypto_key(pkey);
            if (kty_ec == kty) {
                binary_t privkey;
                keyexchange.ec_uncompressed_key(pkey, pubkey, privkey);
            } else if (kty_okp == kty) {
                binary_t temp;
                binary_t privkey;
                keyexchange.get_key(pkey, pubkey, temp, privkey, true);
            }
            uint16 pubkeylen = pubkey.size();

            dbs.printf("   > %s %i(0x%04x)\n", constexpr_len, len, len);
            dbs.printf("    > %s\n", constexpr_key_share_entry);
            dbs.printf("     > %s 0x%04x (%s)\n", constexpr_group, group, tlsadvisor->supported_group_name(group).c_str());
            dbs.printf("     > %s %04x(%i)\n", constexpr_pubkey_len, pubkeylen, pubkeylen);
            dump_memory(pubkey, &dbs, 16, 7, 0x0, dump_notrunc);
            dbs.printf("       %s\n", base16_encode(pubkey).c_str());

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_client_key_share::do_write_body(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
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
        pl << new payload_member(uint16(4 + pubkeylen), true, constexpr_len) << new payload_member(uint16(group), true, constexpr_group)
           << new payload_member(uint16(pubkeylen), true, constexpr_pubkey_len) << new payload_member(pubkey, constexpr_pubkey);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

std::string tls_extension_client_key_share::get_kid() { return KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC; }

tls_extension_server_key_share::tls_extension_server_key_share(tls_session* session) : tls_extension_key_share(session) {}

return_t tls_extension_server_key_share::add(uint16 group) { return tls_extension_key_share::add(group, from_server); }

return_t tls_extension_server_key_share::add(const std::string& group) { return tls_extension_key_share::add(group, from_server); }

void tls_extension_server_key_share::clear() {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto& keyshare = protection.get_keyexchange();

    keyshare.erase(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE);
    keyshare.erase(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC);
}

return_t tls_extension_server_key_share::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 group = 0;
        binary_t pubkey;
        uint16 pubkeylen = 0;
        {
            //  struct {
            //      KeyShareEntry server_share;
            //  } KeyShareServerHello;
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_group) << new payload_member(uint16(0), true, constexpr_pubkey_len)
               << new payload_member(binary_t(), constexpr_pubkey);
            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
            pl.read(stream, endpos_extension(), pos);

            // RFC 8448 5.  HelloRetryRequest
            // if (0 == pubkeylen) hello_retry_request

            group = pl.t_value_of<uint16>(constexpr_group);
            pubkeylen = pl.t_value_of<uint16>(constexpr_pubkey_len);
            pl.get_binary(constexpr_pubkey, pubkey);

            add_pubkey(group, pubkey, keydesc(get_kid()));
        }

        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            dbs.printf("   > %s 0x%04x (%s)\n", constexpr_group, group, tlsadvisor->supported_group_name(group).c_str());
            if (pubkeylen) {
                dbs.printf("   > %s %i\n", constexpr_pubkey_len, pubkeylen);
                dump_memory(pubkey, &dbs, 16, 5, 0x0, dump_notrunc);
                dbs.printf("     %s\n", base16_encode(pubkey).c_str());
            }

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }

        {
            // _group = group;
            // _pubkey = std::move(pubkey);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_server_key_share::do_write_body(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        auto session = get_session();
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
        auto session = get_session();
        auto advisor = crypto_advisor::get_instance();
        auto& protection = session->get_tls_protection();
        auto cli_keyshare = protection.get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);
        if (nullptr == cli_keyshare) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        uint32 nid = 0;
        nidof_evp_pkey(cli_keyshare, nid);

        auto hint = advisor->hintof_curve_nid(nid);
        if (hint) {
            auto group = tlsgroupof(hint);
            if (group) {
                add(group);
            }
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
