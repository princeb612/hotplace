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
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/extension/tls_extension_key_share.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_extension_key_share::tls_extension_key_share(tls_session* session) : tls_extension(tls1_ext_key_share, session) {}

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
            // TODO ...
            case 0x0017: /* secp256r1 */ {
                ret = keychain.add_ec(&keyshare, NID_X9_62_prime256v1, pubkey, binary_t(), desc);
            } break;
            case 0x0018: /* secp384r1 */ {
                ret = keychain.add_ec(&keyshare, NID_secp384r1, pubkey, binary_t(), desc);
            } break;
            case 0x0019: /* secp521r1 */ {
                ret = keychain.add_ec(&keyshare, NID_secp521r1, pubkey, binary_t(), desc);
            } break;
            case 0x001d: /* x25519 */ {
                ret = keychain.add_okp(&keyshare, NID_X25519, pubkey, binary_t(), desc);
            } break;
            case 0x001e: /* x448 */ {
                ret = keychain.add_okp(&keyshare, NID_X448, pubkey, binary_t(), desc);
            } break;
            case 0x0100: /* ffdhe2048 */ {
                ret = errorcode_t::not_supported;
            } break;
            case 0x0101: /* ffdhe3072 */ {
                ret = errorcode_t::not_supported;
            } break;
            case 0x0102: /* ffdhe4096 */ {
                ret = errorcode_t::not_supported;
            } break;
            case 0x0103: /* ffdhe6144 */ {
                ret = errorcode_t::not_supported;
            } break;
            case 0x0104: /* ffdhe8192 */ {
                ret = errorcode_t::not_supported;
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

constexpr char constexpr_key_share_entry[] = "key share entry";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_group[] = "group";
constexpr char constexpr_pubkey_len[] = "public key len";
constexpr char constexpr_pubkey[] = "public key";

tls_extension_client_key_share::tls_extension_client_key_share(tls_session* session) : tls_extension_key_share(session) {}

return_t tls_extension_client_key_share::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 8446 4.2.8.  Key Share
        // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_dhe_ke)

        uint16 len = 0;
        uint16 group = 0;
        keydesc desc;

        //  struct {
        //      NamedGroup group;
        //      opaque key_exchange<1..2^16-1>;
        //  } KeyShareEntry;

        desc.set_kid("CH");
        //  struct {
        //      KeyShareEntry client_shares<0..2^16-1>;
        //  } KeyShareClientHello;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_len);
            pl.read(stream, endpos_extension(), pos);

            len = pl.t_value_of<uint16>(constexpr_len);
        }
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_group) << new payload_member(uint16(0), true, constexpr_pubkey_len)
               << new payload_member(binary_t(), constexpr_pubkey);
            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
            pl.read(stream, endpos_extension(), pos);

            group = pl.t_value_of<uint16>(constexpr_group);
            // uint16 pubkeylen = pl.t_value_of<uint16>(constexpr_pubkey_len);
            binary_t pubkey;
            pl.get_binary(constexpr_pubkey, pubkey);

            add_pubkey(group, pubkey, desc);

            _keys.push_back(group);
            _keyshares.insert({group, pubkey});
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            debugstream->printf(" > %s %i(0x%04x)\n", constexpr_len, len, len);

            for (auto item : _keys) {
                auto group = item;
                auto iter = _keyshares.find(item);
                auto const& pubkey = iter->second;
                uint16 pubkeylen = pubkey.size();

                debugstream->printf("  > %s\n", constexpr_key_share_entry);
                debugstream->printf("   > %s 0x%04x (%s)\n", constexpr_group, group, tlsadvisor->supported_group_string(group).c_str());
                debugstream->printf("   > %s %04x(%i)\n", constexpr_pubkey_len, pubkeylen, pubkeylen);
                dump_memory(pubkey, debugstream, 16, 5, 0x0, dump_notrunc);
                debugstream->printf("     %s\n", base16_encode(pubkey).c_str());
            }
        }

        {
            //
            _key_share_len = len;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_client_key_share::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

tls_extension_server_key_share::tls_extension_server_key_share(tls_session* session) : tls_extension_key_share(session), _group(0) {}

return_t tls_extension_server_key_share::read_data(const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 group = 0;
        keydesc desc;
        binary_t pubkey;
        uint16 pubkeylen = 0;
        {
            desc.set_kid("SH");
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

            add_pubkey(group, pubkey, desc);
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > %s 0x%04x (%s)\n", constexpr_group, group, tlsadvisor->supported_group_string(group).c_str());
            if (pubkeylen) {
                debugstream->printf(" > %s %i\n", constexpr_pubkey_len, pubkeylen);
                dump_memory(pubkey, debugstream, 16, 3, 0x0, dump_notrunc);
                debugstream->printf("   %s\n", base16_encode(pubkey).c_str());
            }
        }

        {
            _group = group;
            _pubkey = std::move(pubkey);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_server_key_share::write(binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
