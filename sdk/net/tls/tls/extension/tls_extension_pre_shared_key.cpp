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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension_pre_shared_key.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_psk_identities_len[] = "psk identities len";
constexpr char constexpr_psk_identity_len[] = "psk identity len";
constexpr char constexpr_psk_identity[] = "psk identity";
constexpr char constexpr_obfuscated_ticket_age[] = "obfuscated ticket age";
constexpr char constexpr_psk_binders_len[] = "psk binders len";
constexpr char constexpr_psk_binder_len[] = "psk binder len";
constexpr char constexpr_psk_binder[] = "psk binder";
constexpr char constexpr_selected_identity[] = "selected identity";

tls_extension_psk::tls_extension_psk(tls_session* session) : tls_extension(tls1_ext_pre_shared_key, session) {}

tls_extension_client_psk::tls_extension_client_psk(tls_session* session)
    : tls_extension_psk(session), _psk_identities_len(0), _obfuscated_ticket_age(0), _psk_binders_len(0) {}

return_t tls_extension_client_psk::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        // RFC 4279 Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)
        // RFC 4785 Pre-Shared Key (PSK) Ciphersuites with NULL Encryption for Transport Layer Security (TLS)
        // RFC 5487 Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode
        // RFC 5489 ECDHE_PSK Cipher Suites for Transport Layer Security (TLS)
        //
        // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes (psk_ke)
        // RFC 8446 4.2.10.  Early Data Indication
        // RFC 8446 4.2.11.  Pre-Shared Key Extension
        //
        // struct {
        //     opaque identity<1..2^16-1>;
        //     uint32 obfuscated_ticket_age;
        // } PskIdentity;
        //
        // opaque PskBinderEntry<32..255>;
        //
        // struct {
        //     PskIdentity identities<7..2^16-1>;
        //     PskBinderEntry binders<33..2^16-1>;
        // } OfferedPsks;
        //
        // struct {
        //     select (Handshake.msg_type) {
        //         case client_hello: OfferedPsks;
        //         case server_hello: uint16 selected_identity;
        //     };
        // } PreSharedKeyExtension;
        //
        // RFC 9257 Guidance for External Pre-Shared Key (PSK) Usage in TLS

        uint16 psk_identities_len = 0;
        uint16 psk_identity_len = 0;
        binary_t psk_identity;
        uint32 obfuscated_ticket_age = 0;
        uint16 psk_binders_len = 0;
        uint8 psk_binder_len = 0;
        binary_t psk_binder;
        // openssl_kdf kdf;

        size_t offset_psk_binders_len = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_psk_identities_len) << new payload_member(uint16(0), true, constexpr_psk_identity_len)
               << new payload_member(binary_t(), constexpr_psk_identity) << new payload_member(uint32(0), true, constexpr_obfuscated_ticket_age)
               << new payload_member(uint16(0), true, constexpr_psk_binders_len) << new payload_member(uint8(0), constexpr_psk_binder_len)
               << new payload_member(binary_t(), constexpr_psk_binder);
            pl.set_reference_value(constexpr_psk_identity, constexpr_psk_identity_len);
            pl.set_reference_value(constexpr_psk_binder, constexpr_psk_binder_len);
            pl.read(stream, endpos_extension(), pos);

            psk_identities_len = pl.t_value_of<uint16>(constexpr_psk_identities_len);
            psk_identity_len = pl.t_value_of<uint16>(constexpr_psk_identity_len);
            pl.get_binary(constexpr_psk_identity, psk_identity);
            obfuscated_ticket_age = pl.t_value_of<uint32>(constexpr_obfuscated_ticket_age);
            offset_psk_binders_len = offsetof_header() + pl.offset_of(constexpr_psk_binders_len);  // 0-RTT "res binder"
            psk_binders_len = pl.t_value_of<uint16>(constexpr_psk_binders_len);
            psk_binder_len = pl.t_value_of<uint8>(constexpr_psk_binder_len);
            pl.get_binary(constexpr_psk_binder, psk_binder);
        }

        {
            // RFC 8448 4.  Resumed 0-RTT Handshake

            // binder hash
            auto& protection = session->get_tls_protection();
            binary_t context_resumption_binder_hash;
            {
                size_t content_header_size = 0;
                // size_t sizeof_dtls_recons = 0;
                if (protection.is_kindof_tls()) {
                    content_header_size = RTL_FIELD_SIZE(tls_content_t, tls);
                } else {
                    content_header_size = RTL_FIELD_SIZE(tls_content_t, dtls);
                    // sizeof_dtls_recons = 8;
                }
                ret = protection.calc_context_hash(session, sha2_256, stream + content_header_size, offset_psk_binders_len - 1, context_resumption_binder_hash);
                // if (errorcode_t::success != ret) do something
            }

            // verify psk binder
            ret = protection.calc_psk(session, context_resumption_binder_hash, psk_binder);
        }

        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("   > %s 0x%04x(%i)\n", constexpr_psk_identity_len, psk_identity_len, psk_identity_len);
            dump_memory(psk_identity, &dbs, 16, 4, 0x0, dump_notrunc);
            dbs.printf("   > %s 0x%08x\n", constexpr_obfuscated_ticket_age, obfuscated_ticket_age);
            dbs.printf("   > %s 0x%04x(%i)\n", constexpr_psk_binders_len, psk_binders_len, psk_binders_len);
            dbs.printf("   > %s 0x%04x(%i)\n", constexpr_psk_binder_len, psk_binder_len, psk_binder_len);
            dbs.printf("   > %s %s \e[1;33m%s\e[0m\n", constexpr_psk_binder, base16_encode(psk_binder).c_str(),
                       (errorcode_t::success == ret) ? "true" : "false");

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }

        {
            _psk_identities_len = psk_identities_len;
            _psk_identity = std::move(psk_identity);
            _obfuscated_ticket_age = obfuscated_ticket_age;
            _psk_binders_len = psk_binders_len;
            _psk_binder = std::move(psk_binder);
            // _offset_psk_binders_len = offset_psk_binders_len;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_client_psk::do_write_body(binary_t& bin) { return not_supported; }

tls_extension_server_psk::tls_extension_server_psk(tls_session* session) : tls_extension_psk(session), _selected_identity(0) {}

return_t tls_extension_server_psk::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 selected_identity = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_selected_identity);
            pl.read(stream, endpos_extension(), pos);

            selected_identity = pl.t_value_of<uint16>(constexpr_selected_identity);
        }

        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("   > %s %i\n", constexpr_selected_identity, selected_identity);

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }

        {
            //
            _selected_identity = selected_identity;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_extension_server_psk::do_write_body(binary_t& bin) { return not_supported; }

}  // namespace net
}  // namespace hotplace
