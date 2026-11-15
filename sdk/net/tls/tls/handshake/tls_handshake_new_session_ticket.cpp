/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_new_session_ticket.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <chrono>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_early_data.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_new_session_ticket.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_ticket_lifetime[] = "ticket timeline";
constexpr char constexpr_ticket_age_add[] = "ticket age add";
constexpr char constexpr_ticket_nonce_len[] = "ticket nonce len";
constexpr char constexpr_ticket_nonce[] = "ticket nonce";
constexpr char constexpr_session_ticket_len[] = "session ticket len";
constexpr char constexpr_session_ticket[] = "session ticket";
constexpr char constexpr_ticket_extension_len[] = "ticket extension len";
constexpr char constexpr_ticket_extensions[] = "ticket extensions";

tls_handshake_new_session_ticket::tls_handshake_new_session_ticket(tls_session* session) : tls_handshake(tls_handshake_type_t::new_session_ticket, session) {}

tls_handshake_new_session_ticket::~tls_handshake_new_session_ticket() {}

return_t tls_handshake_new_session_ticket::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_server != dir) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_new_session_ticket::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        protection.update_transcript_hash(session, stream + hspos, get_size());
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_new_session_ticket::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        // TLS 1.2 (including DTLS 1.2) uses the RFC 5077 ticket
        // format. It has no ticket_nonce, ticket_age_add, or extensions.
        // Keep this legacy path separate from the TLS 1.3 RFC 8446 format.
        if (false == protection.is_kindof_tls13()) {
            uint32 lifetime_hint = 0;
            binary_t session_ticket;

            payload pl;
            pl << new payload_member(uint32(0), true, "ticket lifetime hint") << new payload_member(uint16(0), true, "session ticket len")
               << new payload_member(binary_t(), "session ticket");
            pl.set_reference_value("session ticket", "session ticket len");
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }

            lifetime_hint = pl.t_value_of<uint32>("ticket lifetime hint");
            pl.get_binary("session ticket", session_ticket);

            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            auto& kv = session->get_session_info(from_server).get_keyvalue();
            kv.set(session_ticket_lifetime, lifetime_hint);
            kv.set(session_ticket_age_add, 0);
            kv.set(session_ticket_timestamp, static_cast<uint64>(now_ms));

            // TLS 1.2 tickets are opaque RFC 5077 state, not TLS 1.3
            // resumption PSKs. Retain the legacy ticket view without trying
            // to derive a TLS 1.3 resumption secret from it.
            secrets.assign(tls_secret_t::new_session_ticket, std::move(session_ticket));
            __leave2;
        }

        /**
         * RFC 8446 4.6.1.  New Session Ticket Message
         * struct {
         *     uint32 ticket_lifetime;
         *     uint32 ticket_age_add;
         *     opaque ticket_nonce<0..255>;
         *     opaque ticket<1..2^16-1>;
         *     Extension extensions<0..2^16-2>;
         * } NewSessionTicket;
         */

        uint32 ticket_lifetime = 0;
        uint32 ticket_age_add = 0;
        binary_t ticket_nonce;
        binary_t session_ticket;
        binary_t ticket_extensions;

        {
            payload pl;
            pl << new payload_member(uint32(0), true, constexpr_ticket_lifetime)       //
               << new payload_member(uint32(0), true, constexpr_ticket_age_add)        //
               << new payload_member(uint8(0), constexpr_ticket_nonce_len)             //
               << new payload_member(binary_t(), constexpr_ticket_nonce)               //
               << new payload_member(uint16(0), true, constexpr_session_ticket_len)    //
               << new payload_member(binary_t(), constexpr_session_ticket)             //
               << new payload_member(uint16(0), true, constexpr_ticket_extension_len)  //
               << new payload_member(binary_t(), constexpr_ticket_extensions);
            pl.set_reference_value(constexpr_ticket_nonce, constexpr_ticket_nonce_len);
            pl.set_reference_value(constexpr_session_ticket, constexpr_session_ticket_len);
            pl.set_reference_value(constexpr_ticket_extensions, constexpr_ticket_extension_len);
            ret = pl.read(stream, size, pos);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }

            ticket_lifetime = pl.t_value_of<uint32>(constexpr_ticket_lifetime);
            ticket_age_add = pl.t_value_of<uint32>(constexpr_ticket_age_add);
            pl.get_binary(constexpr_ticket_nonce, ticket_nonce);
            pl.get_binary(constexpr_session_ticket, session_ticket);
            pl.get_binary(constexpr_ticket_extensions, ticket_extensions);
        }

        // RFC 8446 4.6.1 defines ticket as opaque<1..2^16-1>.
        // A zero-length identity cannot be offered in a PSK identity vector.
        if (session_ticket.empty()) {
            ret = errorcode_t::bad_format;
            __leave2_trace(ret);
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                dbs.autoindent(1);
                dbs.println(" > %s 0x%08x (%i secs)", constexpr_ticket_lifetime, ticket_lifetime, ticket_lifetime);
                dbs.println(" > %s 0x%08x", constexpr_ticket_age_add, ticket_age_add);
                dbs.println(" > %s %s", constexpr_ticket_nonce, base16_encode(ticket_nonce).c_str());
                dbs.println(" > %s %s", constexpr_session_ticket, base16_encode(session_ticket).c_str());
                if (check_trace_level(loglevel_t::loglevel_debug)) {
                    dump_memory(session_ticket, &dbs, 16, 3, 0x0, dump_notrunc);
                }
                dbs.println(" > %s 0x%zx (%zi)", constexpr_ticket_extensions, ticket_extensions.size(), ticket_extensions.size());
                dump_memory(ticket_extensions, &dbs, 16, 3, 0x0, dump_notrunc);
                dbs.autoindent(0);
            });
        }
#endif

        uint32 max_early_data_size = 0;
        if (false == ticket_extensions.empty()) {
            // The early_data extension is ticket-specific; retain its limit with
            // this identity rather than in the legacy latest-ticket metadata.
            tls_extensions extensions;
            ret = extensions.read(this, dir, ticket_extensions);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
            auto early_data = static_cast<tls_extension_early_data*>(extensions.get(tls_extension_type_t::early_data));
            if (early_data) {
                max_early_data_size = early_data->get_max_early_data_size();
            }
        }

        // Keep the complete ticket metadata together. The key-value fields
        // below remain a compatibility view of the most recently received
        // ticket; commit them only after the ticket has been fully derived.
        constexpr uint32 max_ticket_lifetime = 7 * 24 * 60 * 60;
        uint32 bounded_ticket_lifetime = (ticket_lifetime > max_ticket_lifetime) ? max_ticket_lifetime : ticket_lifetime;
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        uint64 ticket_timestamp_ms = static_cast<uint64>(now_ms);

        // RFC 8446 4.6.1: zero-lifetime tickets are discarded immediately.
        if (0 == ticket_lifetime) {
            session->remove_resumption_ticket(session_ticket);
            const binary_t& legacy_ticket = secrets.get(tls_secret_t::new_session_ticket);
            if ((legacy_ticket == session_ticket) || (legacy_ticket.empty() && session->get_resumption_tickets().empty())) {
                secrets.assign(tls_secret_t::new_session_ticket, binary_t());
                auto& ticket_kv = session->get_session_info(from_server).get_keyvalue();
                ticket_kv.set(session_ticket_lifetime, 0);
                ticket_kv.set(session_ticket_age_add, 0);
                ticket_kv.set(session_ticket_timestamp, 0);
            }
        } else {
            binary_t resumption_psk;
            ret = protection.calc_resumption_ticket_psk(ticket_nonce, resumption_psk);
            if (errorcode_t::success != ret) {
                __leave2;
            }
            tls_resumption_ticket ticket;
            ticket.identity = session_ticket;
            ticket.nonce = ticket_nonce;
            ticket.psk = resumption_psk;
            ticket.lifetime = bounded_ticket_lifetime;
            ticket.age_add = ticket_age_add;
            ticket.timestamp = ticket_timestamp_ms;
            ticket.cipher_suite = protection.get_cipher_suite();
            ticket.max_early_data_size = max_early_data_size;
            session->store_resumption_ticket(ticket);

            // Do not publish partially processed ticket metadata if PSK
            // derivation failed above.
            auto& ticket_kv = session->get_session_info(from_server).get_keyvalue();
            ticket_kv.set(session_ticket_lifetime, bounded_ticket_lifetime);
            ticket_kv.set(session_ticket_age_add, ticket_age_add);
            ticket_kv.set(session_ticket_timestamp, ticket_timestamp_ms);

            secrets.assign(tls_secret_t::new_session_ticket, session_ticket);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_new_session_ticket::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();
        uint32 ticket_lifetime = 0;
        uint32 ticket_age_add = 0;
        binary_t ticket_nonce;
        binary_t session_ticket;
        binary_t ticket_extensions;

        {
            ticket_lifetime = 3 * 60 * 60;  // seconds as a 32-bit unsigned integer, MUST NOT use any value greater than 7 days.
            ret = crypto::openssl_prng::random(reinterpret_cast<unsigned char*>(&ticket_age_add), sizeof(ticket_age_add));
            if (errorcode_t::success != ret) {
                __leave2;
            }

            ret = session->generate_ticket_nonce(ticket_nonce);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // Keep identities independently addressable in the server-side
            // ticket store. Do not let a random collision replace an older PSK.
            constexpr size_t ticket_identity_size = 0xB2;
            constexpr size_t ticket_identity_attempts = 8;
            bool unique_identity = false;
            for (size_t attempt = 0; attempt < ticket_identity_attempts; ++attempt) {
                ret = crypto::openssl_prng::random(session_ticket, ticket_identity_size);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                tls_resumption_ticket existing_ticket;
                if (false == session->find_resumption_ticket(session_ticket, existing_ticket)) {
                    unique_identity = true;
                    break;
                }
            }
            if (false == unique_identity) {
                ret = errorcode_t::internal_error;
                __leave2;
            }
        }
        binary_t ticket_psk;
        ret = protection.calc_resumption_ticket_psk(ticket_nonce, ticket_psk);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        {
            payload pl;
            pl << new payload_member(uint32(ticket_lifetime), true, constexpr_ticket_lifetime)                //
               << new payload_member(uint32(ticket_age_add), true, constexpr_ticket_age_add)                  //
               << new payload_member(uint8(ticket_nonce.size()), constexpr_ticket_nonce_len)                  //
               << new payload_member(ticket_nonce, constexpr_ticket_nonce)                                    //
               << new payload_member(uint16(session_ticket.size()), true, constexpr_session_ticket_len)       //
               << new payload_member(session_ticket, constexpr_session_ticket)                                //
               << new payload_member(uint16(ticket_extensions.size()), true, constexpr_ticket_extension_len)  //
               << new payload_member(ticket_extensions, constexpr_ticket_extensions);
            pl.write(bin);
        }

        // Retain every issued ticket independently on the server side as
        // well. A later ClientHello may select any ticket from this connection;
        // the singleton secret fields are only a compatibility view.
        tls_resumption_ticket issued_ticket;
        issued_ticket.identity = session_ticket;
        issued_ticket.nonce = ticket_nonce;
        issued_ticket.psk = std::move(ticket_psk);
        issued_ticket.lifetime = ticket_lifetime;
        issued_ticket.age_add = ticket_age_add;
        issued_ticket.timestamp = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        issued_ticket.cipher_suite = protection.get_cipher_suite();
        session->store_resumption_ticket(issued_ticket);

        // Publish the compatibility metadata only after the per-ticket PSK
        // has been derived and the complete ticket has been serialized.
        auto& kv = session->get_session_info(from_server).get_keyvalue();
        kv.set(session_ticket_lifetime, ticket_lifetime);
        kv.set(session_ticket_age_add, ticket_age_add);
        kv.set(session_ticket_timestamp, issued_ticket.timestamp);

        secrets.assign(tls_secret_t::new_session_ticket, std::move(session_ticket));
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
