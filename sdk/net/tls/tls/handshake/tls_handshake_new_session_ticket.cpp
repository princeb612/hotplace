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
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_new_session_ticket.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

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

tls_handshake_new_session_ticket::tls_handshake_new_session_ticket(tls_session* session) : tls_handshake(tls_hs_new_session_ticket, session) {}

return_t tls_handshake_new_session_ticket::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_server != dir) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_new_session_ticket::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        protection.update_transcript_hash(session, stream + hspos, get_size());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_new_session_ticket::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();

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
            pl.read(stream, size, pos);

            ticket_lifetime = pl.t_value_of<uint32>(constexpr_ticket_lifetime);
            ticket_age_add = pl.t_value_of<uint32>(constexpr_ticket_age_add);
            pl.get_binary(constexpr_ticket_nonce, ticket_nonce);
            pl.get_binary(constexpr_session_ticket, session_ticket);
            pl.get_binary(constexpr_ticket_extensions, ticket_extensions);
        }

        {
            auto& kv = session->get_session_info(from_server).get_keyvalue();
            kv.set(session_ticket_lifetime, ticket_lifetime);
            kv.set(session_ticket_age_add, ticket_age_add);
            protection.set_item(tls_context_new_session_ticket, session_ticket);

            kv.set(session_ticket_timestamp, time(nullptr));
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.autoindent(1);
            dbs.println(" > %s 0x%08x (%i secs)", constexpr_ticket_lifetime, ticket_lifetime, ticket_lifetime);
            dbs.println(" > %s 0x%08x", constexpr_ticket_age_add, ticket_age_add);
            dbs.println(" > %s %s", constexpr_ticket_nonce, base16_encode(ticket_nonce).c_str());
            dbs.println(" > %s", constexpr_session_ticket);
            dump_memory(session_ticket, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.autoindent(0);

            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_new_session_ticket::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        uint32 ticket_lifetime = 0;
        uint32 ticket_age_add = 0;
        binary_t ticket_nonce;
        binary_t session_ticket;
        binary_t ticket_extensions;
        openssl_prng prng;

        {
            ticket_lifetime = 30;                      // seconds as a 32-bit unsigned integer, MUST NOT use any value greater than 7 days.
            prng.random((byte_t*)&ticket_age_add, 4);  // random 32-bit value
            ticket_nonce.resize(2);                    // nonce
            prng.random(session_ticket, 0xB2);         // PSK identity

            auto& kv = session->get_session_info(from_server).get_keyvalue();
            kv.set(session_ticket_lifetime, ticket_lifetime);
            kv.set(session_ticket_age_add, ticket_age_add);
            protection.set_item(tls_context_new_session_ticket, session_ticket);
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
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
