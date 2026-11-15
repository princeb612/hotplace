/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_handshake_encrypted_extensions.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_encrypted_extensions.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_encrypted_extensions::tls_handshake_encrypted_extensions(tls_session* session) : tls_handshake(tls_handshake_type_t::encrypted_extensions, session) {}

tls_handshake_encrypted_extensions::~tls_handshake_encrypted_extensions() {}

return_t tls_handshake_encrypted_extensions::do_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        // RFC 8446 4.2.11: if the server accepts early data in EncryptedExtensions,
        // it MUST have selected the first PSK identity offered by the client.
        if ((from_server == dir) && (tls_io_operation_t::read == opdir) && (nullptr != get_extensions().get(tls_extension_type_t::early_data))) {
            // A received EncryptedExtensions early_data indication is an
            // acceptance signal. The client must have offered early_data and
            // the server must have selected the first offered PSK identity.
            uint16 selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
            const auto& early_state = session->get_session_info(from_server).get_keyvalue();
            bool early_data_offered = (0 != early_state.get(session_early_data_offered));
            if (!early_data_offered || (0 != selected_identity)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                session->reset_session_status();
                ret = errorcode_t::handshake_failure;
                __leave2_trace(ret);
            }
            session->get_session_info(from_server).get_keyvalue().set(session_early_data_accepted, 1);
        }

        protection.update_transcript_hash(session, stream + hspos, get_size());

        session->update_session_status(session_status_encrypted_extensions);
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_encrypted_extensions::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
            // RFC 8446 2.  Protocol Overview
            // EncryptedExtensions:  responses to ClientHello extensions that are
            //    not required to determine the cryptographic parameters, other than
            //    those that are specific to individual certificates.
            //    [Section 4.3.1]

            // RFC 8446 4.3.1.  Encrypted Extensions
            // struct {
            //     Extension extensions<0..2^16-1>;
            // } EncryptedExtensions;

            // RFC 8446 4.3.1.  Encrypted Extensions

            auto session = get_session();
            auto& protection = session->get_tls_protection();
            if (protection.is_kindof_tls()) {
                uint16 len = ntoh16(*(uint16*)(stream + pos));
                pos += 2;
                ret = get_extensions().read(this, dir, stream, pos + sizeof(uint16) + len, pos);
            } else if (protection.is_kindof_dtls() || (tls_flow_t::zero_rtt == protection.get_flow())) {
                // DTLS 1.3 ciphertext
                //
                pos += 2;  // len
                ret = get_extensions().read(this, dir, stream, size, pos);
            }

            session->clear_scheduled_extensions();  // release ALPN
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_encrypted_extensions::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    binary_t extensions;
    session->select_into_scheduled_extension(&get_extensions());
    ret = get_extensions().write(dir, extensions);
    binary_append(bin, uint16(extensions.size()), hton16);
    binary_append(bin, extensions);
    return ret;
}

}  // namespace net
}  // namespace hotplace
