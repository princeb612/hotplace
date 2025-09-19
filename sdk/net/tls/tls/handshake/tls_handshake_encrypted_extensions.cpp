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
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_encrypted_extensions.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_encrypted_extensions::tls_handshake_encrypted_extensions(tls_session* session) : tls_handshake(tls_hs_encrypted_extensions, session) {}

tls_handshake_encrypted_extensions::~tls_handshake_encrypted_extensions() {}

return_t tls_handshake_encrypted_extensions::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

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
            } else if (protection.is_kindof_dtls() || (tls_flow_0rtt == protection.get_flow())) {
                // DTLS 1.3 ciphertext
                //
                pos += 2;  // len
                ret = get_extensions().read(this, dir, stream, size, pos);
            }
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
