/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_encrypted_extensions.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_protection.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_encrypted_extensions::tls_handshake_encrypted_extensions(tls_session* session) : tls_handshake(tls_hs_encrypted_extensions, session) {}

return_t tls_handshake_encrypted_extensions::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        { protection.calc_transcript_hash(session, stream + hspos, get_size()); }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_encrypted_extensions::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
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

            auto& protection = session->get_tls_protection();
            // if (protection.is_kindof_dtls() /* || (tls_0_rtt == protection.get_flow()) */) {
            if (protection.is_kindof_dtls() || (tls_0_rtt == protection.get_flow())) {
                // DTLS 1.3 ciphertext
                // uint16 len = ntoh16(*(uint16*)(stream + pos));
                pos += 2;  // len
                ret = get_extensions().read(tls_hs_encrypted_extensions, session, dir, stream, size, pos);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_encrypted_extensions::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    binary_t extensions;
    ret = get_extensions().write(extensions);
    binary_append(bin, uint16(extensions.size()), hton16);
    binary_append(bin, extensions);
    return ret;
}

}  // namespace net
}  // namespace hotplace
