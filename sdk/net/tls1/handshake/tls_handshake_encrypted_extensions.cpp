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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_handshake.hpp>

namespace hotplace {
namespace net {

tls_handshake_encrypted_extensions::tls_handshake_encrypted_extensions(tls_session* session) : tls_handshake(tls_hs_encrypted_extensions, session) {}

return_t tls_handshake_encrypted_extensions::do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = get_header_range().begin;
        auto hdrsize = get_header_size();
        auto& protection = session->get_tls_protection();

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

            ret = do_read(dir, stream + hspos, hdrsize, pos, debugstream);

            protection.calc_transcript_hash(session, stream + hspos, hdrsize);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_encrypted_extensions::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
            // RFC 8446 4.3.1.  Encrypted Extensions

            auto& protection = session->get_tls_protection();
            // if (protection.is_kindof_dtls() /* || (tls_0_rtt == protection.get_flow()) */) {
            if (protection.is_kindof_dtls() || (tls_0_rtt == protection.get_flow())) {
                // DTLS 1.3 ciphertext

                pos += 2;  // len
                for (return_t test = errorcode_t::success;;) {
                    test = tls_dump_extension(tls_hs_encrypted_extensions, session, stream, size, pos, debugstream);
                    if (errorcode_t::no_more == test) {
                        break;
                    } else if (errorcode_t::success == test) {
                        continue;
                    } else {
                        ret = test;
                        break;
                    }
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
