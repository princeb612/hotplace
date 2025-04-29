/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/io/stream/stream.hpp>
#include <sdk/net/tls/dtls_record_publisher.hpp>
#include <sdk/net/tls/tls/handshake/dtls_handshake_fragmented.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

dtls_record_publisher::dtls_record_publisher() : _session(nullptr), _fragment_size(1024) {}

void dtls_record_publisher::set_fragment_size(uint16 size) {
    const uint16 minsize = 1 << 7;
    const uint16 maxsize = 1 << 10;
    adjust_range(size, minsize, maxsize);
    _fragment_size = size;
}

uint16 dtls_record_publisher::get_fragment_size() { return _fragment_size; }

return_t dtls_record_publisher::publish(tls_record* record, tls_direction_t dir, std::function<void(binary_t& bin)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;
        auto session = get_session();

        {
            auto rctype = record->get_type();
            tls_hs_type_t hstype = tls_hs_client_hello;
            size_t last_fragment_size = 0;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto& kv = session->get_session_info(dir).get_keyvalue();
            uint16 hsseq = 0;

            auto lambda_fragment = [&](const byte_t* stream, size_t size, size_t fragment_offset, size_t fragment_size) -> void {
                auto record_fragmented = builder.set(session).set(rctype).set(dir).construct().build();
                if (record_fragmented) {
                    auto handshake = new dtls_handshake_fragmented(hstype, session);
                    if (handshake) {
                        handshake->prepare_fragment(stream, size, hsseq, fragment_offset, fragment_size);
                        last_fragment_size = fragment_size;
                        *record_fragmented << handshake;
                    }

                    binary_t bin;
                    record_fragmented->write(dir, bin);
                    func(bin);

                    record_fragmented->release();
                }
            };

            auto lambda_handshake = [&](tls_handshake* handshake) -> void {
                binary_t bin;
                handshake->do_write_body(dir, bin);
                hstype = handshake->get_type();
                hsseq = kv.get(session_dtls_message_seq);
                split(bin, get_fragment_size(), lambda_fragment);
                kv.inc(session_dtls_message_seq);
            };

            if (tls_content_type_handshake == rctype) {
                // do not change epoch, sequence
                tls_record_handshake* record_handshake = static_cast<tls_record_handshake*>(record);

                record_handshake->set_flags(dont_control_dtls_sequence);

                record_handshake->get_handshakes().for_each(lambda_handshake);

                binary_t bin_record;
                record_handshake->write(dir, bin_record);
            } else {
                record->addref();

                binary_t bin;
                record->write(dir, bin);

                func(bin);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void dtls_record_publisher::set_session(tls_session* session) { _session = session; }

tls_session* dtls_record_publisher::get_session() { return _session; }

}  // namespace net
}  // namespace hotplace
