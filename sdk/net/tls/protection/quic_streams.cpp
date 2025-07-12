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

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frame.hpp>
#include <sdk/net/http/http3/http3_stream.hpp>
#include <sdk/net/tls/quic/frame/quic_frame.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic_streams.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_streams::quic_streams() {}

quic_streams::~quic_streams() { clear(); }

quic_streams& quic_streams::add(quic_frame_stream* stream) {
    __try2 {
        if (nullptr == stream) {
            __leave2;
        }

        auto streamid = stream->get_streamid();
        auto flags = stream->get_flags();
        uint32 finmask = 0;

        if (quic_frame_stream::quic_frame_stream_fin & flags) {
            finmask = bin_check_fin;
        }

        if (quic_frame_stream::quic_frame_stream_off & flags) {
            _streams.write(streamid, stream->get_offset(), stream->get_streamdata(), bin_wait_fin | finmask);
        } else {
            _streams.assign(streamid, stream->get_streamdata());
        }

        if (_streams.isfragmented(streamid, finmask)) {
            __leave2;
        }

        consume(stream);
    }
    __finally2 {}
    return *this;
}

quic_streams& quic_streams::operator<<(quic_frame_stream* stream) { return add(stream); }

return_t quic_streams::consume(quic_frame_stream* stream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto streamid = stream->get_streamid();

        auto lambda = [&](quic_frame_stream* stream, const binary_t& bin, size_t& pos) -> return_t {
            return_t ret = errorcode_t::success;

            auto packet = stream->get_packet();
            auto session = packet->get_session();
            auto& protection = session->get_tls_protection();
            const binary_t& alpn = protection.get_secrets().get(tls_context_alpn);

            constexpr byte_t alpn_h3[3] = {0x2, 'h', '3'};              // HTTP/3
            constexpr byte_t alpn_ping[5] = {0x4, 'p', 'i', 'n', 'g'};  // ping
            if (0 == memcmp(alpn_h3, &alpn[0], sizeof(alpn_h3))) {
                if (streamid & quic_stream_unidirectional) {
                    http3_stream h3stream;
                    ret = h3stream.read(&bin[0], bin.size(), pos);
                } else {
                    http3_frames frames;
                    ret = frames.read(&bin[0], bin.size(), pos);
                }
            } else if (0 == memcmp(alpn_ping, &alpn[0], sizeof(alpn_ping))) {
                // TODO
            }

            return ret;
        };
        _streams.consume(streamid, stream, lambda);
    }
    __finally2 {}
    return ret;
}

void quic_streams::clear() { _streams.clear(); }

void quic_streams::clear(uint64 streamid) { _streams.erase(streamid); }

}  // namespace net
}  // namespace hotplace
