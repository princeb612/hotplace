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
#include <sdk/net/http/http3/http3_frames.hpp>
#include <sdk/net/http/qpack/qpack_encoder.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream_h3_handler.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

quic_frame_stream_h3_handler::quic_frame_stream_h3_handler(tls_session* session) : quic_frame_stream_handler(session) {}

quic_frame_stream_h3_handler::~quic_frame_stream_h3_handler() {}

return_t quic_frame_stream_h3_handler::read(uint64 stream_id) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& streams = session->get_quic_session().get_streams();

        auto lambda_decoder = [&](const binary_t& bin, size_t& pos) -> return_t {
            return_t ret = errorcode_t::success;
            qpack_encoder encoder;
            std::list<http_compression_decode_t> kv;
            auto& dyntable = session->get_quic_session().get_dynamic_table();
            ret = encoder.decode(&dyntable, bin.empty() ? nullptr : &bin[0], bin.size(), pos, kv, qpack_quic_stream_decoder);
            return ret;
        };
        auto lambda_encoder = [&](const binary_t& bin, size_t& pos) -> return_t {
            return_t ret = errorcode_t::success;
            qpack_encoder encoder;
            std::list<http_compression_decode_t> kv;
            auto& dyntable = session->get_quic_session().get_dynamic_table();
            ret = encoder.decode(&dyntable, bin.empty() ? nullptr : &bin[0], bin.size(), pos, kv, qpack_quic_stream_encoder);
            return ret;
        };
        auto lambda_control = [&](const binary_t& bin, size_t& pos) -> return_t {
            return_t ret = errorcode_t::success;
            http3_frames frames;
            ret = frames.read(session, bin.empty() ? nullptr : &bin[0], bin.size(), pos);
            return ret;
        };

        if (quic_stream_unidirectional == (stream_id & quic_stream_unidirectional)) {
            uint8 unitype = 0;
            ret = streams.gettag(stream_id, unitype);
            if (errorcode_t::success != ret) {
                __leave2;  // not_found
            }

            switch (unitype) {
                case h3_qpack_decoder_stream: {
                    ret = streams.consume(stream_id, lambda_decoder);
                } break;
                case h3_qpack_encoder_stream: {
                    ret = streams.consume(stream_id, lambda_encoder);
                } break;
                case h3_push_stream: {
                    ret = errorcode_t::not_implemented;
                } break;
                case h3_control_stream: {
                    ret = streams.consume(stream_id, lambda_control);
                } break;
            }
        } else {
            ret = streams.consume(stream_id, lambda_control);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
