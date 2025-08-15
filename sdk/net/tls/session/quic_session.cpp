/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frames.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

quic_session::quic_session() { get_setting().set(quic_param_max_udp_payload_size, 1200); }

quic_session::~quic_session() { clear(); }

t_key_value<uint64, uint64>& quic_session::get_setting() { return _setting; }

qpack_dynamic_table& quic_session::get_dynamic_table() { return _qpack_dyntable; }

t_ovl_points<uint32>& quic_session::get_pkns(protection_space_t space) { return _pkn[space]; }

quic_session& quic_session::add(quic_frame_stream* stream) {
    __try2 {
        if (nullptr == stream) {
            __leave2;
        }

        auto streamid = stream->get_streamid();
        auto flags = stream->get_flags();
        uint32 finmask = 0;

        if (quic_frame_stream::quic_frame_stream_fin & flags) {
            finmask = bin_wait_fin;
        }

        if (quic_frame_stream::quic_frame_stream_off & flags) {
            _streams.write(streamid, stream->get_offset(), stream->get_streamdata(), finmask);
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

quic_session& quic_session::operator<<(quic_frame_stream* stream) { return add(stream); }

return_t quic_session::consume(quic_frame_stream* stream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto lambda_h3 = [&](quic_frame_stream* stream, const binary_t& bin, size_t& pos) -> return_t {
            return_t ret = errorcode_t::success;
            auto streamid = stream->get_streamid();
            if (streamid & quic_stream_unidirectional) {
                auto lambda_decode = [&](const binary_t& tbin, size_t& tpos, uint32 flag) -> return_t {
                    qpack_encoder encoder;
                    std::list<qpack_decode_t> kv;
                    return encoder.decode(&_qpack_dyntable, &tbin[0], tbin.size(), tpos, kv, flag);
                };

                auto iter = _encoders.find(streamid);
                if (_encoders.end() != iter) {
                    auto unistreamtype = iter->second;
                    switch (unistreamtype) {
                        case h3_qpack_decoder_stream: {
                            lambda_decode(bin, pos, qpack_quic_stream_decoder);
                        } break;
                        case h3_qpack_encoder_stream: {
                            lambda_decode(bin, pos, qpack_quic_stream_encoder);
                        } break;
                    }
                } else {
                    uint64 unistreamtype = 0;
                    ret = quic_read_vle_int(&bin[0], bin.size(), pos, unistreamtype);
                    if (errorcode_t::success == ret) {
                        switch (unistreamtype) {
                            case h3_qpack_decoder_stream: {
                                _encoders.insert({streamid, unistreamtype});
                                lambda_decode(bin, pos, qpack_quic_stream_decoder);
                            } break;
                            case h3_qpack_encoder_stream: {
                                _encoders.insert({streamid, unistreamtype});
                                lambda_decode(bin, pos, qpack_quic_stream_encoder);
                            } break;
                            case h3_push_stream: {
                            } break;
                            case h3_control_stream: {
                                http3_frames frames;
                                ret = frames.read(&_qpack_dyntable, &bin[0], bin.size(), pos);
                            } break;
                        }
                    }
                }

            } else {
                http3_frames frames;
                ret = frames.read(&_qpack_dyntable, &bin[0], bin.size(), pos);
            }

            return ret;
        };

        constexpr byte_t alpn_h3[3] = {0x2, 'h', '3'};              // HTTP/3
        constexpr byte_t alpn_ping[5] = {0x4, 'p', 'i', 'n', 'g'};  // ping

        const binary_t& alpn = stream->get_packet()->get_session()->get_tls_protection().get_secrets().get(tls_context_alpn);
        if (0 == memcmp(alpn_h3, &alpn[0], sizeof(alpn_h3))) {
            ret = _streams.consume(stream->get_streamid(), stream, lambda_h3);
        } else if (0 == memcmp(alpn_ping, &alpn[0], sizeof(alpn_ping))) {
            //
        }
    }
    __finally2 {}
    return ret;
}

void quic_session::clear() { _streams.clear(); }

void quic_session::clear(uint64 streamid) { _streams.erase(streamid); }

}  // namespace net
}  // namespace hotplace
