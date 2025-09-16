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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frame.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/frame/quic_frame_http3_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
#include <sdk/net/tls/quic_packet_publisher.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_off_bit[] = "OFF bit (0x04)";
constexpr char constexpr_len_bit[] = "LEN bit (0x02)";
constexpr char constexpr_fin_bit[] = "FIN bit (0x01)";

constexpr char constexpr_type[] = "type";
constexpr char constexpr_stream_id[] = "stream id";
constexpr char constexpr_offset[] = "offset";
constexpr char constexpr_length[] = "length";
constexpr char constexpr_stream_data[] = "stream data";
constexpr char constexpr_unitype[] = "uni type";  // uni-directional

quic_frame_http3_stream::quic_frame_http3_stream(tls_session* session, uint8 type) : quic_frame_stream(session, type), _unitype(0) {}

return_t quic_frame_http3_stream::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto tlsadvisor = tls_advisor::get_instance();
        auto type = get_type();
        bool offbit = (type & quic_frame_stream_off) ? true : false;
        bool lenbit = (type & quic_frame_stream_len) ? true : false;
        bool finbit = (type & quic_frame_stream_fin) ? true : false;

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id)                 //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_offset, constexpr_offset)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_length, constexpr_length)  //
           << new payload_member(binary_t(), constexpr_stream_data);
        pl.set_group(constexpr_offset, offbit);
        pl.set_group(constexpr_length, lenbit);
        if (lenbit) {
            pl.set_reference_value(constexpr_stream_data, constexpr_length);
        }
        pl.read(stream, size, pos);

        uint64 stream_id = 0;
        uint64 fin = 0;
        uint64 len = 0;
        uint64 off = 0;
        binary_t stream_data;
        auto session = get_session();
        auto& streams = session->get_quic_session().get_streams();
        auto is_begin = false;

        stream_id = pl.t_value_of<uint64>(constexpr_stream_id);
        if (lenbit) {
            len = pl.t_value_of<uint64>(constexpr_length);
        }
        if (offbit) {
            off = pl.t_value_of<uint64>(constexpr_offset);
        }
        pl.get_binary(constexpr_stream_data, stream_data);

        _stream_id = stream_id;

        if (stream_data.empty()) {
            __leave2;
        }

        /**
         * - if uni-directional, skip the first byte
         *   - RFC 9114 6.  Stream Mapping and Usage
         *   - see h3_stream_t
         * - sketch
         *   - even if the size of stream is 0, should insert the stream_id into get_streams
         */

        uint8 unitype = 0;
        size_t pos = 0;
        {
            if (streams.is_unidirectional_stream(stream_id)) {
                unitype = stream_data[0];
                is_begin = streams.reserve(stream_id, unitype);
                if (is_begin) {
                    pos = 1;
                } else {
                    streams.get_unistream_type(stream_id, unitype);
                }
            }
            streams.append(stream_id, stream_data.size() > pos ? &stream_data[pos] : nullptr, stream_data.size() - pos);

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                basic_stream dbs;
                dbs.println("   > %s %i", constexpr_fin_bit, finbit);
                dbs.println("   > %s %i", constexpr_len_bit, lenbit);
                if (lenbit) {
                    dbs.println("     > 0x%I64x (%I64i)", len, len);
                }
                dbs.println("   > %s %i", constexpr_off_bit, offbit);
                if (offbit) {
                    dbs.println("     > 0x%I64x (%I64i)", off, off);
                }
                dbs.println("   > %s 0x%I64x (%I64i) %s", constexpr_stream_id, stream_id, stream_id, tlsadvisor->quic_streamid_type_string(stream_id).c_str());
                if (streams.is_unidirectional_stream(stream_id)) {
                    auto resource = http_resource::get_instance();
                    dbs.println("    > %s %s", resource->get_h3_stream_name(unitype).c_str(), is_begin ? "*" : "");
                }
                dbs.println("   > %s 0x%zx (%zi)", constexpr_stream_data, stream_data.size(), stream_data.size());
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(stream_data, &dbs, 16, 5, 0x0, dump_notrunc);
                }
                trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
            }
#endif
        }

        switch (unitype) {
            case h3_control_stream: {
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

            } break;
            case h3_qpack_encoder_stream: {
                if (stream_data.size() > pos) {
                    auto& dyntable = session->get_quic_session().get_dynamic_table();
                    qpack_encoder encstream;
                    std::list<http_compression_decode_t> kv;
                    encstream.decode(&dyntable, &stream_data[0], stream_data.size(), pos, kv, qpack_quic_stream_encoder);
                }
            } break;
            case h3_qpack_decoder_stream: {
                if (stream_data.size() > pos) {
                    auto& dyntable = session->get_quic_session().get_dynamic_table();
                    qpack_encoder encstream;
                    std::list<http_compression_decode_t> kv;
                    encstream.decode(&dyntable, &stream_data[0], stream_data.size(), pos, kv, qpack_quic_stream_decoder);
                }
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_http3_stream::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    if (get_publisher()) {
        get_publisher()->consume(get_packet(), bin.size(), [&](segment_t& segment) -> return_t {
            binary_t temp;
            uint8 type = quic_frame_type_stream | quic_frame_stream_len;
            if (segment.pos) {
                type |= quic_frame_stream_off;
            }
            quic_write_vle_int(type, temp);
            quic_write_vle_int(_stream_id, temp);
            if (segment.pos) {
                quic_write_vle_int(segment.pos, temp);
            }

            segment.calc(bin.size() + temp.size());

            quic_write_vle_int(segment.len, temp);

            auto session = get_session();
            auto& streams = session->get_quic_session().get_streams();
            if (streams.is_unidirectional_stream(_stream_id)) {
                if (false == streams.exist(_stream_id)) {
                    temp.push_back(_unitype);
                    segment.calc(bin.size() + temp.size());
                }
            }

            return do_write_body(dir, segment.stream, segment.size, segment.pos, segment.len, bin);
        });
    }
    return ret;
}

return_t quic_frame_http3_stream::do_write_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, size_t len, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (size && (nullptr == stream)) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t snapshot = bin.size();
        auto tlsadvisor = tls_advisor::get_instance();

        uint8 type = quic_frame_type_stream;
        type |= quic_frame_stream_len;
        if (pos) {
            type |= quic_frame_stream_off;
        }
        if (size == pos + len) {
            type |= quic_frame_stream_fin;
        }

        set_type(type);

        auto session = get_session();
        auto& streams = session->get_quic_session().get_streams();
        auto is_begin = false;
        size_t slen = len;
        if (streams.is_unidirectional_stream(_stream_id)) {
            is_begin = streams.reserve(_stream_id, _unitype);
            if (is_begin) {
                slen += 1;
            } else {
                streams.get_unistream_type(_stream_id, _unitype);
            }
            streams.append(_stream_id, stream + pos, len);
        }

        payload pl;
        pl << new payload_member(new quic_encoded(type), constexpr_type)                              //
           << new payload_member(new quic_encoded(uint64(_stream_id)), constexpr_stream_id)           //
           << new payload_member(new quic_encoded(uint64(pos)), constexpr_offset, constexpr_offset)   //
           << new payload_member(new quic_encoded(uint64(slen)), constexpr_length, constexpr_length)  //
           << new payload_member(new quic_encoded(_unitype), constexpr_unitype, constexpr_unitype)    //
           << new payload_member(stream + pos, len, false, constexpr_stream_data);
        pl.set_group(constexpr_offset, (pos > 0));
        pl.set_group(constexpr_unitype, is_begin);
        pl.write(bin);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("\e[1;34m  + frame %s 0x%x(%i)\e[0m", tlsadvisor->quic_frame_type_string(type).c_str(), type, type);
            dbs.println("   > %s 0x%zx (%zi)", constexpr_offset, pos, pos);
            dbs.println("   > %s 0x%zx (%zi)\e[0m", constexpr_length, len, len);
            dbs.println("   > %s 0x%I64x (%I64i) %s", constexpr_stream_id, _stream_id, _stream_id, tlsadvisor->quic_streamid_type_string(_stream_id).c_str());
            auto resource = http_resource::get_instance();
            dbs.println("    > %s", resource->get_h3_stream_name(_unitype).c_str());
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
    }
    __finally2 {}

    return ret;
}

void quic_frame_http3_stream::set(uint64 stream_id, uint8 unitype) {
    _stream_id = stream_id;
    _unitype = unitype;
}

http3_frames& quic_frame_http3_stream::get_frames() { return _frames; }

}  // namespace net
}  // namespace hotplace
