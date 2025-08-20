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
#include <sdk/net/tls/quic/frame/quic_frame_stream.hpp>
#include <sdk/net/tls/quic/packet/quic_packet.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>
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
constexpr char constexpr_group_offset[] = "offset";
constexpr char constexpr_length[] = "length";
constexpr char constexpr_group_length[] = "length";
constexpr char constexpr_stream_data[] = "stream data";
constexpr char constexpr_unitype[] = "uni type";  // uni-directional

quic_frame_stream::quic_frame_stream(quic_packet* packet) : quic_frame(quic_frame_type_stream, packet), _streamid(0), _unitype(0), _offset(0) {}

return_t quic_frame_stream::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto tlsadvisor = tls_advisor::get_instance();
        auto type = get_type();
        bool offbit = (type & quic_frame_stream_off) ? true : false;
        bool lenbit = (type & quic_frame_stream_len) ? true : false;
        bool finbit = (type & quic_frame_stream_fin) ? true : false;

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_stream_id)                       //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_offset, constexpr_group_offset)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_length, constexpr_group_length)  //
           << new payload_member(binary_t(), constexpr_stream_data);
        pl.set_group(constexpr_group_offset, offbit);
        pl.set_group(constexpr_group_length, lenbit);
        if (lenbit) {
            pl.set_reference_value(constexpr_stream_data, constexpr_length);
        }
        pl.read(stream, size, pos);

        uint64 stream_id = 0;
        uint64 fin = 0;
        uint64 len = 0;
        uint64 off = 0;
        binary_t stream_data;

        {
            stream_id = pl.t_value_of<uint64>(constexpr_stream_id);
            if (lenbit) {
                len = pl.t_value_of<uint64>(constexpr_length);
            }
            if (offbit) {
                off = pl.t_value_of<uint64>(constexpr_offset);
            }
            pl.get_binary(constexpr_stream_data, stream_data);

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
                dbs.println("   > %s 0x%zx (%zi)", constexpr_stream_data, stream_data.size(), stream_data.size());
                if (check_trace_level(loglevel_debug)) {
                    dump_memory(stream_data, &dbs, 16, 5, 0x0, dump_notrunc);
                }
                trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
            }
#endif

            _streamid = stream_id;
            _offset = off;
            _streamdata = std::move(stream_data);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_stream::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto segment = get_packet()->get_fragment().get_segment();
        if (segment) {
            size_t bumper = 0;
            segment->peek(quic_frame_type_stream, [&](const fragment_context& context) -> return_t {
                binary_t temp;
                uint8 type = get_type() | quic_frame_stream_off | quic_frame_stream_len;
                quic_write_vle_int(type, temp);
                quic_write_vle_int(_streamid, temp);
                quic_write_vle_int(context.pos, temp);
                auto len = context.size - context.pos;
                quic_write_vle_int(len > context.ssize ? context.ssize : len, temp);
                bumper = temp.size();
                if (quic_stream_unidirectional == (_streamid & quic_stream_unidirectional)) {
                    bumper += 1;  // h3_stream_t
                }
                return success;
            });
            auto lambda = [&](const byte_t* stream, size_t size, size_t pos, size_t len) -> return_t {
                return_t ret = errorcode_t::success;
                ret = do_write_body(dir, stream, size, pos, len, bin);
                return ret;
            };
            ret = get_packet()->get_fragment().consume(quic_frame_type_stream, bumper, lambda);
        }
    }
    __finally2 {}
    return ret;
}

return_t quic_frame_stream::do_write_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, size_t len, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t snapshot = bin.size();
        auto session = get_packet()->get_session();

        uint8 type = get_type() | quic_frame_stream_off | quic_frame_stream_len;
        auto is_uni = (quic_stream_unidirectional == (_streamid & quic_stream_unidirectional));
        auto slen = is_uni ? len + 1 : len;

        payload pl;
        pl << new payload_member(new quic_encoded(type), constexpr_type)                                    //
           << new payload_member(new quic_encoded(uint64(_streamid)), constexpr_stream_id)                  //
           << new payload_member(new quic_encoded(uint64(pos)), constexpr_offset, constexpr_group_offset)   //
           << new payload_member(new quic_encoded(uint64(slen)), constexpr_length, constexpr_group_length)  //
           << new payload_member(new quic_encoded(_unitype), constexpr_unitype, constexpr_unitype)          //
           << new payload_member(stream + pos, len, false, constexpr_stream_data);
        pl.set_group(constexpr_stream_data, is_uni);
        pl.write(bin);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("\e[1;33m + STREAM");
            dbs.println("   > %s 0x%zx (%zi)", constexpr_offset, pos, pos);
            dbs.println("   > %s 0x%zx (%zi)\e[0m", constexpr_length, len, len);
            trace_debug_event(trace_category_net, trace_event_quic_frame, &dbs);
        }
#endif
    }
    __finally2 {}

    return ret;
}

return_t quic_frame_stream::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    get_packet()->get_session()->get_quic_session() << this;
    return ret;
}

uint8 quic_frame_stream::get_flags() { return (quic_frame_stream_mask & get_type()); }

uint64 quic_frame_stream::get_streamid() { return _streamid; }

uint64 quic_frame_stream::get_offset() { return _offset; }

binary_t& quic_frame_stream::get_streamdata() { return _streamdata; }

quic_frame_stream& quic_frame_stream::set_streaminfo(uint64 streamid, uint8 unitype) {
    _streamid = streamid;
    _unitype = unitype;
    return *this;
}

http3_frames quic_frame_stream::get_frames() { return _frames; }

}  // namespace net
}  // namespace hotplace
