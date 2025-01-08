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

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_handshake_message_seq[] = "handshake message sequence number";
constexpr char constexpr_fragment_offset[] = "fragment offset";
constexpr char constexpr_fragment_len[] = "fragment len";

tls_handshake::tls_handshake(tls_hs_type_t type, tls_session* session)
    : _session(session), _type(type), _len(0), _is_dtls(false), _dtls_seq(0), _fragment_offset(0), _fragment_len(0), _hdrsize(0) {
    if (session) {
        session->addref();
    }
    _shared.make_share(this);
}

tls_handshake::~tls_handshake() {
    auto session = get_session();
    if (session) {
        session->release();
    }
}

return_t tls_handshake::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = do_read_header(dir, stream, size, pos, debugstream);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_handshake(dir, stream, size, pos, debugstream);

        pos = get_header_range().begin + sizeof(tls_handshake_t) + get_length();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake::do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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

        size_t hspos = pos;

        tls_hs_type_t hstype;
        uint32 length = 0;
        bool cond_dtls = false;
        uint16 dtls_seq = 0;
        uint32 fragment_offset = 0;
        uint32 fragment_len = 0;
        size_t hdrsize = 0;

        {
            auto& protection = session->get_tls_protection();
            uint16 record_version = protection.get_record_version();
            size_t sizeof_dtls_recons = 0;
            if (is_kindof_dtls(record_version)) {
                // problem
                //    do_something(stream + hspos, sizeof(tls_handshake_t) + length, ...) -> DTLS fails
                //    contrast...
                //    do_something(stream + hspos, size - hspos, ...) -> pass
                //    do_something(stream + hspos, sizeof(tls_handshake_t) + length + sizeof_dtls_recons, ...) -> pass
                // checkpoint
                //    1) reconstruction_data size (8 bytes)
                //       tls_content_t::length    included
                //       tls_handshake_t::length  excluded
                //    2) tls_handshake_t::length == reconstruction_data::fragment_len
                //       lengthof(record) = record_header(13) + tls_handshake_t(4) + reconstruction_data(8) + tls_handshake_t::length

                sizeof_dtls_recons = 8;
            }

            if ((size < pos) || (size - pos < (sizeof(tls_handshake_t) + sizeof_dtls_recons))) {
                ret = errorcode_t::no_more;
                __leave2;
            }

            {
                constexpr char constexpr_message_type[] = "message type";
                constexpr char constexpr_len[] = "len";
                payload pl;
                pl << new payload_member(uint8(0), constexpr_message_type) << new payload_member(uint32_24_t(), constexpr_len);
                pl.read(stream, size, pos);

                hstype = (tls_hs_type_t)pl.t_value_of<uint8>(constexpr_message_type);
                length = pl.t_value_of<uint32>(constexpr_len);
            }
            // uint32_24_t
            // tls_handshake_t* handshake = (tls_handshake_t*)(stream + pos);
            // b24_i32(handshake->length, length);
            // if (size < pos + sizeof(tls_handshake_t) + length) {
            //     ret = errorcode_t::bad_data;
            //     __leave2;
            // }
            // pos += sizeof(tls_handshake_t);

            // hstype = handshake->msg_type;
            hdrsize = sizeof(tls_handshake_t) + length + sizeof_dtls_recons;  // see sizeof_dtls_recons

            // DTLS handshake reconstruction data
            {
                payload pl;
                pl << new payload_member(uint16(0), true, constexpr_handshake_message_seq, constexpr_group_dtls)  // dtls
                   << new payload_member(uint32_24_t(), constexpr_fragment_offset, constexpr_group_dtls)          // dtls
                   << new payload_member(uint32_24_t(), constexpr_fragment_len, constexpr_group_dtls);            // dtls;
                pl.set_group(constexpr_group_dtls, is_kindof_dtls(record_version));
                pl.read(stream, size, pos);

                cond_dtls = pl.get_group_condition(constexpr_group_dtls);
                if (cond_dtls) {
                    dtls_seq = pl.t_value_of<uint32>(constexpr_handshake_message_seq);
                    fragment_offset = pl.t_value_of<uint32>(constexpr_fragment_offset);
                    fragment_len = pl.t_value_of<uint32>(constexpr_fragment_len);
                }
            }
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            debugstream->printf(" > handshake type 0x%02x(%i) (%s)\n", hstype, hstype, tlsadvisor->handshake_type_string(hstype).c_str());
            debugstream->printf(" > length 0x%06x(%i)\n", length, length);
            if (cond_dtls) {
                debugstream->printf(" > %s 0x%04x\n", constexpr_handshake_message_seq, dtls_seq);
                debugstream->printf(" > %s 0x%06x(%i)\n", constexpr_fragment_offset, fragment_offset, fragment_offset);
                debugstream->printf(" > %s 0x%06x(%i)\n", constexpr_fragment_len, fragment_len, fragment_len);
            }
        }
        {
            _range.begin = hspos;
            _range.end = pos;
            _len = length;
            _is_dtls = cond_dtls;
            if (cond_dtls) {
                _dtls_seq = dtls_seq;
                _fragment_offset = fragment_offset;
                _fragment_len = fragment_len;
            }
            _hdrsize = hdrsize;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake::do_handshake(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return errorcode_t::not_supported;
}

return_t tls_handshake::do_read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return errorcode_t::not_supported;
}

return_t tls_handshake::write(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

void tls_handshake::addref() { _shared.addref(); }

void tls_handshake::release() { _shared.delref(); }

tls_hs_type_t tls_handshake::get_type() { return _type; }

tls_session* tls_handshake::get_session() { return _session; }

size_t tls_handshake::get_header_size() { return _hdrsize; }

const range_t& tls_handshake::get_header_range() { return _range; }

uint32 tls_handshake::get_length() { return _len; }

}  // namespace net
}  // namespace hotplace
