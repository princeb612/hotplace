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
#include <sdk/net/tls1/extension/tls_extension.hpp>
#include <sdk/net/tls1/handshake/tls_handshake.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_builder.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_protection.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_message_type[] = "message type";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_handshake_message_seq[] = "handshake message sequence number";
constexpr char constexpr_fragment_offset[] = "fragment offset";
constexpr char constexpr_fragment_len[] = "fragment len";

tls_handshake::tls_handshake(tls_hs_type_t type, tls_session* session)
    : _session(session), _type(type), _bodysize(0), _is_dtls(false), _dtls_seq(0), _fragment_offset(0), _fragment_len(0), _size(0), _extension_len(0) {
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

tls_handshake* tls_handshake::read(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    tls_handshake* obj = nullptr;
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (size - pos < 4) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        tls_hs_type_t hs = (tls_hs_type_t)stream[pos];
        tls_handshake_builder builder;
        auto handshake = builder.set(hs).set(session).build();
        if (handshake) {
            ret = handshake->read(dir, stream, size, pos);
            if (errorcode_t::success == ret) {
                obj = handshake;
            } else {
                handshake->release();
            }
        }
    }
    __finally2 {}
    return obj;
}

return_t tls_handshake::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        ret = do_read_header(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_preprocess(dir, stream, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // in case of CH, SH
        //    size means the end of each
        // application data(EE + finished)
        //    do not interpret finished as extension
        if (tls_hs_encrypted_extensions == get_type()) {
            ret = do_read_body(dir, stream, offsetof_body() + get_body_size(), pos);
        } else {
            ret = do_read_body(dir, stream, size, pos);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_postprocess(dir, stream, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        pos = offsetof_header() + sizeof(tls_handshake_t) + get_body_size();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        binary_t body;
        ret = do_write_body(dir, body);

        do_write_header(dir, bin, body);

        const byte_t* stream = &bin[0];
        size_t size = bin.size();

        ret = do_preprocess(dir, stream, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_postprocess(dir, stream, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake::do_preprocess(tls_direction_t dir, const byte_t* stream, size_t size) { return errorcode_t::success; }

return_t tls_handshake::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) { return errorcode_t::success; }

return_t tls_handshake::do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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
        size_t size_header_body = 0;

        {
            auto& protection = session->get_tls_protection();
            uint16 record_version = protection.get_record_version();
            size_t sizeof_dtls_recons = 0;
            if (is_kindof_dtls(record_version)) {
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
                payload pl;
                pl << new payload_member(uint8(0), constexpr_message_type)
                   << new payload_member(uint32_24_t(), constexpr_len)
                   // DTLS handshake reconstruction data
                   << new payload_member(uint16(0), true, constexpr_handshake_message_seq, constexpr_group_dtls)  // dtls
                   << new payload_member(uint32_24_t(), constexpr_fragment_offset, constexpr_group_dtls)          // dtls
                   << new payload_member(uint32_24_t(), constexpr_fragment_len, constexpr_group_dtls);            // dtls
                ;

                pl.set_group(constexpr_group_dtls, is_kindof_dtls(record_version));
                pl.read(stream, size, pos);

                hstype = (tls_hs_type_t)pl.t_value_of<uint8>(constexpr_message_type);
                length = pl.t_value_of<uint32>(constexpr_len);

                cond_dtls = pl.get_group_condition(constexpr_group_dtls);
                if (cond_dtls) {
                    dtls_seq = pl.t_value_of<uint32>(constexpr_handshake_message_seq);
                    fragment_offset = pl.t_value_of<uint32>(constexpr_fragment_offset);
                    fragment_len = pl.t_value_of<uint32>(constexpr_fragment_len);
                }
            }
            size_header_body = sizeof(tls_handshake_t) + length + sizeof_dtls_recons;  // see sizeof_dtls_recons
        }

        {
            _range.begin = hspos;
            _range.end = pos;
            _bodysize = length;
            _is_dtls = cond_dtls;
            if (cond_dtls) {
                _dtls_seq = dtls_seq;
                _fragment_offset = fragment_offset;
                _fragment_len = fragment_len;
            }
            _size = size_header_body;
        }

        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            dbs.printf(" > handshake type 0x%02x(%i) (%s)\n", hstype, hstype, tlsadvisor->handshake_type_string(hstype).c_str());
            dbs.printf(" > length 0x%06x(%i)\n", length, length);
            if (cond_dtls) {
                dbs.printf(" > %s 0x%04x\n", constexpr_handshake_message_seq, dtls_seq);
                dbs.printf(" > %s 0x%06x(%i)\n", constexpr_fragment_offset, fragment_offset, fragment_offset);
                dbs.printf(" > %s 0x%06x(%i)\n", constexpr_fragment_len, fragment_len, fragment_len);
            }

            trace_debug_event(category_tls1, tls_event_read, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return errorcode_t::success; }

return_t tls_handshake::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) {
    return_t ret = errorcode_t::success;

    // RFC 8446 4.1.2.  Client Hello
    // legacy_version
    //   In TLS 1.3, the client indicates its version preferences in the "supported_versions" extension (Section 4.2.1)
    //   and the legacy_version field MUST be set to 0x0303, which is the version number for TLS 1.2.
    //   TLS 1.3 ClientHellos are identified as having a legacy_version of 0x0303 and a supported_versions extension
    //   present with 0x0304 as the highest version indicated therein.

    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto record_version = protection.get_record_version();

    payload pl;
    pl << new payload_member(uint8(get_type()), constexpr_message_type)
       << new payload_member(uint32_24_t(body.size()), constexpr_len)
       // DTLS handshake reconstruction data
       << new payload_member(uint16(_dtls_seq), true, constexpr_handshake_message_seq, constexpr_group_dtls)  // dtls
       << new payload_member(uint32_24_t(_fragment_offset), constexpr_fragment_offset, constexpr_group_dtls)  // dtls
       << new payload_member(uint32_24_t(_fragment_len), constexpr_fragment_len, constexpr_group_dtls);       // dtls
    ;

    pl.set_group(constexpr_group_dtls, is_kindof_dtls(record_version));
    {
        _range.begin = bin.size();
        _bodysize = body.size();
    }
    pl.write(bin);
    {
        _range.end = bin.size();
        _size = bin.size() + body.size();
    }
    binary_append(bin, body);

    return ret;
}

return_t tls_handshake::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

void tls_handshake::addref() { _shared.addref(); }

void tls_handshake::release() { _shared.delref(); }

tls_extensions& tls_handshake::get_extensions() { return _extensions; }

tls_hs_type_t tls_handshake::get_type() { return _type; }

tls_session* tls_handshake::get_session() { return _session; }

size_t tls_handshake::get_size() { return _size; }

const range_t& tls_handshake::get_header_range() { return _range; }

size_t tls_handshake::offsetof_header() { return _range.begin; }

size_t tls_handshake::offsetof_body() { return _range.end; }

uint32 tls_handshake::get_body_size() { return _bodysize; }

}  // namespace net
}  // namespace hotplace
