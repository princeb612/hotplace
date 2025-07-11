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
#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/extension/tls_extension.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_message_type[] = "message type";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_handshake_message_seq[] = "sequence number";
constexpr char constexpr_fragment[] = "fragment";
constexpr char constexpr_fragment_offset[] = "fragment offset";
constexpr char constexpr_fragment_len[] = "fragment len";

tls_handshake::tls_handshake(tls_hs_type_t type, tls_session* session)
    : _session(session),
      _type(type),
      _bodysize(0),
      _is_dtls(false),
      _dtls_seq(0),
      _fragment_offset(0),
      _fragment_len(0),
      _reassembled_size(0),
      _size(0),
      _extension_len(0),
      _flags(0) {
    if (session) {
        session->addref();
    } else {
        throw exception(errorcode_t::no_session);
    }
    _shared.make_share(this);
}

tls_handshake::~tls_handshake() {
    get_extensions().clear();

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

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto hstype = get_type();
            dbs.printf("\e[1;36m");
            dbs.println("# read handshake type 0x%02x(%i) (%s)", hstype, hstype, tlsadvisor->handshake_type_string(hstype).c_str());
            dbs.printf("\e[0m");
            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif

        size_t bpos = pos;

        auto test = do_read_header(dir, stream, size, pos);
        if (errorcode_t::success != test) {
            if (errorcode_t::reassemble != test) {
                ret = test;
                __leave2;
            }
        }

        ret = do_preprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // RFC 9147 5.5.  Handshake Message Fragmentation and Reassembly
        if (reassemble == test) {
            auto& protection = session->get_tls_protection();
            auto& secrets = protection.get_secrets();

            size_t tpos = 0;
            binary_t assemble;
            secrets.consume(tls_context_fragment, assemble);  // consume _bodysize

#if defined DEBUG
            if (istraceable(trace_category_net, loglevel_debug)) {
                basic_stream dbs;
                dbs.printf("\e[1;33m");
                dbs.println("> reassemble handshake message seq %i", _dtls_seq);
                dump_memory(assemble, &dbs, 16, 3, 0, dump_notrunc);
                dbs.printf("\e[0m");
                trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
            }
#endif

            dtls_handshake_t header;
            header.msg_type = get_type();
            uint24_t length(assemble.size());
            memcpy(header.length, length.data, 3);
            header.seq = hton16(_dtls_seq);
            memset(header.fragment_offset, 0, 3);
            memcpy(header.fragment_len, length.data, 3);

            assemble.insert(assemble.begin(), (byte_t*)&header, (byte_t*)&header + sizeof(header));

            ret = read(dir, &assemble[0], assemble.size(), tpos);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        } else {
            if (tls_hs_encrypted_extensions == get_type()) {
                ret = do_read_body(dir, stream, offsetof_body() + get_body_size(), pos);
            } else {
                ret = do_read_body(dir, stream, size, pos);
            }
            if ((errorcode_t::success != ret) && (errorcode_t::no_more != ret)) {
                __leave2;
            }
            ret = do_postprocess(dir, stream, size);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            pos = offsetof_body() + get_body_size();

            session->run_scheduled(dir);
        }
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

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto hstype = get_type();
            dbs.printf("\e[1;36m");
            dbs.println("# write %p handshake type 0x%02x(%i) (%s)", session, hstype, hstype, tlsadvisor->handshake_type_string(hstype).c_str());
            dbs.printf("\e[0m");
            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif

        ret = do_preprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_t body;
        ret = do_write_body(dir, body);

        do_write_header(dir, bin, body);

        const byte_t* stream = &bin[0];
        size_t size = bin.size();

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

void tls_handshake::run_scheduled(tls_direction_t dir) {}

return_t tls_handshake::prepare_fragment(const byte_t* stream, uint32 size, uint16 seq, uint32 fragment_offset, uint32 fragment_length) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();

        if (session_type_dtls != session->get_type()) {
            ret = errorcode_t::do_nothing;
            __leave2;
        }

        if (fragment_offset + fragment_length > size) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        _dtls_seq = seq;
        _reassembled_size = size;
        _fragment_offset = fragment_offset;
        _fragment_len = fragment_length;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake::do_preprocess(tls_direction_t dir) { return errorcode_t::success; }

return_t tls_handshake::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) { return errorcode_t::success; }

return_t tls_handshake::do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        size_t hspos = pos;
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();
        auto type = session->get_type();

        tls_hs_type_t hstype;
        uint32 length = 0;
        bool cond_dtls = false;
        uint16 dtls_seq = 0;
        uint32 fragment_offset = 0;
        uint32 fragment_len = 0;
        size_t size_header_body = 0;

        {
            uint16 legacy_version = protection.get_lagacy_version();
            size_t sizeof_dtls_recons = 0;
            if (tlsadvisor->is_kindof_dtls(legacy_version)) {
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
                   << new payload_member(uint24_t(0), constexpr_len)
                   // DTLS handshake reconstruction data
                   << new payload_member(uint16(0), true, constexpr_handshake_message_seq, constexpr_group_dtls)  // dtls
                   << new payload_member(uint24_t(0), constexpr_fragment_offset, constexpr_group_dtls)            // dtls
                   << new payload_member(uint24_t(0), constexpr_fragment_len, constexpr_group_dtls);              // dtls
                ;

                pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));
                pl.read(stream, size, pos);

                hstype = (tls_hs_type_t)pl.t_value_of<uint8>(constexpr_message_type);
                length = pl.t_value_of<uint32>(constexpr_len);

                cond_dtls = pl.get_group_condition(constexpr_group_dtls);
                if (cond_dtls) {
                    dtls_seq = pl.t_value_of<uint32>(constexpr_handshake_message_seq);
                    fragment_offset = pl.t_value_of<uint32>(constexpr_fragment_offset);
                    fragment_len = pl.t_value_of<uint32>(constexpr_fragment_len);
                    if (fragment_offset + fragment_len > length) {
                        ret = errorcode_t::bad_format;
                        __leave2;
                    }
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
                auto& kv = session->get_session_info(dir).get_keyvalue();
                auto sess_dtls_seq = kv.get(session_dtls_message_seq);
                if (sess_dtls_seq != dtls_seq) {
                    if (sess_dtls_seq + 1 == dtls_seq) {
                        kv.set(session_dtls_message_seq, dtls_seq);
                    }
                }
                _dtls_seq = dtls_seq;
                _fragment_offset = fragment_offset;
                _fragment_len = fragment_len;
            }
            _size = size_header_body;
        }

        if ((session_type_tls == type) || (session_type_dtls == type)) {
            if (cond_dtls) {
                if (fragment_len < length) {
                    if (0 == fragment_offset) {
                        secrets.erase(tls_context_fragment);
                    }

                    secrets.append(tls_context_fragment, stream + pos, fragment_len);

#if defined DEBUG
                    if (istraceable(trace_category_net, loglevel_debug)) {
                        basic_stream dbs;
                        dbs.printf("\e[1;33m");
                        dbs.println(" > fragment");
                        dump_memory(stream + pos, fragment_len, &dbs, 16, 3, 0, dump_notrunc);
                        dbs.printf("\e[0m");
                        trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
                    }
#endif

                    if (length <= secrets.get(tls_context_fragment).size()) {
                        pos += _fragment_len;
                        ret = errorcode_t::reassemble;
                    } else {
                        pos += fragment_len;
                        ret = errorcode_t::fragmented;
                    }
                }
            }
        } else if ((session_type_quic == type) || (session_type_quic2 == type)) {
            // header     body     end-of-stream
            // \- hspos   \-pos    \-size
            // case not fragmented
            // case fragmented

            if (hspos + length > size) {
                ret = errorcode_t::fragmented;
                secrets.append(tls_context_fragment, stream + hspos, size - hspos);
#if defined DEBUG
                if (istraceable(trace_category_net, loglevel_debug)) {
                    basic_stream dbs;
                    dbs.printf("\e[1;33m");
                    dbs.println(" > fragment");
                    dump_memory(stream + hspos, size - hspos, &dbs, 16, 3, 0, dump_notrunc);
                    dbs.printf("\e[0m");
                    trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
                }
#endif
            }
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.autoindent(1);
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            dbs.println("> handshake type 0x%02x(%i) (%s)", hstype, hstype, tlsadvisor->handshake_type_string(hstype).c_str());
            dbs.println(" > length 0x%06x(%i)", length, length);
            if (cond_dtls) {
                dbs.println(" > %s 0x%04x", constexpr_handshake_message_seq, dtls_seq);
                dbs.println(" > %s 0x%06x(%i)", constexpr_fragment_offset, fragment_offset, fragment_offset);
                dbs.println(" > %s 0x%06x(%i)", constexpr_fragment_len, fragment_len, fragment_len);
            }
            dbs.autoindent(0);
            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif
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

    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto legacy_version = protection.get_lagacy_version();
    auto& kv = session->get_session_info(dir).get_keyvalue();

    _fragment_len = body.size();
    uint32 length = _reassembled_size ? _reassembled_size : body.size();
    if (dont_control_dtls_handshake_sequence & get_flags()) {
    } else {
        _dtls_seq = kv.get(session_dtls_message_seq);
    }

    payload pl;
    pl << new payload_member(uint8(get_type()), constexpr_message_type)
       << new payload_member(uint24_t(length), constexpr_len)
       // DTLS handshake reconstruction data
       << new payload_member(uint16(_dtls_seq), true, constexpr_handshake_message_seq, constexpr_group_dtls)  // dtls
       << new payload_member(uint24_t(_fragment_offset), constexpr_fragment_offset, constexpr_group_dtls)     // dtls
       << new payload_member(uint24_t(_fragment_len), constexpr_fragment_len, constexpr_group_dtls);          // dtls
    ;

#if defined DEBUG
    if (istraceable(trace_category_net)) {
        basic_stream dbs;
        dbs.autoindent(1);
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto hstype = get_type();
        dbs.println("# handshake");
        dbs.println("> handshake type 0x%02x(%i) (%s)", hstype, hstype, tlsadvisor->handshake_type_string(hstype).c_str());
        dbs.println(" > length 0x%06x(%i)", length, length);
        if (session_type_dtls == session->get_type()) {
            dbs.println(" > %s 0x%04x", constexpr_handshake_message_seq, _dtls_seq);
            dbs.println(" > %s 0x%06x(%i)", constexpr_fragment_offset, _fragment_offset, _fragment_offset);
            dbs.println(" > %s 0x%06x(%i)", constexpr_fragment_len, _fragment_len, _fragment_len);
        }
        dbs.autoindent(0);
        trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
    }
#endif

    pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(legacy_version));
    {
        _range.begin = bin.size();
        _bodysize = body.size();
    }

    // handshakes 1..*
    size_t bin_oldsize = bin.size();
    pl.write(bin);
    {
        _range.end = bin.size();
        _size = bin.size() - bin_oldsize + body.size();
    }
    binary_append(bin, body);

    if (dont_control_dtls_handshake_sequence & get_flags()) {
    } else {
        _dtls_seq = kv.inc(session_dtls_message_seq);
    }

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

uint32 tls_handshake::get_body_size() { return _fragment_len ? _fragment_len : _bodysize; }

void tls_handshake::set_extension_len(uint16 len) { _extension_len = len; }

void tls_handshake::set_dtls_seq(uint16 seq) { _dtls_seq = seq; }

uint16 tls_handshake::get_dtls_seq() { return _dtls_seq; }

uint32 tls_handshake::get_fragment_offset() { return _fragment_offset; }

uint32 tls_handshake::get_fragment_len() { return _fragment_len; }

void tls_handshake::set_flags(uint32 flags) { _flags = flags; }

uint32 tls_handshake::get_flags() { return _flags; }

}  // namespace net
}  // namespace hotplace
