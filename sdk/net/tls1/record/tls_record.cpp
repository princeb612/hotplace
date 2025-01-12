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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/record/tls_record.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "content type";
constexpr char constexpr_legacy_version[] = "legacy record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_key_epoch[] = "key epoch";
constexpr char constexpr_dtls_record_seq[] = "dtls record sequence number";

tls_record::tls_record(uint8 type, tls_session* session)
    : _content_type(type), _legacy_version(0), _cond_dtls(false), _key_epoch(0), _len(0), _session(session) {
    if (session) {
        session->addref();
    }
    _shared.make_share(this);
}

tls_record::~tls_record() {
    auto session = get_session();
    if (session) {
        session->release();
    }
}

return_t tls_record::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = read_header(dir, stream, size, pos, debugstream);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t tpos = pos;  // responding to unhandled records
        ret = read_body(dir, stream, size, tpos, debugstream);
        pos += get_length();  // responding to unhandled records
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record::read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
        if ((size < pos) || (size - pos < 5)) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        size_t recpos = pos;

        uint8 content_type = 0;
        uint16 legacy_version = 0;
        uint16 len = 0;
        bool cond_dtls = false;
        uint16 key_epoch = 0;
        binary_t dtls_record_seq;

        {
            /**
             * RFC 8446 5.1.  Record Layer
             *   enum {
             *       invalid(0),
             *       change_cipher_spec(20),
             *       alert(21),
             *       handshake(22),
             *       application_data(23),
             *       (255)
             *   } ContentType;
             *
             *   struct {
             *       ContentType type;
             *       ProtocolVersion legacy_record_version;
             *       uint16 length;
             *       opaque fragment[TLSPlaintext.length];
             *   } TLSPlaintext;
             *
             * RFC 9147 4.  The DTLS Record Layer
             *   Figure 2: DTLS 1.3 Record Formats
             *   Figure 3: DTLS 1.3 Unified Header
             *   Figure 4: DTLS 1.3 Header Examples
             */
            payload pl;
            pl << new payload_member(uint8(0), constexpr_content_type)                             // tls, dtls
               << new payload_member(uint16(0), true, constexpr_legacy_version)                    // tls, dtls
               << new payload_member(uint16(0), true, constexpr_key_epoch, constexpr_group_dtls)   // dtls
               << new payload_member(binary_t(), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(0), true, constexpr_len);                              // tls, dtls

            auto lambda_check_dtls = [&](payload* pl, payload_member* item) -> void {
                auto ver = pl->t_value_of<uint16>(item);
                pl->set_group(constexpr_group_dtls, (ver >= dtls_13));
            };
            pl.set_condition(constexpr_legacy_version, lambda_check_dtls);
            pl.select(constexpr_dtls_record_seq)->reserve(6);
            pl.read(stream, size, pos);

            content_type = pl.t_value_of<uint8>(constexpr_content_type);
            legacy_version = pl.t_value_of<uint16>(constexpr_legacy_version);
            len = pl.t_value_of<uint16>(constexpr_len);
            cond_dtls = pl.get_group_condition(constexpr_group_dtls);
            if (cond_dtls) {
                key_epoch = pl.t_value_of<uint16>(constexpr_key_epoch);
                pl.select(constexpr_dtls_record_seq)->get_variant().to_binary(dtls_record_seq);
            }
        }

        if (size - pos < len) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        {
            _content_type = content_type;
            _legacy_version = legacy_version;
            _len = len;
            _cond_dtls = cond_dtls;
            if (cond_dtls) {
                _key_epoch = key_epoch;
            }
            _range.begin = recpos;
            _range.end = pos;
        }

        if (debugstream) {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto const& range = get_header_range();

            debugstream->printf("# TLS Record\n");
            dump_memory(stream + range.begin, range.end - range.begin + get_length(), debugstream, 16, 3, 0x00, dump_notrunc);
            debugstream->printf("> content type 0x%02x(%i) (%s)\n", content_type, content_type, tlsadvisor->content_type_string(content_type).c_str());
            debugstream->printf("> %s 0x%04x (%s)\n", constexpr_legacy_version, legacy_version, tlsadvisor->tls_version_string(legacy_version).c_str());
            if (is_dtls()) {
                debugstream->printf("> %s 0x%04x\n", constexpr_key_epoch, key_epoch);
                debugstream->printf("> %s %s\n", constexpr_dtls_record_seq, base16_encode(dtls_record_seq).c_str());
                // dump_memory(dtls_record_seq, debugstream, 16, 3, 0x0, dump_notrunc);
            }
            debugstream->printf("> %s 0x%04x(%i)\n", constexpr_len, len, len);
        }

        {
            auto& protection = session->get_tls_protection();
            protection.set_record_version(_legacy_version);
        }
        {
            if (cond_dtls) {
                _dtls_record_seq = std::move(dtls_record_seq);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record::read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) { return not_supported; }

return_t tls_record::write(tls_direction_t dir, binary_t& bin, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        binary_t body;
        ret = write_body(dir, body, debugstream);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = write_header(dir, bin, body, debugstream);
    }
    __finally2 {}
    return ret;
}

return_t tls_record::write_header(tls_direction_t dir, binary_t& bin, const binary_t& body, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    {
        {
            _range.begin = bin.size();
            _len = body.size();
        }

        payload pl;
        pl << new payload_member(uint8(get_type()), constexpr_content_type)                                         // tls, dtls
           << new payload_member(uint16(get_legacy_version()), true, constexpr_legacy_version)                      // tls, dtls
           << new payload_member(uint16(get_key_epoch()), true, constexpr_key_epoch, constexpr_group_dtls)          // dtls
           << new payload_member(binary_t(get_dtls_record_seq()), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
           << new payload_member(uint16(body.size()), true, constexpr_len);                                         // tls, dtls

        auto lambda_check_dtls = [&](payload* pl, payload_member* item) -> void {
            auto ver = pl->t_value_of<uint16>(item);
            pl->set_group(constexpr_group_dtls, (ver >= dtls_13));
        };
        pl.write(bin);

        {
            auto session = get_session();
            auto& protection = session->get_tls_protection();

            _range.end = bin.size();
            _legacy_version = protection.get_record_version();
        }
    }
    return ret;
}

return_t tls_record::write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::success; }

tls_session* tls_record::get_session() { return _session; }

tls_content_type_t tls_record::get_type() { return (tls_content_type_t)_content_type; }

uint16 tls_record::get_legacy_version() { return _legacy_version; }

bool tls_record::is_dtls() { return _cond_dtls; }

uint16 tls_record::get_key_epoch() { return _key_epoch; }

const binary_t& tls_record::get_dtls_record_seq() { return _dtls_record_seq; }

uint16 tls_record::get_length() { return _len; }

const range_t& tls_record::get_header_range() { return _range; }

size_t tls_record::offsetof_header() { return _range.begin; }

size_t tls_record::offsetof_body() { return _range.end; }

void tls_record::addref() { _shared.addref(); }

void tls_record::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
