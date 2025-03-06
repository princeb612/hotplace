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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "record content type";
constexpr char constexpr_legacy_version[] = "legacy record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_key_epoch[] = "key epoch";
constexpr char constexpr_dtls_record_seq[] = "dtls record sequence number";

tls_record::tls_record(uint8 type, tls_session* session) : _content_type(type), _cond_dtls(false), _key_epoch(0), _bodysize(0), _session(session) {
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

return_t tls_record::read(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("# record\n");
            dump_memory(stream, size, &dbs, 16, 3, 0, dump_notrunc);
            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }

        ret = do_read_header(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t tpos = pos;                            // responding to unhandled records
        ret = do_read_body(dir, stream, size, tpos);  // decryption
        pos += get_body_size();                       // responding to unhandled records

        do_postprocess(dir);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        binary_t body;
        ret = do_write_body(dir, body);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_write_header(dir, bin, body);  // encryption

        do_postprocess(dir);  // change secret, recno

        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("# record constructed\n");
            dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
            trace_debug_event(category_net, net_event_tls_write, &dbs);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_record::do_postprocess(tls_direction_t dir) {
    auto session = get_session();
    /*
     * write process
     * - [record header] + [handshake + ... + finished handshake]
     * - encrypt handshake(s) using hs secret, recno (do_write_body)
     * - [record header] + [encrypted record body]
     * - using ap secret, reset recno (do_postprocess)
     */
    session->run_scheduled(dir);
    return errorcode_t::success;
}

return_t tls_record::do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((size < pos) || (size - pos < 5)) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();

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
                pl->set_group(constexpr_group_dtls, is_kindof_dtls(ver));
            };
            pl.set_condition(constexpr_legacy_version, lambda_check_dtls);
            pl.reserve(constexpr_dtls_record_seq, 6);
            pl.read(stream, size, pos);

            content_type = pl.t_value_of<uint8>(constexpr_content_type);
            legacy_version = pl.t_value_of<uint16>(constexpr_legacy_version);
            len = pl.t_value_of<uint16>(constexpr_len);
            cond_dtls = pl.get_group_condition(constexpr_group_dtls);
            if (cond_dtls) {
                key_epoch = pl.t_value_of<uint16>(constexpr_key_epoch);
                pl.get_binary(constexpr_dtls_record_seq, dtls_record_seq);
            }
        }

        if (size - pos < len) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        {
            _content_type = content_type;
            _bodysize = len;
            _cond_dtls = cond_dtls;
            if (cond_dtls) {
                _key_epoch = key_epoch;
            }
            _range.begin = recpos;
            _range.end = pos;
        }

        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto const& range = get_header_range();

            // dbs.printf("# TLS Record\n");
            dbs.printf("> %s 0x%02x(%i) (%s)\n", constexpr_content_type, content_type, content_type, tlsadvisor->content_type_string(content_type).c_str());
            dbs.printf(" > %s 0x%04x (%s)\n", constexpr_legacy_version, legacy_version, tlsadvisor->tls_version_string(legacy_version).c_str());
            if (is_dtls()) {
                dbs.printf(" > %s 0x%04x\n", constexpr_key_epoch, key_epoch);
                dbs.printf(" > %s %s\n", constexpr_dtls_record_seq, base16_encode(dtls_record_seq).c_str());
            }
            dbs.printf(" > %s 0x%04x(%i)\n", constexpr_len, len, len);

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }

        set_legacy_version(legacy_version);

        if (cond_dtls) {
            _dtls_record_seq = std::move(dtls_record_seq);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return not_supported; }

return_t tls_record::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 legacy_version = get_legacy_version();

        {
            _range.begin = bin.size();
            _bodysize = body.size();
        }

        {
            if (_dtls_record_seq.empty()) {
                _dtls_record_seq.resize(6);
            }
        }

        {
            payload pl;
            pl << new payload_member(uint8(get_type()), constexpr_content_type)                                         // tls, dtls
               << new payload_member(uint16(get_legacy_version()), true, constexpr_legacy_version)                      // tls, dtls
               << new payload_member(uint16(get_key_epoch()), true, constexpr_key_epoch, constexpr_group_dtls)          // dtls
               << new payload_member(binary_t(get_dtls_record_seq()), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(body.size()), true, constexpr_len);                                         // tls, dtls

            pl.set_group(constexpr_group_dtls, is_kindof_dtls(legacy_version));
            pl.write(bin);
        }

        _range.end = bin.size();

        binary_append(bin, body);
    }
    __finally2 {}
    return ret;
}

return_t tls_record::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

tls_session* tls_record::get_session() { return _session; }

tls_content_type_t tls_record::get_type() { return (tls_content_type_t)_content_type; }

uint16 tls_record::get_legacy_version() {
    uint16 version = 0;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    version = protection.get_lagacy_version();
    return version;
}

void tls_record::set_legacy_version(uint16 version) {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    protection.set_legacy_version(version);
}

uint16 tls_record::get_tls_version() {
    uint16 version = 0;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    version = protection.get_tls_version();
    return version;
}

void tls_record::set_tls_version(uint16 version) {
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    protection.set_tls_version(version);
}

bool tls_record::is_dtls() { return _cond_dtls; }

uint16 tls_record::get_key_epoch() { return _key_epoch; }

const binary_t& tls_record::get_dtls_record_seq() { return _dtls_record_seq; }

uint16 tls_record::get_body_size() { return _bodysize; }

const range_t& tls_record::get_header_range() { return _range; }

size_t tls_record::offsetof_header() { return _range.begin; }

size_t tls_record::offsetof_body() { return _range.end; }

void tls_record::addref() { _shared.addref(); }

void tls_record::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
