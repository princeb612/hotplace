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
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "record content type";
constexpr char constexpr_record_version[] = "record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_dtls_epoch[] = "epoch";
constexpr char constexpr_dtls_record_seq[] = "sequence number";

tls_record::tls_record(uint8 type, tls_session* session)
    : _content_type(type), _cond_dtls(false), _dtls_epoch(0), _dtls_record_seq(0), _bodysize(0), _session(session) {
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
#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto content_type = get_type();
            dbs.printf("\e[1;36m");
            dbs.println("# write %s 0x%02x(%i) (%s)", constexpr_content_type, content_type, content_type,
                        tlsadvisor->content_type_string(content_type).c_str());
            dbs.printf("\e[0m");
            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif
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

        auto session_type = session->get_type();
        auto& protection = session->get_tls_protection();
        auto is_dtls = (session_type == session_dtls);

        if (is_dtls) {
            auto& kv = session->get_session_info(dir).get_keyvalue();
            _dtls_epoch = kv.get(session_dtls_epoch);
            _dtls_record_seq = kv.get(session_dtls_seq);
        }

        ret = do_write_header(dir, bin, body);  // encryption

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.printf("\e[1;36m");
            dbs.println("# record constructed");
            dbs.printf("\e[0m");
            dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif

        do_postprocess(dir);  // change secret, recno

        if (is_dtls) {
            auto& kv = session->get_session_info(dir).get_keyvalue();
            if (tls_content_type_change_cipher_spec == get_type()) {
                kv.inc(session_dtls_epoch);
                kv.set(session_dtls_seq, 0);
            } else {
                kv.inc(session_dtls_seq);
            }
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
    size_t recpos = pos;
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

        uint8 content_type = 0;
        uint16 record_version = 0;
        uint16 len = 0;
        bool cond_dtls = false;
        uint16 key_epoch = 0;
        uint64 dtls_record_seq = 0;
        auto session_type = session->get_type();

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
            pl << new payload_member(uint8(0), constexpr_content_type)                              // tls, dtls
               << new payload_member(uint16(0), true, constexpr_record_version)                     // tls, dtls
               << new payload_member(uint16(0), true, constexpr_dtls_epoch, constexpr_group_dtls)   // dtls
               << new payload_member(uint48_t(0), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(0), true, constexpr_len);                               // tls, dtls

            auto lambda_check_dtls = [&](payload* pl, payload_member* item) -> void {
                auto ver = pl->t_value_of<uint16>(item);
                pl->set_group(constexpr_group_dtls, is_kindof_dtls(ver));
            };
            pl.set_condition(constexpr_record_version, lambda_check_dtls);
            pl.read(stream, size, pos);

            content_type = pl.t_value_of<uint8>(constexpr_content_type);
            record_version = pl.t_value_of<uint16>(constexpr_record_version);
            len = pl.t_value_of<uint16>(constexpr_len);
            cond_dtls = pl.get_group_condition(constexpr_group_dtls);
            if (cond_dtls) {
                key_epoch = pl.t_value_of<uint16>(constexpr_dtls_epoch);
                dtls_record_seq = pl.t_value_of<uint64>(constexpr_dtls_record_seq);
            }
        }

        if (size - pos < len) {
            ret = errorcode_t::bad_data;
            __leave2;
        } else if (len > 16384 + 2048) {
            // more than 2^14+2048 bytes
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_record_overflow);
            ret = errorcode_t::error_overflow;
            __leave2;
        }

        {
            _content_type = content_type;
            _bodysize = len;
            _cond_dtls = cond_dtls;
            if (cond_dtls) {
                _dtls_epoch = key_epoch;
            }
            _range.begin = recpos;
            _range.end = pos;
        }

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto const& range = get_header_range();

            dbs.println("# record %s [size 0x%x pos 0x%x]", (from_server == dir) ? "(server)" : (from_client == dir) ? "(client)" : "", size, recpos);
            uint16 content_header_size = 0;
            if (tlsadvisor->is_kindof_tls(record_version)) {
                content_header_size = RTL_FIELD_SIZE(tls_content_t, tls);
            } else {
                content_header_size = RTL_FIELD_SIZE(tls_content_t, dtls);
            }
            dump_memory(stream + recpos, content_header_size + len, &dbs, 16, 3, 0, dump_notrunc);

            dbs.println("> %s 0x%02x(%i) (%s)", constexpr_content_type, content_type, content_type, tlsadvisor->content_type_string(content_type).c_str());
            dbs.println(" > %s 0x%04x (%s)", constexpr_record_version, record_version, tlsadvisor->tls_version_string(record_version).c_str());
            if (is_dtls()) {
                dbs.println(" > %s 0x%04x", constexpr_dtls_epoch, key_epoch);
                dbs.println(" > %s 0x%012I64x (%I64u)", constexpr_dtls_record_seq, dtls_record_seq, dtls_record_seq);
            }
            dbs.println(" > %s 0x%04x(%i)", constexpr_len, len, len);

            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif
        if (cond_dtls) {
            _dtls_record_seq = dtls_record_seq;

            auto& kv = session->get_session_info(dir).get_keyvalue();
            kv.set(session_dtls_epoch, key_epoch);
            kv.set(session_dtls_seq, dtls_record_seq);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            pos = recpos;
        }
    }
    return ret;
}

return_t tls_record::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return not_supported; }

return_t tls_record::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        if (apply_protection() && session->get_session_info(dir).apply_protection()) {
            binary_t additional;
            binary_t ciphertext;
            binary_t tag;

            auto& protection = session->get_tls_protection();
            auto record_version = protection.get_lagacy_version();
            auto tagsize = protection.get_tag_size();
            auto tlsversion = protection.get_tls_version();
            auto cs = protection.get_cipher_suite();
            crypto_advisor* advisor = crypto_advisor::get_instance();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            const tls_cipher_suite_t* hint = tlsadvisor->hintof_cipher_suite(cs);
            if (nullptr == hint) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            auto hint_cipher = advisor->hintof_blockcipher(hint->cipher);
            if (nullptr == hint_cipher) {
                ret = errorcode_t::not_supported;
                __leave2;
            }

            {
                bool etm = session->get_keyvalue().get(session_encrypt_then_mac);
                auto is_tls = is_kindof_tls(record_version);
                auto ivsize = sizeof_iv(hint_cipher);
                uint16 len = 0;
                if (cbc == hint->mode) {
                    if (etm) {
                        len = body.size() + tagsize;
                    } else {
                        len = body.size() + tagsize + ivsize;
                    }
                } else {
                    len = body.size() + tagsize;
                }

                /**
                 * AAD
                 *   CBC  uint8(type) || uint16(version)
                 *   AEAD uint8(type) || uint16(version) || uint16(len)
                 */
                payload pl;
                pl << new payload_member(uint8(get_type()), constexpr_content_type)                                         // tls, dtls
                   << new payload_member(uint16(record_version), true, constexpr_record_version)                            // tls, dtls
                   << new payload_member(uint16(get_key_epoch()), true, constexpr_dtls_epoch, constexpr_group_dtls)         // dtls
                   << new payload_member(uint48_t(get_dtls_record_seq()), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
                   << new payload_member(uint16(len), true, constexpr_len);

                pl.set_group(constexpr_group_dtls, false == is_tls);
                pl.write(additional);
            }

            if (cbc == hint->mode) {
                // nested tag
                ret = protection.encrypt(session, dir, body, ciphertext, additional, tag);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            } else {
                // concatenated tag
                ret = protection.encrypt(session, dir, body, ciphertext, additional, tag);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                binary_append(ciphertext, tag);
            }

            // content header + ciphertext
            do_write_header_internal(dir, bin, ciphertext);
        } else {
            do_write_header_internal(dir, bin, body);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_record::do_write_header_internal(tls_direction_t dir, binary_t& bin, const binary_t& body) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 record_version = get_legacy_version();
        auto is_tls = is_kindof_tls(record_version);

        {
            _range.begin = bin.size();
            _bodysize = body.size();
        }

        {
            payload pl;
            pl << new payload_member(uint8(get_type()), constexpr_content_type)                                         // tls, dtls
               << new payload_member(uint16(record_version), true, constexpr_record_version)                            // tls, dtls
               << new payload_member(uint16(get_key_epoch()), true, constexpr_dtls_epoch, constexpr_group_dtls)         // dtls
               << new payload_member(uint48_t(get_dtls_record_seq()), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(body.size()), true, constexpr_len);                                         // tls, dtls

            pl.set_group(constexpr_group_dtls, is_kindof_dtls(record_version));
            pl.write(bin);
        }

        _range.end = bin.size();

        binary_append(bin, body);
    }
    __finally2 {}
    return ret;
}

return_t tls_record::do_write_body(tls_direction_t dir, binary_t& bin) { return errorcode_t::success; }

bool tls_record::apply_protection() { return false; }

tls_session* tls_record::get_session() { return _session; }

tls_content_type_t tls_record::get_type() { return (tls_content_type_t)_content_type; }

uint16 tls_record::get_legacy_version() {
    uint16 version = 0;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    version = protection.get_lagacy_version();
    return version;
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

uint16 tls_record::get_key_epoch() { return _dtls_epoch; }

uint64 tls_record::get_dtls_record_seq() { return _dtls_record_seq; }

uint16 tls_record::get_body_size() { return _bodysize; }

const range_t& tls_record::get_header_range() { return _range; }

size_t tls_record::offsetof_header() { return _range.begin; }

size_t tls_record::offsetof_body() { return _range.end; }

void tls_record::operator<<(tls_record* record) {
    if (record) {
        record->release();
    }
}

void tls_record::operator<<(tls_handshake* handshake) {
    if (handshake) {
        handshake->release();
    }
}

void tls_record::addref() { _shared.addref(); }

void tls_record::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
