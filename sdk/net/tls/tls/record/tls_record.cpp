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
#include <sdk/base/nostd/exception.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "record content type";
constexpr char constexpr_record_version[] = "record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_tls[] = "tls";
constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_dtls_epoch[] = "epoch";
constexpr char constexpr_dtls_record_seq[] = "sequence number";

tls_record::tls_record(uint8 type, tls_session* session)
    : _content_type(type), _cond_dtls(false), _dtls_epoch(0), _dtls_record_seq(0), _bodysize(0), _session(session), _flags(0) {
    if (session) {
        session->addref();
    } else {
        throw exception(errorcode_t::no_session);
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

        ret = do_preprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_read_header(dir, stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        size_t tpos = pos;
        ret = do_read_body(dir, stream, size, tpos);
        pos += get_body_size();

        do_postprocess(dir);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record::write(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    auto snapshot = bin.size();
    __try2 {
#if defined DEBUG
        if (istraceable(trace_category_net)) {
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
        ret = do_preprocess(dir);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        binary_t body;
        ret = do_write_body(dir, body);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto session_type = session->get_type();
        auto& protection = session->get_tls_protection();
        auto is_dtls = (session_type == session_type_dtls);

        if (is_dtls) {
            auto& kv = session->get_session_info(dir).get_keyvalue();
            if (dont_control_dtls_sequence & get_flags()) {
                // do nothing
            } else {
                _dtls_epoch = kv.get(session_dtls_epoch);
                _dtls_record_seq = kv.get(session_dtls_seq);
            }
        }

        ret = do_write_header(dir, bin, body);  // encryption

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            if (get_flags()) {
                dbs.printf("\e[0;36m");
            } else {
                dbs.printf("\e[1;36m");
            }
            dbs.println("# record constructed");
            dbs.printf("\e[0m");
            if (check_trace_level(loglevel_debug)) {
                size_t dpos = 0;
                size_t rsize = 0;
                size_t hsize = 0;
                if (is_dtls) {
                    rsize = RTL_FIELD_SIZE(tls_content_t, dtls);
                    hsize = sizeof(dtls_handshake_t);
                } else {
                    rsize = RTL_FIELD_SIZE(tls_content_t, tls);
                    hsize = sizeof(tls_handshake_t);
                }
                dump_memory(&bin[dpos], rsize, &dbs, 16, 3, 0, dump_notrunc);
                dpos += rsize;
                dump_memory(&bin[dpos], hsize, &dbs, 16, 3, 0, dump_notrunc);
                dpos += hsize;
                dump_memory(&bin[dpos], bin.size() - dpos, &dbs, 16, 3, 0, dump_notrunc);
            } else {
                dump_memory(bin, &dbs, 16, 3, 0, dump_notrunc);
            }
            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif

        do_postprocess(dir);  // change secret, recno

        if (is_dtls && (0 == (dont_control_dtls_sequence & get_flags()))) {
            change_epoch_seq(dir);
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            bin.resize(snapshot);  // rollback
#if 0
            tls_record_builder builder;
            auto lambda = [&](uint8 level, uint8 desc) -> void {
                auto record = builder.set(session).set(tls_content_type_alert).construct().build();
                if (record) {
                    tls_record_alert* alert_casted = (tls_record_alert*)record;
                    alert_casted->set(level, desc);
                    record->write(dir, bin);
                    record->release();
                }
            };
            session->get_alert(dir, lambda);
#endif
        }
    }
    return ret;
}

return_t tls_record::do_preprocess(tls_direction_t dir) { return errorcode_t::success; }

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

        auto session = get_session();
        size_t minsize = (session_type_dtls == session->get_type()) ? sizeof(dtls_header) : sizeof(tls_header);

        if ((size < pos) || (size - pos < minsize)) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

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
                pl->set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(ver));
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
        if (istraceable(trace_category_net)) {
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
            pos = recpos;  // rollback
        }
    }
    return ret;
}

return_t tls_record::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) { return not_supported; }

return_t tls_record::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();

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
            auto hint_cipher = tlsadvisor->hintof_blockcipher(cs);
            if (nullptr == hint_cipher) {
                ret = errorcode_t::not_supported;
                __leave2;
            }

            write_aad(session, dir, additional, body.size());

            bool is_cbc = tlsadvisor->is_kindof_cbc(cs);
            if (is_cbc) {
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
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        uint16 record_version = get_legacy_version();
        auto is_tls = tlsadvisor->is_kindof_tls(record_version);

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

            pl.set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(record_version));
            pl.write(bin);
        }

        _range.end = bin.size();

        binary_append(bin, body);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto const& range = get_header_range();

            dbs.println("# record %s", (from_server == dir) ? "(server)" : (from_client == dir) ? "(client)" : "");

            auto content_type = get_type();
            auto len = body.size();
            dbs.println("> %s 0x%02x(%i) (%s)", constexpr_content_type, content_type, content_type, tlsadvisor->content_type_string(content_type).c_str());
            dbs.println(" > %s 0x%04x (%s)", constexpr_record_version, record_version, tlsadvisor->tls_version_string(record_version).c_str());
            if (session_type_dtls == get_session()->get_type()) {
                if (dont_control_dtls_sequence & get_flags()) {
                } else {
                    uint16 key_epoch = get_key_epoch();
                    uint64 dtls_record_seq = get_dtls_record_seq();
                    dbs.println(" > %s 0x%04x", constexpr_dtls_epoch, key_epoch);
                    dbs.println(" > %s 0x%012I64x (%I64u)", constexpr_dtls_record_seq, dtls_record_seq, dtls_record_seq);
                }
            }
            dbs.println(" > %s 0x%04x(%i)", constexpr_len, len, len);

            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif
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

size_t tls_record::get_record_size() { return _range.width() + _bodysize; }

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

void tls_record::set_flags(uint32 flags) { _flags = flags; }

uint32 tls_record::get_flags() { return _flags; }

void tls_record::change_epoch_seq(tls_direction_t dir) {
    auto session = get_session();
    auto& kv = session->get_session_info(dir).get_keyvalue();
    if (tls_content_type_change_cipher_spec == get_type()) {
        kv.inc(session_dtls_epoch);
        kv.set(session_dtls_seq, 0);
    } else {
        kv.inc(session_dtls_seq);
    }
}

return_t tls_record::read_aad(tls_session* session, binary_t& aad, const binary_t& record_header, uint64 record_no) {
    return_t ret = errorcode_t::success;
    // see also tls_protection::build_tls12_aad_from_record
    return ret;
}

return_t tls_record::write_aad(tls_session* session, tls_direction_t dir, binary_t& aad, uint16 bodysize) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto& protection = session->get_tls_protection();

        auto content_type = get_type();
        auto record_version = protection.get_lagacy_version();
        auto tagsize = protection.get_tag_size();
        auto cs = protection.get_cipher_suite();
        auto hint_blockcipher = tlsadvisor->hintof_blockcipher(cs);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto ivsize = sizeof_iv(hint_blockcipher);
        auto hint_cipher = tlsadvisor->hintof_cipher(cs);
        auto mode = typeof_mode(hint_cipher);
        auto is_tls = protection.is_kindof_tls();
        auto is_tls12 = protection.is_kindof_tls12();
        auto is_cbc = false;
        bool etm = false;
        uint16 key_epoch = 0;
        uint64 dtls_record_seq = 0;
        uint16 len = 0;
        bool set_nonce_explicit = false;

        protection.clear_item(tls_context_nonce_explicit);

        if (is_tls12) {
            // TLS 1.2, DTLS 1.2
            is_cbc = tlsadvisor->is_kindof_cbc(cs);
            etm = session->get_keyvalue().get(session_encrypt_then_mac);
            if (is_cbc) {
                // CBC
                if (etm) {
                    // Encrypt-then-Mac
                    len = bodysize + tagsize;
                } else {
                    // Mac-then-Encrypt
                    len = bodysize + tagsize + ivsize;
                }
            } else if (ccm == mode || gcm == mode) {
                set_nonce_explicit = true;

                // CCM, GCM
                len = bodysize;

                // sketch ...
                // tls_context_nonce_explicit 12-octet
                openssl_prng prng;
                binary_t temp;
                prng.random(temp, 8);
                protection.set_item(tls_context_nonce_explicit, temp);
            } else if (mode_poly1305) {
                len = bodysize + tagsize;
            }
        } else {
            // TLS 1.3, DTLS 1.3
            len = bodysize + tagsize;
        }

        payload pl;
        if (set_nonce_explicit) {
            uint64 record_no = session->get_recordno(dir, false);
            ;
            pl << new payload_member(uint64(record_no), true, constexpr_dtls_epoch, constexpr_group_tls)          // tls
               << new payload_member(uint16(key_epoch), true, constexpr_dtls_epoch, constexpr_group_dtls)         // dtls
               << new payload_member(uint48_t(dtls_record_seq), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint8(content_type), constexpr_content_type)                                 // tls, dtls
               << new payload_member(uint16(record_version), true, constexpr_record_version)                      // tls, dtls
               << new payload_member(uint16(len), true, constexpr_len);                                           // tls, dtls

            pl.set_group(constexpr_group_tls, (true == is_tls));
            pl.set_group(constexpr_group_dtls, (false == is_tls));
        } else {
            /**
             * AAD
             *   CBC  uint8(type) || uint16(version)
             *   AEAD uint8(type) || uint16(version) || uint16(len)
             */
            pl << new payload_member(uint8(content_type), constexpr_content_type)                                 // tls, dtls
               << new payload_member(uint16(record_version), true, constexpr_record_version)                      // tls, dtls
               << new payload_member(uint16(key_epoch), true, constexpr_dtls_epoch, constexpr_group_dtls)         // dtls
               << new payload_member(uint48_t(dtls_record_seq), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(len), true, constexpr_len);                                           // tls, dtls

            pl.set_group(constexpr_group_dtls, false == is_tls);
        }

        pl.write(aad);
    }
    __finally2 {}

    return ret;
}

}  // namespace net
}  // namespace hotplace
