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
#include <sdk/crypto/basic/cipher_encrypt.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_group_c[] = "group c";       // connection id
constexpr char constexpr_group_s16[] = "group s 16";  // sequence
constexpr char constexpr_group_s8[] = "group s 8";    // sequence
constexpr char constexpr_group_l[] = "group l";       // length
constexpr char constexpr_group_e[] = "group e";       // epoch

constexpr char constexpr_unified_header[] = "unified header";
constexpr char constexpr_connection_id[] = "connection id";
constexpr char constexpr_sequence16[] = "sequence 16";
constexpr char constexpr_sequence8[] = "sequence 8";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_encdata[] = "enc data + tag";
constexpr char constexpr_sequence[] = "sequence";
constexpr char constexpr_recno[] = "record no";

dtls13_ciphertext::dtls13_ciphertext(uint8 type, tls_session* session) : tls_record(type, session), _sequence(0), _sequence_len(0), _offset_encdata(0) {}

dtls13_ciphertext::~dtls13_ciphertext() {}

tls_handshakes& dtls13_ciphertext::get_handshakes() { return _handshakes; }

tls_records& dtls13_ciphertext::get_records() { return _records; }

return_t dtls13_ciphertext::do_read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        size_t recpos = pos;

        uint8 uhdr = 0;
        binary_t connection_id;
        uint16 sequence = 0;
        uint8 sequence_len = 0;
        size_t offset_sequence = 0;
        uint16 len = 0;
        binary_t encdata;
        size_t offset_encdata = 0;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_unified_header)                          //
               << new payload_member(binary_t(), constexpr_connection_id, constexpr_group_c)      // cid    C:1
               << new payload_member(uint16(0), true, constexpr_sequence16, constexpr_group_s16)  // seq 16 S:1
               << new payload_member(uint8(0), constexpr_sequence8, constexpr_group_s8)           // seq 8  S:0
               << new payload_member(uint16(0), true, constexpr_len, constexpr_group_l)           // len    L:1
               << new payload_member(binary_t(), constexpr_encdata);

            /**
             * 0 1 2 3 4 5 6 7
             * +-+-+-+-+-+-+-+-+
             * |0|0|1|C|S|L|E E|
             * +-+-+-+-+-+-+-+-+
             */

            auto lambda_condition = [&](payload* pl, payload_member* item) -> void {
                auto uhdr = pl->t_value_of<uint8>(item);
                pl->set_group(constexpr_group_c, (0x10 & uhdr));
                pl->set_group(constexpr_group_s16, 0 != (0x08 & uhdr));
                pl->set_group(constexpr_group_s8, 0 == (0x08 & uhdr));
                pl->set_group(constexpr_group_l, (0x04 & uhdr));
                if (0x04 & uhdr) {
                    pl->set_reference_value(constexpr_encdata, constexpr_len);
                }
            };
            pl.set_condition(constexpr_unified_header, lambda_condition);
            pl.read(stream, size, pos);

            uhdr = pl.t_value_of<uint8>(constexpr_unified_header);
            if (pl.get_group_condition(constexpr_group_c)) {
                pl.get_binary(constexpr_connection_id, connection_id);
            }
            if (pl.get_group_condition(constexpr_group_s16)) {
                sequence = pl.t_value_of<uint16>(constexpr_sequence16);
                sequence_len = 2;
                offset_sequence = pl.offset_of(constexpr_group_s16);
            }
            if (pl.get_group_condition(constexpr_group_s8)) {
                sequence = pl.t_value_of<uint16>(constexpr_sequence8);
                sequence_len = 1;
                offset_sequence = pl.offset_of(constexpr_group_s8);
            }
            if (pl.get_group_condition(constexpr_group_l)) {
                len = pl.t_value_of<uint16>(constexpr_len);
            }
            pl.get_binary(constexpr_encdata, encdata);
            offset_encdata = pl.offset_of(constexpr_encdata);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> %s", constexpr_unified_header);
            dbs.println(" > 0x%02x (C:%i S:%i L:%i E:%x)", uhdr, (uhdr & 0x10) ? 1 : 0, (uhdr & 0x08) ? 1 : 0, (uhdr & 0x04) ? 1 : 0, (uhdr & 0x03));
            if (connection_id.size()) {
                dbs.println(" > %s %s", constexpr_connection_id, base16_encode(connection_id).c_str());
            }

            dbs.println(" > %s %04x", constexpr_sequence, sequence);
            dbs.println(" > %s %04x", constexpr_len, len);
            dbs.println(" > %s", constexpr_encdata);
            if (check_trace_level(loglevel_debug)) {
                dump_memory(encdata, &dbs, 16, 3, 0x0, dump_notrunc);
            }

            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif

        {
            _content_type = uhdr;
            _bodysize = len;

            _range.begin = recpos;
            _range.end = pos;

            _sequence = sequence;
            _sequence_len = sequence_len;
            _offset_encdata = offset_encdata;
        }
    }
    __finally2 {}
    return ret;
}

return_t dtls13_ciphertext::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto sess_recno = session->get_recordno(dir, false);

        auto recpos = offsetof_header();
        auto sequence = _sequence;
        auto sequence_len = _sequence_len;
        auto offset_encdata = _offset_encdata;

        uint16 recno = 0;
        uint16 rec_enc = 0;
        binary_t protmask;

        ret = protection.protection_mask(session, dir, stream + offset_encdata, size - offset_encdata, protmask, 2);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // recno
        if (2 == sequence_len) {
            rec_enc = t_binary_to_integer<uint16>(protmask);
        } else {
            rec_enc = t_binary_to_integer<uint8>(protmask);
        }
        recno = sequence ^ rec_enc;

        if (recno != sess_recno) {
            ret = errorcode_t::mismatch;
            __leave2;
        }

        binary_t additional;
        {
            binary_append(additional, stream + recpos, offset_encdata);
            for (auto i = 0; i < sequence_len; i++) {
                additional[1 + i] ^= protmask[i];
            }
        }

        binary_t plaintext;
        {
            // decryption
            ret = protection.decrypt(session, dir, stream, size, recpos, plaintext, additional);
        }

#if defined DEBUG
        if (istraceable(trace_category_net, loglevel_debug)) {
            basic_stream dbs;

            dbs.println("> rec_enc %04x", rec_enc);
            if (2 == sequence_len) {
                dbs.println("> %s %04x (%04x XOR %s)", constexpr_recno, recno, sequence, base16_encode(protmask).substr(0, sequence_len << 1).c_str());
            } else if (1 == sequence_len) {
                dbs.println("> %s %02x (%02x XOR %s)", constexpr_recno, recno, sequence, base16_encode(protmask).substr(0, sequence_len << 1).c_str());
            }

            dbs.println("> protmask");
            dump_memory(protmask, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.println("> additional");
            dump_memory(additional, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.println("> %s %04x", constexpr_recno, recno);
            dbs.println("> plaintext");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);

            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif

        // record
        if (errorcode_t::success == ret) {
            uint8 type = *plaintext.rbegin();
            size_t tpos = 0;

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                basic_stream dbs;

                dbs.println("> content type 0x%02x(%i) %s", type, type, tlsadvisor->content_type_string(type).c_str());

                if (check_trace_level(loglevel_debug)) {
                    switch (type) {
                        case tls_content_type_application_data: {
                            dump_memory(&plaintext[0], plaintext.size() - 1, &dbs, 16, 3, 0x0, dump_notrunc);
                        } break;
                    }
                }

                trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
            }
#endif

            switch (type) {
                case tls_content_type_alert: {
                    tls_record_alert alert(session);
                    ret = alert.read_plaintext(dir, &plaintext[0], plaintext.size() - 1, tpos);
                } break;
                case tls_content_type_handshake: {
                    auto handshake = tls_handshake::read(session, dir, &plaintext[0], plaintext.size() - 1, tpos);
                    get_handshakes().add(handshake);
                } break;
                case tls_content_type_application_data: {
                } break;
                case tls_content_type_ack: {
                    tls_record_ack ack(session);
                    ret = ack.do_read_body(dir, &plaintext[0], plaintext.size() - 1, tpos);
                } break;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t dtls13_ciphertext::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto sess_recno = session->get_recordno(dir, false);
        uint8 cap = byte_capacity(sess_recno);
        if (cap > 2) {
            ret = errorcode_t::exceed;
            __leave2;
        }

        size_t recpos = bin.size();
        /**
         * 0 1 2 3 4 5 6 7
         * +-+-+-+-+-+-+-+-+
         * |0|0|1|C|S|L|E E|
         * +-+-+-+-+-+-+-+-+
         */
        binary_t ciphertext;
        binary_t header;
        binary_t tag;
        uint8 uhdr = 0x20;
        uint8 c = (_cid.empty()) ? 0x00 : 0x01;
        uint8 s = (1 == cap) ? 0x00 : 0x08;
        uint8 l = (body.empty()) ? 0x00 : 0x04;
        uint8 e = 0x03;
        uhdr |= (c | s | l | e);
        uint8 sequence_len = s ? 2 : 1;
        uint8 tagsize = protection.get_tag_size();

        binary_t cid;

        {
            payload pl;
            pl << new payload_member(uhdr, constexpr_unified_header)                                          //
               << new payload_member(_cid, constexpr_connection_id, constexpr_group_c)                        // cid    C:1
               << new payload_member(uint16(sess_recno), true, constexpr_sequence16, constexpr_group_s16)     // seq 16 S:1
               << new payload_member(uint8(sess_recno), constexpr_sequence8, constexpr_group_s8)              // seq 8  S:0
               << new payload_member(uint16(body.size() + tagsize), true, constexpr_len, constexpr_group_l);  // len    L:1
            pl.set_group(constexpr_group_c, (0x10 & uhdr));
            pl.set_group(constexpr_group_s16, 0 != (0x08 & uhdr));
            pl.set_group(constexpr_group_s8, 0 == (0x08 & uhdr));
            pl.set_group(constexpr_group_l, (0x04 & uhdr));
            pl.write(header);
        }

        {
            _content_type = uhdr;
            _bodysize = body.size();
            _range.begin = recpos;
            _range.end = header.size();
            _sequence = sess_recno;
            _sequence_len = sequence_len;
            _offset_encdata = header.size();
        }

        {
            ret = protection.encrypt(session, dir, body, ciphertext, header, tag);
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        binary_t block;
        {
            binary_append(block, ciphertext);
            binary_append(block, tag);
        }

        uint16 recno = 0;
        uint16 rec_enc = 0;
        binary_t protmask;
        ret = protection.protection_mask(session, dir, &block[0], block.size(), protmask, 2);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (2 == sequence_len) {
            rec_enc = t_binary_to_integer<uint16>(protmask);
        } else {
            rec_enc = t_binary_to_integer<uint8>(protmask);
        }
        recno = sess_recno ^ rec_enc;

        {
            payload pl;
            pl << new payload_member(uhdr, constexpr_unified_header)                                  //
               << new payload_member(_cid, constexpr_connection_id, constexpr_group_c)                // cid    C:1
               << new payload_member(uint16(recno), true, constexpr_sequence16, constexpr_group_s16)  // seq 16 S:1
               << new payload_member(uint8(recno), constexpr_sequence8, constexpr_group_s8)           // seq 8  S:0
               << new payload_member(uint16(block.size()), true, constexpr_len, constexpr_group_l);   // len    L:1
            pl.set_group(constexpr_group_c, (0x10 & uhdr));
            pl.set_group(constexpr_group_s16, 0 != (0x08 & uhdr));
            pl.set_group(constexpr_group_s8, 0 == (0x08 & uhdr));
            pl.set_group(constexpr_group_l, (0x04 & uhdr));
            pl.write(bin);

            binary_append(bin, block);
        }

#if defined DEBUG
        if (istraceable(trace_category_net, loglevel_debug)) {
            basic_stream dbs;

            dbs.println("> header");
            dump_memory(header, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.println("> header masked (sequence)");
            dump_memory(&bin[0], header.size(), &dbs, 16, 3, 0x0, dump_notrunc);

            trace_debug_event(trace_category_net, trace_event_tls_record, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t dtls13_ciphertext::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto& handshakes = get_handshakes();
    auto& records = get_records();
    if (handshakes.size()) {
        handshakes.write(get_session(), dir, bin);
        binary_append(bin, uint8(get_type()));
    } else if (records.size()) {
        auto lambda = [&](tls_record* record) -> return_t {
            ret = record->do_write_body(dir, bin);
            if (errorcode_t::success == ret) {
                binary_append(bin, uint8(record->get_type()));
            }
            return ret;
        };
        ret = records.for_each(lambda);
    }
    return ret;
}

void dtls13_ciphertext::operator<<(tls_record* record) { get_records().add(record); }

void dtls13_ciphertext::operator<<(tls_handshake* handshake) { get_handshakes().add(handshake); }

tls_record& dtls13_ciphertext::add(tls_content_type_t type, tls_session* session, std::function<return_t(tls_record*)> func, bool upref) {
    get_records().add(type, session, func, upref);
    return *this;
}

tls_record& dtls13_ciphertext::add(tls_hs_type_t type, tls_session* session, std::function<return_t(tls_handshake*)> func, bool upref) {
    get_handshakes().add(type, session, func, upref);
    return *this;
}

}  // namespace net
}  // namespace hotplace
