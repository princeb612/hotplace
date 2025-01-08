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
#include <sdk/crypto/crypto/cipher_encrypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_record.hpp>

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

return_t dtls13_ciphertext::read_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
               << new payload_member(binary_t(), constexpr_connection_id, constexpr_group_c)      // cid
               << new payload_member(uint16(0), true, constexpr_sequence16, constexpr_group_s16)  // seq 16
               << new payload_member(uint8(0), constexpr_sequence8, constexpr_group_s8)           // seq 8
               << new payload_member(uint16(0), true, constexpr_len, constexpr_group_l)           // l
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
                pl.select(constexpr_connection_id)->get_variant().to_binary(connection_id);
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
            pl.select(constexpr_encdata)->get_variant().to_binary(encdata);
            offset_encdata = pl.offset_of(constexpr_encdata);
        }

        if (debugstream) {
            debugstream->printf("> %s %02x (C:%i S:%i L:%i E:%x)\n", constexpr_unified_header, uhdr, (uhdr & 0x10) ? 1 : 0, (uhdr & 0x08) ? 1 : 0,
                                (uhdr & 0x04) ? 1 : 0, (uhdr & 0x03));
            if (connection_id.size()) {
                debugstream->printf("> %s %s\n", constexpr_connection_id, base16_encode(connection_id).c_str());
            }
            debugstream->printf("> %s %04x\n", constexpr_sequence, sequence);
            debugstream->printf("> %s %04x\n", constexpr_len, len);
            debugstream->printf("> %s\n", constexpr_encdata);
            dump_memory(encdata, debugstream, 16, 3, 0x0, dump_notrunc);
        }

        {
            _content_type = uhdr;
            _len = len;

            _range.begin = recpos;
            _range.end = pos;

            _sequence = sequence;
            _sequence_len = sequence_len;
            _offset_encdata = offset_encdata;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls13_ciphertext::read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto recpos = get_header_range().begin;
        auto sequence = _sequence;
        auto sequence_len = _sequence_len;
        auto offset_encdata = _offset_encdata;

        {
            uint16 recno = 0;
            uint16 rec_enc = 0;
            binary_t ciphertext;
            tls_secret_t sn_key;
            auto session = get_session();
            auto& protection = session->get_tls_protection();
            auto hsstatus = session->get_session_info(dir).get_status();
            {
                cipher_encrypt_builder builder;
                auto cipher = builder.set(aes128, ecb).build();
                size_t blocksize = 16;  // minimal block
                if (cipher) {
                    if (from_server == dir) {
                        if (tls_hs_finished == hsstatus) {
                            sn_key = tls_secret_application_server_sn_key;
                        } else {
                            sn_key = tls_secret_handshake_server_sn_key;
                        }
                    } else {
                        if (tls_hs_finished == hsstatus) {
                            sn_key = tls_secret_application_client_sn_key;
                        } else {
                            sn_key = tls_secret_handshake_client_sn_key;
                        }
                    }
                    cipher->encrypt(protection.get_item(sn_key), binary_t(), stream + offset_encdata, blocksize, ciphertext);
                    cipher->release();
                }

                // recno
                if (2 == sequence_len) {
                    rec_enc = t_binary_to_integer<uint16>(ciphertext);
                } else {
                    rec_enc = t_binary_to_integer<uint8>(ciphertext);
                }
                recno = sequence ^ rec_enc;
            }

            binary_t aad;
            {
                binary_append(aad, stream + recpos, offset_encdata);
                for (auto i = 0; i < sequence_len; i++) {
                    aad[1 + i] ^= ciphertext[i];
                }
            }

            if (debugstream) {
                debugstream->printf("> record number key %s\n", base16_encode(protection.get_item(sn_key)).c_str());

                // s->printf("> %s %04x\n", constexpr_recno, recno);
                debugstream->printf("> %s %04x (%04x XOR %s)\n", constexpr_recno, recno, sequence,
                                    base16_encode(ciphertext).substr(0, sequence_len << 1).c_str());
                dump_memory(ciphertext, debugstream, 16, 3, 0x0, dump_notrunc);
            }

            binary_t plaintext;
            binary_t tag;
            {
                // decryption
                ret = protection.decrypt_tls13(session, dir, stream, size - aad.size(), recpos, plaintext, aad, tag, debugstream);
            }

            if (debugstream) {
                debugstream->printf("> aad\n");
                dump_memory(aad, debugstream, 16, 3, 0x0, dump_notrunc);
                debugstream->printf("> plaintext\n");
                dump_memory(plaintext, debugstream, 16, 3, 0x0, dump_notrunc);
            }

            // record
            if (errorcode_t::success == ret) {
                uint8 hstype = *plaintext.rbegin();
                size_t tpos = 0;

                switch (hstype) {
                    case tls_content_type_alert: {
                        tls_record_alert alert(session);
                        ret = alert.read_plaintext(dir, &plaintext[0], plaintext.size() - 1, tpos, debugstream);
                    } break;
                    case tls_content_type_handshake: {
                        ret = tls_dump_handshake(session, &plaintext[0], plaintext.size() - 1, tpos, debugstream, dir);
                    } break;
                    case tls_content_type_application_data: {
                        if (debugstream) {
                            debugstream->printf("> application data\n");
                            dump_memory(&plaintext[0], plaintext.size() - 1, debugstream, 16, 3, 0x0, dump_notrunc);
                        }
                    } break;
                    case tls_content_type_ack: {
                        tls_record_ack ack(session);
                        ret = ack.read_data(dir, &plaintext[0], plaintext.size() - 1, tpos, debugstream);
                    } break;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t dtls13_ciphertext::write(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
