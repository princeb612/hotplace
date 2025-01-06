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

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/basic/template.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/crypto/cipher_encrypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_record.hpp>

namespace hotplace {
namespace net {

return_t tls_dump_tls_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir);
return_t tls_dump_dtls13_ciphertext(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir);

return_t tls_dump_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint8 b = stream[pos];
        if (TLS_CONTENT_TYPE_MASK_CIPHERTEXT & b) {
            // DTLS 1.3 Ciphertext
            ret = tls_dump_dtls13_ciphertext(s, session, stream, size, pos, dir);
        } else {
            // TLS 1.2~, DTLS 1.3 Plaintext
            ret = tls_dump_tls_record(s, session, stream, size, pos, dir);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_tls_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((size < pos) || (size - pos < 5)) {
            ret = errorcode_t::no_more;
            __leave2;
        }

        {
            uint8 content_type = stream[pos];
            tls_record_builder builder;
            auto record = builder.set(session).set(content_type).build();
            if (record) {
                ret = record->read(dir, stream, size, pos, s);
                record->release();
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_dtls13_ciphertext(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_direction_t dir) {
    return_t ret = errorcode_t::success;

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

    size_t recpos = pos;

    uint8 uhdr = 0;
    binary_t connection_id;
    uint16 sequence = 0;
    uint8 sequence_len = 0;
    size_t offset_sequence = 0;
    uint16 len = 0;
    binary_t encdata;
    size_t offset_encdata = 0;
    uint16 recno = 0;
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

    {
        s->printf("> %s %02x (C:%i S:%i L:%i E:%x)\n", constexpr_unified_header, uhdr, (uhdr & 0x10) ? 1 : 0, (uhdr & 0x08) ? 1 : 0, (uhdr & 0x04) ? 1 : 0,
                  (uhdr & 0x03));
        if (connection_id.size()) {
            s->printf("> %s %s\n", constexpr_connection_id, base16_encode(connection_id).c_str());
        }
        s->printf("> %s %04x\n", constexpr_sequence, sequence);
        s->printf("> %s %04x\n", constexpr_len, len);
        s->printf("> %s\n", constexpr_encdata);
        dump_memory(encdata, s, 16, 3, 0x0, dump_notrunc);
    }

    uint16 rec_enc = 0;
    binary_t ciphertext;
    tls_secret_t sn_key;
    auto& protection = session->get_tls_protection();
    auto hsstatus = session->get_session_info(dir).get_status();
    {
        cipher_encrypt_builder builder;
        auto cipher = builder.set(aes128, ecb).build();
        size_t blocksize = 16;  // minimal block
        if (cipher) {
            if (from_server == dir) {
                if (tls_handshake_finished == hsstatus) {
                    sn_key = tls_secret_application_server_sn_key;
                } else {
                    sn_key = tls_secret_handshake_server_sn_key;
                }
            } else {
                if (tls_handshake_finished == hsstatus) {
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

    {
        s->printf("> record number key %s\n", base16_encode(protection.get_item(sn_key)).c_str());

        // s->printf("> %s %04x\n", constexpr_recno, recno);
        s->printf("> %s %04x (%04x XOR %s)\n", constexpr_recno, recno, sequence, base16_encode(ciphertext).substr(0, sequence_len << 1).c_str());
        dump_memory(ciphertext, s, 16, 3, 0x0, dump_notrunc);
    }

    binary_t plaintext;
    binary_t tag;
    {
        // decryption
        ret = protection.decrypt_tls13(session, dir, stream, size - aad.size(), recpos, plaintext, aad, tag, s);
    }

    {
        s->printf("> aad\n");
        dump_memory(aad, s, 16, 3, 0x0, dump_notrunc);
        s->printf("> plaintext\n");
        dump_memory(plaintext, s, 16, 3, 0x0, dump_notrunc);
    }

    // record
    if (errorcode_t::success == ret) {
        uint8 hstype = *plaintext.rbegin();
        size_t tpos = 0;

        switch (hstype) {
            case tls_content_type_alert: {
                ret = tls_dump_alert(s, session, &plaintext[0], plaintext.size() - 1, tpos);
            } break;
            case tls_content_type_handshake: {
                ret = tls_dump_handshake(s, session, &plaintext[0], plaintext.size() - 1, tpos, dir);
            } break;
            case tls_content_type_application_data: {
                s->printf("> application data\n");
                dump_memory(&plaintext[0], plaintext.size() - 1, s, 16, 3, 0x0, dump_notrunc);
            } break;
            case tls_content_type_ack: {
                // ret = tls_dump_ack(s, session, &plaintext[0], plaintext.size() - 1, tpos, dir);
                tls_ack ack(session);
                ret = ack.read_data(dir, &plaintext[0], plaintext.size() - 1, tpos, s);
            } break;
        }
    }

    return ret;
}

}  // namespace net
}  // namespace hotplace
