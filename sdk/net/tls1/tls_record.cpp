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
#include <sdk/crypto/crypto/crypto_encrypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Record

return_t tls_dump_tls_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
return_t tls_dump_dtls13_ciphertext(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);

return_t tls_dump_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint8 b = stream[pos];
        if (0x20 & b) {
            // DTLS 1.3 Ciphertext
            ret = tls_dump_dtls13_ciphertext(s, session, stream, size, pos, role);
        } else {
            // TLS 1.2~, DTLS 1.3 Plaintext
            ret = tls_dump_tls_record(s, session, stream, size, pos, role);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_tls_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((size < pos) || (size - pos < 5)) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        size_t recpos = pos;
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        constexpr char constexpr_content_type[] = "content type";
        constexpr char constexpr_legacy_version[] = "legacy record version";
        constexpr char constexpr_len[] = "len";
        constexpr char constexpr_application_data[] = "application data";

        constexpr char constexpr_group_dtls[] = "dtls";
        constexpr char constexpr_key_epoch[] = "key epoch";
        constexpr char constexpr_dtls_record_seq[] = "dtls record sequence number";

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

            auto lambda_check_dtls = [&](payload_member* item) -> bool {
                auto ver = t_to_int<uint16>(item);
                return (ver >= dtls_13);
            };
            pl.set_group_condition(constexpr_group_dtls, constexpr_legacy_version, lambda_check_dtls);
            pl.select(constexpr_dtls_record_seq)->reserve(6);
            pl.read(stream, size, pos);

            content_type = t_to_int<uint8>(pl.select(constexpr_content_type));
            legacy_version = t_to_int<uint16>(pl.select(constexpr_legacy_version));
            len = t_to_int<uint16>(pl.select(constexpr_len));
            cond_dtls = pl.get_group_condition(constexpr_group_dtls);
            if (cond_dtls) {
                key_epoch = t_to_int<uint16>(pl.select(constexpr_key_epoch));
                pl.select(constexpr_dtls_record_seq)->get_variant().to_binary(dtls_record_seq);
            }
        }

        if (size - pos < len) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        {
            auto& protection = session->get_tls_protection();
            protection.set_record_version(legacy_version);
        }

        {
            s->printf("# TLS Record\n");
            dump_memory(stream + recpos, (pos - recpos) + len, s, 16, 3, 0x00, dump_notrunc);
            s->printf("\n");
            s->printf("> content type 0x%02x(%i) (%s)\n", content_type, content_type, tlsadvisor->content_type_string(content_type).c_str());
            s->printf("> %s 0x%04x (%s)\n", constexpr_legacy_version, legacy_version, tlsadvisor->tls_version_string(legacy_version).c_str());
            if (cond_dtls) {
                s->printf("> %s 0x%04x\n", constexpr_key_epoch, key_epoch);
                s->printf("> %s %s\n", constexpr_dtls_record_seq, base16_encode(dtls_record_seq).c_str());
                // dump_memory(dtls_record_seq, s, 16, 3, 0x0, dump_notrunc);
                // s->printf("\n");
            }
            s->printf("> %s 0x%04x(%i)\n", constexpr_len, len, len);
        }

        size_t tpos = 0;
        switch (content_type) {
            case tls_content_type_invalid: {
            } break;
            case tls_content_type_change_cipher_spec: {
                // RFC 5246 7.1.  Change Cipher Spec Protocol
                // RFC 4346 7.1. Change Cipher Spec Protocol
                // struct {
                //     enum { change_cipher_spec(1), (255) } type;
                // } ChangeCipherSpec;
                tpos = pos;
                ret = tls_dump_change_cipher_spec(s, session, stream, size, tpos);
                session->get_roleinfo(role).change_cipher_spec();
                session->reset_recordno(role);
            } break;
            case tls_content_type_alert: {
                // RFC 8446 6.  Alert Protocol
                // RFC 5246 7.2.  Alert Protocol
                auto roleinfo = session->get_roleinfo(role);
                if (roleinfo.doprotect()) {
                    tls_protection& protection = session->get_tls_protection();
                    binary_t plaintext;
                    binary_t tag;
                    auto tlsversion = protection.get_tls_version();
                    if (is_basedon_tls13(tlsversion)) {
                        ret = protection.decrypt_tls13(session, role, stream, len, recpos, plaintext, tag, s);
                    } else {
                        ret = protection.decrypt_tls1(session, role, stream, size, recpos, plaintext, s);
                    }
                    if (errorcode_t::success == ret) {
                        tpos = 0;
                        ret = tls_dump_alert(s, session, &plaintext[0], plaintext.size(), tpos);
                    }
                } else {
                    tpos = pos;
                    ret = tls_dump_alert(s, session, stream, size, tpos);
                }
            } break;
            case tls_content_type_handshake: {
                auto roleinfo = session->get_roleinfo(role);
                if (roleinfo.doprotect()) {
                    /**
                     * RFC 2246 6.2.3. Record payload protection
                     *     struct {
                     *         ContentType type;
                     *         ProtocolVersion version;
                     *         uint16 length;
                     *         select (CipherSpec.cipher_type) {
                     *             case stream: GenericStreamCipher;
                     *             case block: GenericBlockCipher;
                     *         } fragment;
                     *     } TLSCiphertext;
                     * RFC 2246 6.2.3.1. Null or standard stream cipher
                     *     stream-ciphered struct {
                     *         opaque content[TLSCompressed.length];
                     *         opaque MAC[CipherSpec.hash_size];
                     *     } GenericStreamCipher;
                     *     HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
                     *                   TLSCompressed.version + TLSCompressed.length +
                     *                   TLSCompressed.fragment));
                     * RFC 2246 6.2.3.2. CBC block cipher
                     *     block-ciphered struct {
                     *         opaque content[TLSCompressed.length];
                     *         opaque MAC[CipherSpec.hash_size];
                     *         uint8 padding[GenericBlockCipher.padding_length];
                     *         uint8 padding_length;
                     *     } GenericBlockCipher;
                     */
                    tls_protection& protection = session->get_tls_protection();
                    binary_t plaintext;
                    binary_t tag;
                    auto tlsversion = protection.get_tls_version();
                    if (is_basedon_tls13(tlsversion)) {
                        ret = protection.decrypt_tls13(session, role, stream, len, recpos, plaintext, tag, s);
                    } else {
                        ret = protection.decrypt_tls1(session, role, stream, size, recpos, plaintext, s);
                    }
                    if (errorcode_t::success == ret) {
                        tpos = 0;
                        ret = tls_dump_handshake(s, session, &plaintext[0], plaintext.size(), tpos, role);
                    }
                } else {
                    tpos = pos;
                    ret = tls_dump_handshake(s, session, stream, pos + len, tpos, role);
                }
            } break;
            case tls_content_type_application_data: {
                tls_protection& protection = session->get_tls_protection();
                binary_t plaintext;
                binary_t tag;
                auto tlsversion = protection.get_tls_version();
                if (is_basedon_tls13(tlsversion)) {
                    ret = protection.decrypt_tls13(session, role, stream, len, recpos, plaintext, tag, s);
                } else {
                    ret = protection.decrypt_tls1(session, role, stream, pos + len, recpos, plaintext, s);
                }
                if (errorcode_t::success == ret) {
                    auto plainsize = plaintext.size();
                    if (plainsize) {
                        auto tlsversion = protection.get_tls_version();
                        uint8 last_byte = *plaintext.rbegin();
                        if (is_basedon_tls13(tlsversion)) {
                            if (tls_content_type_alert == last_byte) {
                                ret = tls_dump_alert(s, session, &plaintext[0], plainsize - 1, tpos);
                            } else if (tls_content_type_handshake == last_byte) {
                                tpos = 0;
                                while (tpos < plainsize) {
                                    auto test = tls_dump_handshake(s, session, &plaintext[0], plainsize, tpos, role);
                                    if (errorcode_t::success != test) {
                                        if (errorcode_t::no_data != test) {
                                            ret = test;
                                        }
                                        break;
                                    }
                                }
                            } else if (tls_content_type_application_data == last_byte) {
                                s->autoindent(5);
                                s->printf("> %s\n", constexpr_application_data);
                                dump_memory(&plaintext[0], plainsize - 1, s, 16, 3, 0x0, dump_notrunc);
                                s->autoindent(0);
                                s->printf("\n");
                            }
                        } else {
                            crypto_advisor* advisor = crypto_advisor::get_instance();
                            const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
                            const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
                            auto dlen = hint_mac->digest_size;
                            size_t extra = last_byte + dlen + 1;
                            if (plaintext.size() > extra) {
                                s->autoindent(3);
                                s->printf(" > %s\n", constexpr_application_data);  // data
                                dump_memory(&plaintext[0], plaintext.size() - extra, s, 16, 3, 0x0, dump_notrunc);
                                s->autoindent(0);
                                s->printf("\n");
                            }
                        }
                    }
                }
            } break;
        }
        pos += len;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_dtls13_ciphertext(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
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

        pl.set_hook(constexpr_unified_header, [&](payload* pl, payload_member* item) -> void {
            auto uhdr = t_to_int<uint8>(item);
            pl->set_group(constexpr_group_c, (0x10 & uhdr));
            pl->set_group(constexpr_group_s16, 0 != (0x08 & uhdr));
            pl->set_group(constexpr_group_s8, 0 == (0x08 & uhdr));
            pl->set_group(constexpr_group_l, (0x04 & uhdr));
            if (0x04 & uhdr) {
                pl->set_reference_value(constexpr_encdata, constexpr_len);
            }
        });
        pl.read(stream, size, pos);

        uhdr = t_to_int<uint8>(pl.select(constexpr_unified_header));
        if (pl.get_group_condition(constexpr_group_c)) {
            pl.select(constexpr_connection_id)->get_variant().to_binary(connection_id);
        }
        if (pl.get_group_condition(constexpr_group_s16)) {
            sequence = t_to_int<uint16>(pl.select(constexpr_sequence16));
            sequence_len = 2;
            offset_sequence = pl.offset_of(constexpr_group_s16);
        }
        if (pl.get_group_condition(constexpr_group_s8)) {
            sequence = t_to_int<uint16>(pl.select(constexpr_sequence8));
            sequence_len = 1;
            offset_sequence = pl.offset_of(constexpr_group_s8);
        }
        if (pl.get_group_condition(constexpr_group_l)) {
            len = t_to_int<uint16>(pl.select(constexpr_len));
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
        s->printf("\n");
    }

    uint16 rec_enc = 0;
    binary_t ciphertext;
    tls_secret_t sn_key;
    auto& protection = session->get_tls_protection();
    auto hsstatus = session->get_roleinfo(role).get_status();
    {
        cipher_encrypt_builder builder;
        auto cipher = builder.set(aes128, ecb).build();
        size_t blocksize = 16;  // minimal block
        if (cipher) {
            if (role_server == role) {
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
        s->printf("\n");
    }

    binary_t plaintext;
    binary_t tag;
    {
        // decryption
        ret = protection.decrypt_tls13(session, role, stream, size - aad.size(), recpos, plaintext, aad, tag, s);
    }

    {
        s->printf("> aad\n");
        dump_memory(aad, s, 16, 3, 0x0, dump_notrunc);
        s->printf("\n");
        s->printf("> plaintext\n");
        dump_memory(plaintext, s, 16, 3, 0x0, dump_notrunc);
        s->printf("\n");
    }

    // record
    if (errorcode_t::success == ret) {
        uint8 hstype = *plaintext.rbegin();
        size_t tpos = 0;

        switch (hstype) {
            case tls_content_type_alert: {
                ret = tls_dump_alert(s, session, &plaintext[0], plaintext.size(), tpos);
            } break;
            case tls_content_type_handshake: {
                ret = tls_dump_handshake(s, session, &plaintext[0], plaintext.size(), tpos, role);
            } break;
            case tls_content_type_application_data: {
                s->printf("> application data\n");
                dump_memory(&plaintext[0], plaintext.size() - 1, s, 16, 3, 0x0, dump_notrunc);
                s->printf("\n");
            } break;
            case tls_content_type_ack: {
                ret = tls_dump_ack(s, session, &plaintext[0], plaintext.size(), tpos, role);
            } break;
        }
    }

    return ret;
}

}  // namespace net
}  // namespace hotplace
