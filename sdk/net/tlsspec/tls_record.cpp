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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tlsspec/tls.hpp>
#include <sdk/net/tlsspec/tls_advisor.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Record

return_t tls_dump_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
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
        constexpr char constexpr_record_version[] = "legacy record version";
        constexpr char constexpr_len[] = "len";
        constexpr char constexpr_application_data[] = "application data";

        payload pl;
        pl << new payload_member(uint8(0), constexpr_content_type) << new payload_member(uint16(0), true, constexpr_record_version)
           << new payload_member(uint16(0), true, constexpr_len);
        pl.read(stream, size, pos);  // tls_content_t

        auto content_type = t_to_int<uint8>(pl.select(constexpr_content_type));
        auto protocol_version = t_to_int<uint16>(pl.select(constexpr_record_version));
        auto len = t_to_int<uint16>(pl.select(constexpr_len));

        s->printf("# TLS Record\n");
        dump_memory(stream + recpos, sizeof(tls_content_t) + len, s, 16, 3, 0x00, dump_notrunc);
        s->printf("\n");
        s->printf("> content type 0x%02x(%i) (%s)\n", content_type, content_type, tlsadvisor->content_type_string(content_type).c_str());
        s->printf("> %s 0x%04x (%s)\n", constexpr_record_version, protocol_version, tlsadvisor->tls_version_string(protocol_version).c_str());
        s->printf("> %s 0x%04x(%i)\n", constexpr_len, len, len);

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
                    if (tls_13 == tlsversion) {
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
                    if (tls_13 == tlsversion) {
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
                if (tls_13 == tlsversion) {
                    ret = protection.decrypt_tls13(session, role, stream, len, recpos, plaintext, tag, s);  // pos = aadlen
                } else {
                    ret = protection.decrypt_tls1(session, role, stream, pos + len, recpos, plaintext, s);
                }
                if (errorcode_t::success == ret) {
                    auto plainsize = plaintext.size();
                    if (plainsize) {
                        auto tlsversion = protection.get_tls_version();
                        uint8 last_byte = *plaintext.rbegin();
                        if (tls_13 == tlsversion) {
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

}  // namespace net
}  // namespace hotplace
