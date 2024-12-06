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
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tlsspec/tls.hpp>

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

        tls_advisor* resource = tls_advisor::get_instance();

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
        dump_memory(stream, size, s, 16, 3, 0x00, dump_notrunc);
        s->printf("\n");
        s->printf("> content type 0x%02x(%i) (%s)\n", content_type, content_type, resource->content_type_string(content_type).c_str());
        s->printf("> %s 0x%04x (%s)\n", constexpr_record_version, protocol_version, resource->tls_version_string(protocol_version).c_str());
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
            } break;
            case tls_content_type_alert: {
                // RFC 8446 6.  Alert Protocol
                // RFC 5246 7.2.  Alert Protocol
                tpos = pos;
                ret = tls_dump_alert(s, session, stream, size, tpos);
            } break;
            case tls_content_type_handshake: {
                tpos = pos;
                while (tpos < size) {
                    ret = tls_dump_handshake(s, session, stream, size, tpos);
                    if (errorcode_t::success != ret) {
                        break;
                    }
                }
            } break;
            case tls_content_type_application_data: {
                tls_protection& protection = session->get_tls_protection();
                binary_t plaintext;
                binary_t tag;
                ret = protection.decrypt(session, role, stream, len, plaintext, pos, tag, s);
                if (errorcode_t::success == ret) {
                    auto plainsize = plaintext.size();
                    if (plainsize) {
                        uint8 record_type = *plaintext.rbegin();
                        if (tls_content_type_alert == record_type) {
                            ret = tls_dump_alert(s, session, &plaintext[0], plainsize - 1, tpos);
                        } else if (tls_content_type_handshake == record_type) {
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
                        } else if (tls_content_type_application_data == record_type) {
                            s->autoindent(5);
                            s->printf("> %s\n", constexpr_application_data);
                            dump_memory(&plaintext[0], plainsize - 1, s, 16, 3, 0x0, dump_notrunc);
                            s->autoindent(0);
                            s->printf("\n");
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
