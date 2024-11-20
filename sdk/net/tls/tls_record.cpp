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
#include <sdk/net/tls/tlsspec.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Record

return_t tls_dump_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size < 5) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        tls_advisor* resource = tls_advisor::get_instance();

        constexpr char constexpr_content_type[] = "content type";
        constexpr char constexpr_record_version[] = "legacy record version";
        constexpr char constexpr_len[] = "len";

        payload pl;
        pl << new payload_member(uint8(0), constexpr_content_type) << new payload_member(uint16(0), true, constexpr_record_version)
           << new payload_member(uint16(0), true, constexpr_len);
        pl.read(stream, size, pos);

        auto content_type = t_to_int<uint8>(pl.select(constexpr_content_type));
        auto protocol_version = t_to_int<uint16>(pl.select(constexpr_record_version));
        auto len = t_to_int<uint16>(pl.select(constexpr_len));

        s->autoindent(2);
        s->printf("# TLS Record\n");
        s->printf("> content type %i (%s)\n", content_type, resource->content_type_string(content_type).c_str());
        s->printf("> %s 0x%02x (%s)\n", constexpr_record_version, protocol_version, resource->tls_version_string(protocol_version).c_str());
        s->autoindent(0);
        s->printf("> %s 0x%04x(%i)\n", constexpr_len, len, len);

        size_t tpos = 0;
        switch (content_type) {
            case tls_content_type_invalid: {
            } break;
            case tls_content_type_change_cipher_spec: {
                ret = tls_dump_change_cipher_spec(s, session, stream + pos, size - pos, tpos);  // TODO
                pos += len;
            } break;
            case tls_content_type_alert: {
                ret = tls_dump_alert(s, session, stream + pos, size - pos, tpos);  // TODO
                pos += len;
            } break;
            case tls_content_type_handshake: {
                ret = tls_dump_handshake(s, session, stream + pos, size - pos, tpos);
            } break;
            case tls_content_type_application_data: {
                // ret = tls_dump_application_data(s, session, stream + pos, size - pos, tpos);  // TODO

                tls_advisor* advisor = tls_advisor::get_instance();

                uint16 cipher_suite = session->get_cipher_suite();
                tls_handshake_key& handshake_key = session->get_handshake_key();
                const tls_alg_info_t* hint = advisor->hintof_tls_algorithm(cipher_suite);
                auto tagsize = hint->tagsize;

                binary_t decrypted;
                binary_t aad;
                binary_t tag;

                binary_append(aad, stream, pos);
                binary_append(tag, stream + pos + len - tagsize, tagsize);
                auto const& key = handshake_key.get_item(tls_secret_server_handshake_key);
                auto const& iv = handshake_key.get_item(tls_secret_server_handshake_iv);

                crypt_context_t* handle = nullptr;
                openssl_crypt crypt;
                ret = crypt.open(&handle, hint->cipher, hint->mode, key, iv);
                if (errorcode_t::success == ret) {
                    ret = crypt.decrypt2(handle, stream + pos, len - tagsize, decrypted, &aad, &tag);
                    crypt.close(handle);
                }

                pos += len;

                s->autoindent(3);
                s->printf(" > key %s\n", base16_encode(key).c_str());
                s->printf(" > iv %s\n", base16_encode(iv).c_str());
                s->printf(" > aad %s\n", base16_encode(aad).c_str());
                s->printf(" > tag %s\n", base16_encode(tag).c_str());
                s->printf(" > decrypted\n");  // RFC 8446 4.3.1.  Encrypted Extensions
                dump_memory(decrypted, s, 16, 3, 0x0, dump_notrunc);
                s->autoindent(0);
                s->printf("\n");
            } break;
        }
        pos += tpos;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
