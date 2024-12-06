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

#include <sdk/base/basic/base16.hpp>
#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/basic/template.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/crypto/crypto_hash.hpp>
#include <sdk/crypto/crypto/crypto_mac.hpp>
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tlsspec/tls.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Handshake

static return_t tls_dump_client_hello(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_server_hello(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_new_session_ticket(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_encrypted_extensions(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_certificate(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_server_key_exchange(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
static return_t tls_dump_server_hello_done(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
static return_t tls_dump_certificate_verify(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_client_key_exchange(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
static return_t tls_dump_finished(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);

return_t tls_dump_handshake(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if ((size < pos) || (size - pos < 4)) {
            ret = errorcode_t::no_data;
            __leave2;
        }

        // RFC 8446
        //  5.1.  Record Layer
        //  5.2.  Record Payload Protection
        auto& protection = session->get_tls_protection();

        tls_handshake_t* handshake = (tls_handshake_t*)(stream + pos);
        uint32 length = 0;
        b24_i32(handshake->length, length);
        if (size < pos + sizeof(tls_handshake_t) + length) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        size_t hspos = pos;
        auto hstype = handshake->msg_type;
        tls_advisor* advisor = tls_advisor::get_instance();

        s->printf(" > handshake type %i(%02x) (%s)\n", hstype, hstype, advisor->handshake_type_string(hstype).c_str());
        s->printf(" > length 0x%04x(%i)\n", length, length);

        binary_t handshake_hash;
        auto lambda_do_transcript_hash = [&](tls_session* session, const byte_t* stream, size_t size, binary_t& digest) -> void {
            auto hash = protection.get_transcript_hash();
            if (hash) {
                hash->digest(stream, size, digest);
                // s->printf(" > transcript hash\n");
                // dump_memory(digest, s, 16, 3, 0x0, dump_notrunc);
                // s->printf("\n");
                hash->release();
            }
        };

        pos += sizeof(tls_handshake_t);

        switch (handshake->msg_type) {
            case tls_handshake_client_hello: /* 1 */ {
                ret = tls_dump_client_hello(hstype, s, session, stream, size, pos);
                // cipher_suite not selected yet
                // client_hello excluding 5-byte record headers
                protection.set_item(tls_context_client_hello, stream + hspos, size - hspos);  // temporary
            } break;
            case tls_handshake_server_hello: /* 2 */ {
                ret = tls_dump_server_hello(hstype, s, session, stream, size, pos);

                binary_t hello_hash;
                // hello_hash = hash(client_hello + server_hello)
                const binary_t& client_hello = protection.get_item(tls_context_client_hello);
                lambda_do_transcript_hash(session, &client_hello[0], client_hello.size(), handshake_hash);
                lambda_do_transcript_hash(session, stream + hspos, size - hspos, hello_hash);
                protection.calc(session, tls_context_server_hello);  // handshake related
                session->get_roleinfo(role).set_status(handshake->msg_type);
            } break;
            case tls_handshake_new_session_ticket: /* 4 */ {
                ret = tls_dump_new_session_ticket(s, session, stream, size, pos);
            } break;
            case tls_handshake_end_of_early_data: /* 5 */ {
                //
            } break;
            case tls_handshake_encrypted_extensions: /* 8 */ {
                // RFC 8446 4.3.1.  Encrypted Extensions
                // struct {
                //     Extension extensions<0..2^16-1>;
                // } EncryptedExtensions;
                ret = tls_dump_encrypted_extensions(s, session, stream, size, pos);

                lambda_do_transcript_hash(session, stream + hspos, sizeof(tls_handshake_t) + length, handshake_hash);
            } break;
            case tls_handshake_certificate: /* 11 */ {
                // RFC 4346 7.4.2. Server Certificate
                //  opaque ASN.1Cert<1..2^24-1>;
                //  struct {
                //      ASN.1Cert certificate_list<0..2^24-1>;
                //  } Certificate;
                // RFC 4346 7.4.3. Server Key Exchange Message
                // RFC 4346 7.4.6. Client certificate
                // RFC 4346 7.4.7. Client Key Exchange Message
                ret = tls_dump_certificate(s, session, stream, size, pos);

                lambda_do_transcript_hash(session, stream + hspos, sizeof(tls_handshake_t) + length, handshake_hash);
            } break;
            case tls_handshake_server_key_exchange: /* 12 */ {
                ret = tls_dump_server_key_exchange(s, session, stream, size, pos, role);
            } break;
            case tls_handshake_certificate_request: /* 13 */ {
                // RFC 4346 7.4.4. Certificate request
                // do something
                lambda_do_transcript_hash(session, stream + hspos, sizeof(tls_handshake_t) + length, handshake_hash);
            } break;
            case tls_handshake_server_hello_done: /* 14 */ {
                ret = tls_dump_server_hello_done(s, session, stream, size, pos, role);
            } break;
            case tls_handshake_certificate_verify: /* 15 */ {
                // RFC 4346 7.4.8. Certificate verify
                ret = tls_dump_certificate_verify(s, session, stream, size, pos);

                lambda_do_transcript_hash(session, stream + hspos, sizeof(tls_handshake_t) + length, handshake_hash);
            } break;
            case tls_handshake_client_key_exchange: /* 16 */ {
                ret = tls_dump_client_key_exchange(s, session, stream, size, pos, role);
            } break;
            case tls_handshake_finished: /* 20 */ {
                ret = tls_dump_finished(s, session, stream, size, pos, role);
                // excluding 1-byte wrapped record trailers
                lambda_do_transcript_hash(session, stream + hspos, sizeof(tls_handshake_t) + length, handshake_hash);

                if (role_server == role) {
                    protection.calc(session, tls_context_server_finished);  // application, exporter related
                } else {
                    protection.calc(session, tls_context_client_finished);  // resumption related
                }
                session->get_roleinfo(role).set_status(handshake->msg_type);
                session->handshake_finished();
            } break;
            case tls_handshake_key_update: /* 24 */ {
            } break;
            case tls_handshake_message_hash: /* 254 */ {
            } break;
            default: {
            } break;
        }

        size_t pos_expect = hspos + sizeof(tls_handshake_t) + length;
        if (pos_expect != pos) {
            // have something not parsed ..
        }
        pos = pos_expect;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_client_hello(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* advisor = tls_advisor::get_instance();

        constexpr char constexpr_version[] = "version";
        constexpr char constexpr_random[] = "random";
        constexpr char constexpr_session_id[] = "session id";
        constexpr char constexpr_session_ids[] = "session ids";
        constexpr char constexpr_cipher_suite[] = "cipher suite";
        constexpr char constexpr_cipher_suites[] = "cipher suites";
        constexpr char constexpr_compression_methods[] = "compression methods";
        constexpr char constexpr_compression_method[] = "compression method";
        constexpr char constexpr_extensions[] = "extension len";
        constexpr char constexpr_extension[] = "extension";

        /* RFC 8446 4.1.2.  Client Hello
         *  uint16 ProtocolVersion;
         *  opaque Random[32];
         *
         *  uint8 CipherSuite[2];    // Cryptographic suite selector
         *
         *  struct {
         *      ProtocolVersion legacy_version = 0x0303;    // TLS v1.2
         *      Random random;
         *      opaque legacy_session_id<0..32>;
         *      CipherSuite cipher_suites<2..2^16-2>;
         *      opaque legacy_compression_methods<1..2^8-1>;
         *      Extension extensions<8..2^16-1>;
         *  } ClientHello;
         */

        uint16 version = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_version);
            pl.read(stream, size, pos);

            version = t_to_int<uint16>(pl.select(constexpr_version));

            if (version < 0x0303) {
                // RFC 8996
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }

        binary_t random;
        binary_t session_id;
        binary_t cipher_suite;
        binary_t compression_method;
        uint8 session_ids = 0;
        uint16 cipher_suites = 0;
        uint8 compression_methods = 0;
        uint8 extension_len = 0;
        {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_random) << new payload_member(uint8(0), constexpr_session_ids)
               << new payload_member(binary_t(), constexpr_session_id) << new payload_member(uint16(0), true, constexpr_cipher_suites)
               << new payload_member(binary_t(), constexpr_cipher_suite) << new payload_member(uint8(0), constexpr_compression_methods)
               << new payload_member(binary_t(), constexpr_compression_method) << new payload_member(uint16(0), true, constexpr_extensions);

            pl.select(constexpr_random)->reserve(32);
            pl.set_reference_value(constexpr_session_id, constexpr_session_ids);
            pl.set_reference_value(constexpr_cipher_suite, constexpr_cipher_suites);
            pl.set_reference_value(constexpr_compression_method, constexpr_compression_methods);
            pl.set_reference_value(constexpr_extensions, constexpr_extension);
            pl.read(stream, size, pos);

            // RFC 8446 4.1.1.  Cryptographic Negotiation
            // -  A list of cipher suites
            // -  A "supported_groups" (Section 4.2.7) extension
            // -  A "signature_algorithms" (Section 4.2.3) extension
            // -  A "pre_shared_key" (Section 4.2.11) extension

            pl.select(constexpr_random)->get_variant().to_binary(random);
            session_ids = t_to_int<uint8>(pl.select(constexpr_session_ids));
            pl.select(constexpr_session_id)->get_variant().to_binary(session_id);
            cipher_suites = t_to_int<uint16>(pl.select(constexpr_cipher_suites)) >> 1;  // bytes / sizeof(uint16)
            pl.select(constexpr_cipher_suite)->get_variant().to_binary(cipher_suite);
            compression_methods = t_to_int<uint8>(pl.select(constexpr_compression_methods));
            pl.select(constexpr_compression_method)->get_variant().to_binary(compression_method);
            extension_len = t_to_int<uint16>(pl.select(constexpr_extensions));
        }

        {
            // server_key_update
            session->get_tls_protection().set_item(tls_context_client_hello_random, random);
        }

        s->autoindent(1);
        s->printf(" > %s 0x%04x (%s)\n", constexpr_version, version, advisor->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        if (random.size()) {
            dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
            s->printf("\n");
            s->printf("   %s\n", base16_encode(random).c_str());
        }
        s->printf(" > %s\n", constexpr_session_id);
        if (session_id.size()) {
            s->printf("   %s\n", base16_encode(session_id).c_str());
        }
        s->printf(" > %s %i\n", constexpr_cipher_suites, cipher_suites);
        for (auto i = 0; i < cipher_suites; i++) {
            auto cs = t_binary_to_integer<uint16>(&cipher_suite[i << 1], sizeof(uint16));
            s->printf("   0x%04x %s\n", cs, advisor->cipher_suite_string(cs).c_str());
        }
        s->printf(" > %s %i\n", constexpr_compression_methods, compression_methods);
        for (auto i = 0; i < compression_methods; i++) {
            auto compr = t_binary_to_integer<uint8>(&compression_method[i], sizeof(uint8));
            s->printf("   0x%02x %s\n", compr, advisor->compression_method_string(compr).c_str());
        }
        s->autoindent(0);
        s->printf(" > %s %i(0x%02x)\n", constexpr_extensions, extension_len, extension_len);

        while (errorcode_t::success == tls_dump_extension(hstype, s, session, stream, size, pos)) {
        };
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_server_hello(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* advisor = tls_advisor::get_instance();

        constexpr char constexpr_version[] = "version";
        constexpr char constexpr_random[] = "random";
        constexpr char constexpr_session_ids[] = "session ids";
        constexpr char constexpr_session_id[] = "session id";
        constexpr char constexpr_cipher_suite[] = "cipher suite";
        constexpr char constexpr_compression_method[] = "compression method";
        constexpr char constexpr_extensions[] = "extension len";
        constexpr char constexpr_extension[] = "extension";

        /* RFC 8446 4.1.3.  Server Hello */

        uint16 version = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_version);
            pl.read(stream, size, pos);

            version = t_to_int<uint16>(pl.select(constexpr_version));
        }

        binary_t random;
        binary_t session_id;
        uint8 session_ids = 0;
        uint16 cipher_suite = 0;
        uint8 compression_method = 0;
        uint8 extension_len = 0;
        {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_random) << new payload_member(uint8(0), constexpr_session_ids)
               << new payload_member(binary_t(), constexpr_session_id) << new payload_member(uint16(0), true, constexpr_cipher_suite)
               << new payload_member(uint8(0), constexpr_compression_method) << new payload_member(uint16(0), true, constexpr_extensions);

            pl.select(constexpr_random)->reserve(32);
            pl.set_reference_value(constexpr_session_id, constexpr_session_ids);
            pl.read(stream, size, pos);

            // RFC 8446 4.1.1.  Cryptographic Negotiation
            // If PSK is being used, ... "pre_shared_key" extension indicating the selected key
            // When (EC)DHE is in use, ... "key_share" extension
            // When authenticating via a certificate, ... Certificate (Section 4.4.2) and CertificateVerify (Section 4.4.3)

            pl.select(constexpr_random)->get_variant().to_binary(random);
            session_ids = t_to_int<uint8>(pl.select(constexpr_session_ids));
            pl.select(constexpr_session_id)->get_variant().to_binary(session_id);
            cipher_suite = t_to_int<uint16>(pl.select(constexpr_cipher_suite));
            compression_method = t_to_int<uint8>(pl.select(constexpr_compression_method));
            extension_len = t_to_int<uint16>(pl.select(constexpr_extensions));
        }

        {
            // server_key_update
            session->get_tls_protection().set_item(tls_context_server_hello_random, random);
        }

        s->autoindent(1);
        s->printf(" > %s 0x%04x (%s)\n", constexpr_version, version, advisor->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        if (random.size()) {
            dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
            s->printf("\n");
            s->printf("   %s\n", base16_encode(random).c_str());
        }
        s->printf(" > %s\n", constexpr_session_id);
        if (session_id.size()) {
            s->printf("   %s\n", base16_encode(session_id).c_str());
        }
        s->printf(" > %s 0x%04x %s\n", constexpr_cipher_suite, cipher_suite, advisor->cipher_suite_string(cipher_suite).c_str());
        s->printf(" > %s %i %s\n", constexpr_compression_method, compression_method, advisor->compression_method_string(compression_method).c_str());
        s->autoindent(0);
        s->printf(" > %s %i(0x%02x)\n", constexpr_extensions, extension_len, extension_len);

        while (errorcode_t::success == tls_dump_extension(hstype, s, session, stream, size, pos)) {
        };

        // cipher_suite
        session->get_tls_protection().set_cipher_suite(cipher_suite);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_new_session_ticket(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* advisor = tls_advisor::get_instance();

        /**
         * RFC 8446 4.6.1.  New Session Ticket Message
         * struct {
         *     uint32 ticket_lifetime;
         *     uint32 ticket_age_add;
         *     opaque ticket_nonce<0..255>;
         *     opaque ticket<1..2^16-1>;
         *     Extension extensions<0..2^16-2>;
         * } NewSessionTicket;
         */

        constexpr char constexpr_ticket_lifetime[] = "ticket timeline";
        constexpr char constexpr_ticket_age_add[] = "ticket age add";
        constexpr char constexpr_ticket_nonce_len[] = "ticket nonce len";
        constexpr char constexpr_ticket_nonce[] = "ticket nonce";
        constexpr char constexpr_session_ticket_len[] = "session ticket len";
        constexpr char constexpr_session_ticket[] = "session ticket";
        constexpr char constexpr_ticket_extension_len[] = "ticket extension len";
        constexpr char constexpr_ticket_extensions[] = "ticket extensions";

        uint32 ticket_lifetime = 0;
        uint32 ticket_age_add = 0;
        binary_t ticket_nonce;
        binary_t session_ticket;
        binary_t ticket_extensions;
        {
            payload pl;
            pl << new payload_member(uint32(0), true, constexpr_ticket_lifetime) << new payload_member(uint32(0), true, constexpr_ticket_age_add)
               << new payload_member(uint8(0), constexpr_ticket_nonce_len) << new payload_member(binary_t(), constexpr_ticket_nonce)
               << new payload_member(uint16(0), true, constexpr_session_ticket_len) << new payload_member(binary_t(), constexpr_session_ticket)
               << new payload_member(uint16(0), true, constexpr_ticket_extension_len) << new payload_member(binary_t(), constexpr_ticket_extensions);
            pl.set_reference_value(constexpr_ticket_nonce, constexpr_ticket_nonce_len);
            pl.set_reference_value(constexpr_session_ticket, constexpr_session_ticket_len);
            pl.set_reference_value(constexpr_ticket_extensions, constexpr_ticket_extension_len);
            pl.read(stream, size, pos);

            ticket_lifetime = t_to_int<uint32>(pl.select(constexpr_ticket_lifetime));
            ticket_age_add = t_to_int<uint32>(pl.select(constexpr_ticket_age_add));
            pl.select(constexpr_ticket_nonce)->get_variant().to_binary(ticket_nonce);
            pl.select(constexpr_session_ticket)->get_variant().to_binary(session_ticket);
            pl.select(constexpr_ticket_extensions)->get_variant().to_binary(ticket_extensions);
        }

        s->autoindent(1);
        s->printf(" > %s 0x%08x\n", constexpr_ticket_lifetime, ticket_lifetime);
        s->printf(" > %s 0x%08x\n", constexpr_ticket_age_add, ticket_age_add);
        s->printf(" > %s %s\n", constexpr_ticket_nonce, base16_encode(ticket_nonce).c_str());
        s->printf(" > %s\n", constexpr_session_ticket);
        dump_memory(session_ticket, s, 16, 3, 0x0, dump_notrunc);
        s->printf("\n");
        s->printf(" > %s %s\n", constexpr_ticket_extensions, base16_encode(ticket_extensions).c_str());
        s->autoindent(0);
        s->printf("\n");
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_encrypted_extensions(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 8446 4.3.1.  Encrypted Extensions

        tls_advisor* advisor = tls_advisor::get_instance();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_certificate(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* advisor = tls_advisor::get_instance();

        constexpr char constexpr_request_context_len[] = "request context len";
        constexpr char constexpr_request_context[] = "request context";
        constexpr char constexpr_certificates_len[] = "certifcates len";
        constexpr char constexpr_certificate_len[] = "certifcate len";
        constexpr char constexpr_certificate[] = "certifcate";
        constexpr char constexpr_group_tls13[] = "tls1.3";

        binary_t cert;
        crypto_keychain keychain;
        uint8 request_context_len = 0;
        uint32 certificates_len = 0;
        uint32 certificate_len = 0;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_request_context_len, constexpr_group_tls13)  // TLS 1.3
               << new payload_member(binary_t(), constexpr_request_context, constexpr_group_tls13)    // TLS 1.3
               << new payload_member(uint32_24_t(), constexpr_certificates_len) << new payload_member(uint32_24_t(), constexpr_certificate_len)
               << new payload_member(binary_t(), constexpr_certificate);
            pl.set_reference_value(constexpr_certificate, constexpr_certificate_len);
            pl.set_reference_value(constexpr_request_context, constexpr_request_context_len);
            auto tls_version = session->get_tls_protection().get_tls_version();
            pl.set_group(constexpr_group_tls13, tls_version == tls_13 ? true : false);  // tls_extension_supported_versions 0x002b server_hello
            pl.read(stream, size, pos);

            request_context_len = t_to_int<uint8>(pl.select(constexpr_request_context_len));
            certificates_len = t_to_int<uint32>(pl.select(constexpr_certificates_len));
            certificate_len = t_to_int<uint32>(pl.select(constexpr_certificate_len));
            pl.select(constexpr_certificate)->get_variant().to_binary(cert);
        }

        constexpr char constexpr_certificate_extensions[] = "certificate extensions";
        constexpr char constexpr_record_type[] = "record type";

        binary_t cert_extensions;
        uint8 record_type = 0;
        {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_certificate_extensions) << new payload_member(uint8(0), constexpr_record_type);
            pl.select(constexpr_certificate_extensions)->reserve(certificates_len - certificate_len - sizeof(uint24_t));
            pl.read(stream, size, pos);

            pl.select(constexpr_certificate_extensions)->get_variant().to_binary(cert_extensions);
            record_type = t_to_int<uint8>(pl.select(constexpr_record_type));
        }

        s->autoindent(1);
        s->printf(" > %s %i\n", constexpr_request_context_len, request_context_len);
        s->printf(" > %s 0x%04x(%i)\n", constexpr_certificates_len, certificates_len, certificates_len);
        s->printf(" > %s 0x%04x(%i)\n", constexpr_certificate_len, certificate_len, certificate_len);
        dump_memory(cert, s, 16, 3, 0x00, dump_notrunc);
        s->printf("\n");
        s->printf(" > %s\n", constexpr_certificate_extensions);
        dump_memory(cert_extensions, s, 16, 3, 0x00, dump_notrunc);
        s->printf("\n");
        s->printf(" > %s 0x%02x (%s)\n", constexpr_record_type, record_type, advisor->content_type_string(record_type).c_str());
        s->autoindent(0);
        s->printf("\n");

        auto& servercert = session->get_tls_protection().get_cert();
        ret = keychain.load_der(&servercert, &cert[0], cert.size(), keydesc(use_sig));
        if (errorcode_t::success == ret) {
            dump_key(servercert.any(), s, 15, 4, dump_notrunc);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_server_key_exchange(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        size_t hspos = pos;
        uint8 curve_info = 0;
        uint16 curve = 0;
        uint8 pubkey_len = 0;
        binary_t pubkey;
        uint16 signature = 0;
        uint16 sig_len = 0;
        binary_t sig;

        constexpr char constexpr_curve_info[] = "curve info";
        constexpr char constexpr_curve[] = "curve";
        constexpr char constexpr_pubkey_len[] = "public key len";
        constexpr char constexpr_pubkey[] = "public key";
        constexpr char constexpr_signature[] = "signature";
        constexpr char constexpr_sig_len[] = "signature len";
        constexpr char constexpr_sig[] = "computed signature";

        // RFC 5246 7.4.3.  Server Key Exchange Message
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_curve_info) << new payload_member(uint16(0), true, constexpr_curve)
               << new payload_member(uint8(0), constexpr_pubkey_len) << new payload_member(binary_t(), constexpr_pubkey)
               << new payload_member(uint16(0), true, constexpr_signature) << new payload_member(uint16(0), true, constexpr_sig_len)
               << new payload_member(binary_t(), constexpr_sig);
            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
            pl.set_reference_value(constexpr_sig, constexpr_sig_len);
            pl.read(stream, size, pos);

            curve_info = t_to_int<uint8>(pl.select(constexpr_curve_info));
            curve = t_to_int<uint16>(pl.select(constexpr_curve));
            pubkey_len = t_to_int<uint8>(pl.select(constexpr_pubkey_len));
            pl.select(constexpr_pubkey)->get_variant().to_binary(pubkey);
            signature = t_to_int<uint16>(pl.select(constexpr_signature));
            sig_len = t_to_int<uint16>(pl.select(constexpr_sig_len));
            pl.select(constexpr_sig)->get_variant().to_binary(sig);
        }

        {
            //
            // protection.set_item(tls_context_server_public_key, pubkey);
            auto& keyexchange = protection.get_keyexchange();
            if (3 == curve_info) {  // named_curve
                //
            }
        }

        {
            // hash(client_hello_random + server_hello_random + curve_info + public_key)
            binary_t message;
            binary_append(message, protection.get_item(tls_context_client_hello_random));
            binary_append(message, protection.get_item(tls_context_server_hello_random));
            binary_append(message, stream + hspos, 3);
            binary_append(message, pubkey_len);
            binary_append(message, pubkey);

            auto sign = session->get_tls_protection().get_crypto_sign(signature);
            if (sign) {
                crypto_key& key = session->get_tls_protection().get_cert();
                auto pkey = key.any();
                ret = sign->verify(pkey, message, sig);
                sign->release();
            } else {
                ret = errorcode_t::not_supported;
            }
        }

        {
            s->autoindent(1);
            s->printf(" > %s %i\n", constexpr_curve_info, curve_info);
            s->printf(" > %s 0x%04x %s\n", constexpr_curve, curve, tlsadvisor->named_curve_string(curve).c_str());
            s->printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
            dump_memory(pubkey, s, 16, 3, 0x0, dump_notrunc);
            s->printf("\n");
            s->printf(" > %s 0x%04x %s\n", constexpr_signature, signature, tlsadvisor->signature_scheme_string(signature).c_str());
            s->printf(" > %s %i\n", constexpr_sig_len, sig_len);
            dump_memory(sig, s, 16, 3, 0x0, dump_notrunc);
            s->printf("\n");
            s->autoindent(0);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_server_hello_done(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_certificate_verify(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* advisor = tls_advisor::get_instance();

        constexpr char constexpr_signature[] = "signature algorithm";
        constexpr char constexpr_len[] = "len";
        constexpr char constexpr_handshake_hash[] = "handshake's hash";
        constexpr char constexpr_record[] = "record";

        uint16 scheme = 0;
        uint16 len = 0;
        uint8 record = 0;
        binary_t handshake_hash;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_signature) << new payload_member(uint16(0), true, constexpr_len)
               << new payload_member(binary_t(), constexpr_handshake_hash) << new payload_member(uint8(0), constexpr_record);
            pl.set_reference_value(constexpr_handshake_hash, constexpr_len);
            pl.read(stream, size, pos);

            scheme = t_to_int<uint16>(pl.select(constexpr_signature));
            len = t_to_int<uint16>(pl.select(constexpr_len));
            pl.select(constexpr_handshake_hash)->get_variant().to_binary(handshake_hash);
            record = t_to_int<uint8>(pl.select(constexpr_record));
        }

        tls_protection& protection = session->get_tls_protection();
        binary_t hshash;
        auto sign = session->get_tls_protection().get_crypto_sign(scheme);
        if (sign) {
            /**
             * RFC 8446 4.4.  Authentication Messages
             *
             *  CertificateVerify:  A signature over the value
             *     Transcript-Hash(Handshake Context, Certificate).
             *
             * RFC 8446 4.4.3.  Certificate Verify
             *
             * https://tls13.xargs.org/#server-certificate-verify/annotated
             *  ### find the hash of the conversation to this point, excluding
             *  ### 5-byte record headers or 1-byte wrapped record trailers
             *  Each TLS 1.3 record disguised as TLS 1.2 application data has a final byte which indicates its actual record type.
             *  $ handshake_hash=$((
             *     tail -c +6 clienthello;
             *     tail -c +6 serverhello;
             *     perl -pe 's/.$// if eof' serverextensions;
             *     perl -pe 's/.$// if eof' servercert) | openssl sha384)
             */

            auto hash = protection.get_transcript_hash();  // hash(client_hello .. certificate)
            if (hash) {
                hash->digest(hshash);
                hash->release();
            }

            constexpr char constexpr_context[] = "TLS 1.3, server CertificateVerify";
            basic_stream tosign;
            tosign.fill(64, 0x20);                    // octet 32 (0x20) repeated 64 times
            tosign << constexpr_context;              // context string
            tosign.fill(1, 0x00);                     // single 0 byte
            tosign.write(&hshash[0], hshash.size());  // content to be signed

            // $ openssl x509 -pubkey -noout -in server.crt > server.pub
            // public key from server certificate or handshake 0x11 certificate
            crypto_key& key = session->get_tls_protection().get_cert();
            auto pkey = key.any();

            // ### verify the signature
            // $ cat /tmp/tosign | openssl dgst -verify server.pub -sha256 \
            //     -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -signature /tmp/sig
            ret = sign->verify(pkey, tosign.data(), tosign.size(), handshake_hash);

            sign->release();
        } else {
            ret = errorcode_t::not_supported;
        }

        s->autoindent(1);
        s->printf(" > %s 0x%04x %s\n", constexpr_signature, scheme, advisor->signature_scheme_string(scheme).c_str());
        s->printf(" > %s 0x%04x(%i)\n", constexpr_len, len, len);
        s->printf(" > %s %s %s\n", constexpr_handshake_hash, base16_encode(handshake_hash).c_str(), (errorcode_t::success == ret) ? "true" : "false");
        dump_memory(handshake_hash, s, 16, 3, 0x00, dump_notrunc);
        s->printf("\n");
        s->autoindent(0);
        s->printf(" > %s %02x\n", constexpr_record, record);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_client_key_exchange(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        constexpr char constexpr_pubkey_len[] = "public key len";
        constexpr char constexpr_pubkey[] = "public key";

        uint8 pubkey_len = 0;
        binary_t pubkey;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_pubkey_len) << new payload_member(binary_t(), constexpr_pubkey);
            pl.set_reference_value(constexpr_pubkey, constexpr_pubkey_len);
            pl.read(stream, size, pos);

            pubkey_len = t_to_int<uint8>(pl.select(constexpr_pubkey_len));
            pl.select(constexpr_pubkey)->get_variant().to_binary(pubkey);
        }

        {
            //
            // session->get_tls_protection().set_item(tls_context_client_public_key, pubkey);
            // get_keyexchange ...

        }

        {
            s->autoindent(1);
            s->printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
            s->printf(" > %s\n", constexpr_pubkey);
            dump_memory(pubkey, s, 16, 3, 0x0, dump_notrunc);
            s->autoindent(0);
            s->printf("\n");
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_finished(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint_tls_alg = tlsadvisor->hintof_tls_algorithm(protection.get_cipher_suite());
        auto dlen = sizeof_digest(advisor->hintof_digest(hint_tls_alg->mac));

        constexpr char constexpr_verify_data[] = "verify data";
        constexpr char constexpr_record[] = "record";

        uint8 record = 0;
        binary_t verify_data;

        {
            // RFC 8448 record not exist
            payload pl;
            pl << new payload_member(binary_t(), constexpr_verify_data) << new payload_member(uint8(0), constexpr_record);
            pl.select(constexpr_verify_data)->reserve(dlen);
            pl.read(stream, size, pos);

            pl.select(constexpr_verify_data)->get_variant().to_binary(verify_data);
            record = t_to_int<uint8>(pl.select(constexpr_record));
        }

        {
            // https://tls13.xargs.org/#server-handshake-finished/annotated
            //
            // finished_key = HKDF-Expand-Label(key: server_secret, label: "finished", ctx: "", len: 48)
            // finished_hash = SHA384(Client Hello ... Server Cert Verify)
            // verify_data = HMAC-SHA384(key: finished_key, msg: finished_hash)

            // ### excluding 5-byte record headers or 1-byte wrapped record trailers
            // $ fin_hash=$((
            //     tail -c +6 clienthello;
            //     tail -c +6 serverhello;
            //     perl -pe 's/.$// if eof' serverextensions;
            //     perl -pe 's/.$// if eof' servercert;
            //     perl -pe 's/.$// if eof' servercertverify) | openssl sha384)
            binary_t fin_hash;
            auto hash = protection.get_transcript_hash();
            if (hash) {
                hash->digest(fin_hash);
                hash->release();
            }

            auto typeof_secret = tls_secret_handshake_server;
            if (role) {
                typeof_secret = tls_secret_handshake_client;
            }
            const binary_t& ht_secret = protection.get_item(typeof_secret);
            // $ fin_key=$(./hkdf-384 expandlabel $ht_secret "finished" "" 48)
            hash_algorithm_t hashalg = tlsadvisor->hash_alg_of(protection.get_cipher_suite());
            binary_t fin_key;
            openssl_kdf kdf;
            binary_t context;
            kdf.hkdf_expand_label(fin_key, hashalg, dlen, ht_secret, str2bin("finished"), context);
            // $ echo $fin_hash | xxd -r -p \
            //     | openssl dgst -sha384 -mac HMAC -macopt hexkey:$fin_key
            binary_t maced;
            crypto_hmac_builder builder;
            crypto_hmac* hmac = builder.set(hashalg).build();
            if (hmac) {
                hmac->mac(fin_key, fin_hash, maced);
                hmac->release();
            }

            if (verify_data != maced) {
                ret = errorcode_t::error_verify;
            }

            s->autoindent(1);
            s->printf("> %s\n", constexpr_verify_data);
            dump_memory(verify_data, s, 16, 3, 0x00, dump_notrunc);
            s->printf("\n");
            s->printf("  > secret (internal) %02x\n", typeof_secret);
            s->printf("  > ht_secret %s\n", base16_encode(ht_secret).c_str());
            s->printf("  > fin_key   %s\n", base16_encode(fin_key).c_str());
            s->printf("  > fin_hash  %s\n", base16_encode(fin_hash).c_str());
            s->printf("  > maced     %s %s\n", base16_encode(maced).c_str(), (errorcode_t::success == ret) ? "true" : "false");
            dump_memory(maced, s, 16, 3, 0x00, dump_notrunc);
            s->printf("\n");
            s->printf("> %s %02x", constexpr_record, record);
            s->autoindent(0);
            s->printf("\n");
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
