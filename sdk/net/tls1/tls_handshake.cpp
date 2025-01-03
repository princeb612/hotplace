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
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/crypto/crypto_hash.hpp>
#include <sdk/crypto/crypto/crypto_hmac.hpp>
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/crypto/crypto/transcript_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Handshake

static return_t tls_dump_client_hello(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_server_hello(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_new_session_ticket(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_encrypted_extensions(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_certificate(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
static return_t tls_dump_server_key_exchange(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
static return_t tls_dump_server_hello_done(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
static return_t tls_dump_certificate_verify(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role);
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
            ret = errorcode_t::no_more;
            __leave2;
        }

        // RFC 8446
        //  5.1.  Record Layer
        //  5.2.  Record Payload Protection
        auto& protection = session->get_tls_protection();
        auto record_version = protection.get_record_version();
        size_t sizeof_dtls_recons = 0;
        if (is_kindof_dtls(record_version)) {
            // problem
            //    do_something(stream + hspos, sizeof(tls_handshake_t) + length, ...) -> DTLS fails
            //    contrast...
            //    do_something(stream + hspos, size - hspos, ...) -> pass
            //    do_something(stream + hspos, sizeof(tls_handshake_t) + length + sizeof_dtls_recons, ...) -> pass
            // checkpoint
            //    1) reconstruction_data size (8 bytes)
            //       tls_content_t::length    included
            //       tls_handshake_t::length  excluded
            //    2) tls_handshake_t::length == reconstruction_data::fragment_len
            //       lengthof(record) = record_header(13) + tls_handshake_t(4) + reconstruction_data(8) + tls_handshake_t::length

            sizeof_dtls_recons = 8;
        }

        size_t hspos = pos;
        tls_handshake_t* handshake = (tls_handshake_t*)(stream + pos);
        uint32 length = 0;
        b24_i32(handshake->length, length);
        if (size < pos + sizeof(tls_handshake_t) + length) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
        pos += sizeof(tls_handshake_t);

        auto hstype = handshake->msg_type;
        size_t hssize = sizeof(tls_handshake_t) + length + sizeof_dtls_recons;  // see sizeof_dtls_recons

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        // DTLS handshake reconstruction data
        constexpr char constexpr_group_dtls[] = "dtls";
        constexpr char constexpr_handshake_message_seq[] = "handshake message sequence number";
        constexpr char constexpr_fragment_offset[] = "fragment offset";
        constexpr char constexpr_fragment_len[] = "fragment len";
        bool cond_dtls = false;
        uint16 dtls_seq = 0;
        uint32 fragment_offset = 0;
        uint32 fragment_len = 0;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_handshake_message_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint32_24_t(), constexpr_fragment_offset, constexpr_group_dtls)          // dtls
               << new payload_member(uint32_24_t(), constexpr_fragment_len, constexpr_group_dtls);            // dtls;
            pl.set_group(constexpr_group_dtls, (record_version >= dtls_12));
            pl.read(stream, size, pos);

            cond_dtls = pl.get_group_condition(constexpr_group_dtls);
            if (cond_dtls) {
                dtls_seq = pl.t_value_of<uint32>(constexpr_handshake_message_seq);
                fragment_offset = pl.t_value_of<uint32>(constexpr_fragment_offset);
                fragment_len = pl.t_value_of<uint32>(constexpr_fragment_len);
            }
        }

        s->printf(" > handshake type 0x%02x(%i) (%s)\n", hstype, hstype, tlsadvisor->handshake_type_string(hstype).c_str());
        s->printf(" > length 0x%06x(%i)\n", length, length);
        if (cond_dtls) {
            s->printf(" > %s 0x%04x\n", constexpr_handshake_message_seq, dtls_seq);
            s->printf(" > %s 0x%06x(%i)\n", constexpr_fragment_offset, fragment_offset, fragment_offset);
            s->printf(" > %s 0x%06x(%i)\n", constexpr_fragment_len, fragment_len, fragment_len);
        }

        binary_t handshake_hash;

        /**
         * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
         *  4.  Handshake Protocol
         *      enum {
         *          client_hello(1),
         *          server_hello(2),
         *          new_session_ticket(4),
         *          end_of_early_data(5),
         *          encrypted_extensions(8),
         *          certificate(11),
         *          certificate_request(13),
         *          certificate_verify(15),
         *          finished(20),
         *          key_update(24),
         *          message_hash(254),
         *          (255)
         *      } HandshakeType;
         *
         *      struct {
         *          HandshakeType msg_type;    // handshake type
         *          uint24 length;             // remaining bytes in message
         *          select (Handshake.msg_type) {
         *              case client_hello:          ClientHello;
         *              case server_hello:          ServerHello;
         *              case end_of_early_data:     EndOfEarlyData;
         *              case encrypted_extensions:  EncryptedExtensions;
         *              case certificate_request:   CertificateRequest;
         *              case certificate:           Certificate;
         *              case certificate_verify:    CertificateVerify;
         *              case finished:              Finished;
         *              case new_session_ticket:    NewSessionTicket;
         *              case key_update:            KeyUpdate;
         *          };
         *      } Handshake;
         */
        switch (handshake->msg_type) {
            case tls_handshake_client_hello: /* 1 */ {
                auto hsstatus = session->get_roleinfo(role).get_status();
                if (tls_handshake_finished == hsstatus) {
                    // 0-RTT
                    protection.set_flow(tls_0_rtt);
                }
                switch (protection.get_flow()) {
                    case tls_1_rtt: {
                    } break;
                    case tls_0_rtt: {
                        protection.get_keyexchange().clear();

                        session->reset_recordno(role_client);
                        session->reset_recordno(role_server);
                    } break;
                    case tls_hello_retry_request: {
                        auto& keyexchange = protection.get_keyexchange();
                        keyexchange.erase("CH");  // client_hello key_share
                        keyexchange.erase("SH");  // server_hello key_share
                    } break;
                    default: {
                    } break;
                }

                ret = tls_dump_client_hello(hstype, s, session, stream, size, pos);

                switch (protection.get_flow()) {
                    case tls_1_rtt: {
                        // 1-RTT
                        protection.set_item(tls_context_client_hello, stream + hspos, hssize);  // transcript hash, see server_hello
                    } break;
                    case tls_0_rtt: {
                        protection.reset_transcript_hash(session);
                        protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);  // client_hello
                        ret = protection.calc(session, tls_handshake_client_hello, role);
                    } break;
                    case tls_hello_retry_request: {
                        protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);  // client_hello
                    } break;
                }

                session->get_roleinfo(role).set_status(handshake->msg_type);

            } break;
            case tls_handshake_server_hello: /* 2 */ {
                ret = tls_dump_server_hello(hstype, s, session, stream, size, pos);

                // calculates the hash of all handshake messages to this point (ClientHello and ServerHello).
                binary_t hello_hash;
                if (tls_1_rtt == protection.get_flow()) {
                    const binary_t& client_hello = protection.get_item(tls_context_client_hello);
                    protection.calc_transcript_hash(session, &client_hello[0], client_hello.size(), handshake_hash);  // client_hello
                }

                protection.calc_transcript_hash(session, stream + hspos, hssize, hello_hash);  // server_hello
                ret = protection.calc(session, tls_handshake_server_hello, role);
                session->get_roleinfo(role).set_status(handshake->msg_type);
                if (errorcode_t::success != ret) {
                    protection.set_flow(tls_hello_retry_request);

                    /**
                     *    RFC 8446 4.4.1.  The Transcript Hash
                     *
                     *       As an exception to this general rule, when the server responds to a
                     *       ClientHello with a HelloRetryRequest, the value of ClientHello1 is
                     *       replaced with a special synthetic handshake message of handshake type
                     *       "message_hash" containing Hash(ClientHello1).  I.e.,
                     *
                     *       Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
                     *           Hash(message_hash ||        // Handshake type
                     *                00 00 Hash.length  ||  // Handshake message length (bytes)
                     *                Hash(ClientHello1) ||  // Hash of ClientHello1
                     *                HelloRetryRequest  || ... || Mn)
                     */
                    const binary_t& client_hello = protection.get_item(tls_context_client_hello);
                    protection.reset_transcript_hash(session);
                    protection.calc_transcript_hash(session, &client_hello[0], client_hello.size(), handshake_hash);

                    binary message_hash;
                    message_hash << uint8(tls_handshake_message_hash) << uint16(0) << byte_t(handshake_hash.size()) << handshake_hash;
                    const binary_t& synthetic_handshake_message = message_hash.get();

                    protection.reset_transcript_hash(session);
                    protection.calc_transcript_hash(session, &synthetic_handshake_message[0], synthetic_handshake_message.size(), handshake_hash);
                    protection.calc_transcript_hash(session, stream + hspos, hssize, hello_hash);
                }

                protection.clear_item(tls_context_client_hello);

            } break;
            case tls_handshake_new_session_ticket: /* 4 */ {
                ret = tls_dump_new_session_ticket(s, session, stream, size, pos);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_end_of_early_data: /* 5 */ {
                protection.calc(session, tls_handshake_end_of_early_data, role);
                session->reset_recordno(role_client);
                session->reset_recordno(role_server);
                session->get_roleinfo(role).set_status(handshake->msg_type);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_encrypted_extensions: /* 8 */ {
                // RFC 8446 2.  Protocol Overview
                // EncryptedExtensions:  responses to ClientHello extensions that are
                //    not required to determine the cryptographic parameters, other than
                //    those that are specific to individual certificates.
                //    [Section 4.3.1]

                // RFC 8446 4.3.1.  Encrypted Extensions
                // struct {
                //     Extension extensions<0..2^16-1>;
                // } EncryptedExtensions;

                ret = tls_dump_encrypted_extensions(hstype, s, session, stream + hspos, hssize, pos);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_certificate: /* 11 */ {
                // RFC 8446 2.  Protocol Overview
                // Certificate:  The certificate of the endpoint and any per-certificate
                //    extensions.  This message is omitted by the server if not
                //    authenticating with a certificate and by the client if the server
                //    did not send CertificateRequest (thus indicating that the client
                //    should not authenticate with a certificate).  Note that if raw
                //    public keys [RFC7250] or the cached information extension
                //    [RFC7924] are in use, then this message will not contain a
                //    certificate but rather some other value corresponding to the
                //    server's long-term key.  [Section 4.4.2]

                // RFC 4346 7.4.2. Server Certificate
                //  opaque ASN.1Cert<1..2^24-1>;
                //  struct {
                //      ASN.1Cert certificate_list<0..2^24-1>;
                //  } Certificate;
                // RFC 4346 7.4.3. Server Key Exchange Message
                // RFC 4346 7.4.6. Client certificate
                // RFC 4346 7.4.7. Client Key Exchange Message
                ret = tls_dump_certificate(s, session, stream, size, pos, role);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_server_key_exchange: /* 12 */ {
                ret = tls_dump_server_key_exchange(s, session, stream, size, pos, role);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_certificate_request: /* 13 */ {
                // RFC 4346 7.4.4. Certificate request
                // do something
                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_server_hello_done: /* 14 */ {
                ret = tls_dump_server_hello_done(s, session, stream, size, pos, role);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_certificate_verify: /* 15 */ {
                // RFC 8446 2.  Protocol Overview
                // CertificateVerify:  A signature over the entire handshake using the
                //    private key corresponding to the public key in the Certificate
                //    message.  This message is omitted if the endpoint is not
                //    authenticating via a certificate.  [Section 4.4.3]

                // RFC 4346 7.4.8. Certificate verify
                ret = tls_dump_certificate_verify(s, session, stream, size, pos, role);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_client_key_exchange: /* 16 */ {
                ret = tls_dump_client_key_exchange(s, session, stream, size, pos, role);

                protection.calc(session, tls_handshake_client_key_exchange, role);

                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
            } break;
            case tls_handshake_finished: /* 20 */ {
                // RFC 8446 2.  Protocol Overview
                // Finished:  A MAC (Message Authentication Code) over the entire
                //    handshake.  This message provides key confirmation, binds the
                //    endpoint's identity to the exchanged keys, and in PSK mode also
                //    authenticates the handshake.  [Section 4.4.4]

                ret = tls_dump_finished(s, session, stream, size, pos, role);
                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);

                // role_server : application, exporter related
                // role_client : resumption related
                protection.calc(session, tls_handshake_finished, role);

                session->get_roleinfo(role).set_status(handshake->msg_type);

                session->reset_recordno(role);
            } break;
            case tls_handshake_key_update:   /* 24 */
            case tls_handshake_message_hash: /* 254 */
            default: {
                protection.calc_transcript_hash(session, stream + hspos, hssize, handshake_hash);
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

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        constexpr char constexpr_version[] = "version";
        constexpr char constexpr_random[] = "random";
        constexpr char constexpr_session_id[] = "session id";
        constexpr char constexpr_session_id_len[] = "session id len";
        constexpr char constexpr_cipher_suite[] = "cipher suite";
        constexpr char constexpr_cipher_suite_len[] = "cipher suite len";
        constexpr char constexpr_compression_method_len[] = "compression method len";
        constexpr char constexpr_compression_method[] = "compression method";
        constexpr char constexpr_extension_len[] = "extension len";

        constexpr char constexpr_group_dtls[] = "dtls";
        constexpr char constexpr_cookie_len[] = "cookie len";
        constexpr char constexpr_cookie[] = "cookie";

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
         *      CipherSuite cipher_suite_len<2..2^16-2>;
         *      opaque legacy_compression_methods<1..2^8-1>;
         *      Extension extensions<8..2^16-1>;
         *  } ClientHello;
         */

        auto& protection = session->get_tls_protection();
        uint16 record_version = protection.get_record_version();
        uint16 version = 0;
        binary_t random;
        binary_t session_id;
        binary_t cipher_suite;
        binary_t compression_method;
        uint8 session_id_len = 0;
        uint16 cipher_suite_len = 0;
        uint8 compression_method_len = 0;
        uint16 extension_len = 0;

        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_version) << new payload_member(binary_t(), constexpr_random)
               << new payload_member(uint8(0), constexpr_session_id_len) << new payload_member(binary_t(), constexpr_session_id)
               << new payload_member(uint8(0), constexpr_cookie_len, constexpr_group_dtls)  // dtls
               << new payload_member(binary_t(), constexpr_cookie, constexpr_group_dtls)    // dtls
               << new payload_member(uint16(0), true, constexpr_cipher_suite_len) << new payload_member(binary_t(), constexpr_cipher_suite)
               << new payload_member(uint8(0), constexpr_compression_method_len) << new payload_member(binary_t(), constexpr_compression_method)
               << new payload_member(uint16(0), true, constexpr_extension_len);

            pl.set_group(constexpr_group_dtls, (record_version >= dtls_12));

            pl.select(constexpr_random)->reserve(32);
            pl.set_reference_value(constexpr_session_id, constexpr_session_id_len);
            pl.set_reference_value(constexpr_cipher_suite, constexpr_cipher_suite_len);
            pl.set_reference_value(constexpr_compression_method, constexpr_compression_method_len);
            pl.set_reference_value(constexpr_cookie, constexpr_cookie_len);  // dtls
            pl.read(stream, size, pos);

            // RFC 8446 4.1.1.  Cryptographic Negotiation
            // -  A list of cipher suites
            // -  A "supported_groups" (Section 4.2.7) extension
            // -  A "signature_algorithms" (Section 4.2.3) extension
            // -  A "pre_shared_key" (Section 4.2.11) extension

            version = pl.t_value_of<uint16>(constexpr_version);

            pl.get_binary(constexpr_random, random);
            session_id_len = pl.t_value_of<uint8>(constexpr_session_id_len);
            pl.get_binary(constexpr_session_id, session_id);
            cipher_suite_len = pl.t_value_of<uint16>(constexpr_cipher_suite_len);
            pl.get_binary(constexpr_cipher_suite, cipher_suite);
            compression_method_len = pl.t_value_of<uint8>(constexpr_compression_method_len);
            pl.get_binary(constexpr_compression_method, compression_method);
            extension_len = pl.t_value_of<uint16>(constexpr_extension_len);
        }

        s->autoindent(1);
        s->printf(" > %s 0x%04x (%s)\n", constexpr_version, version, tlsadvisor->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        if (random.size()) {
            // dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
            s->printf("   %s\n", base16_encode(random).c_str());
        }
        s->printf(" > %s %02x(%i)\n", constexpr_session_id, session_id_len, session_id_len);
        if (session_id.size()) {
            s->printf("   %s\n", base16_encode(session_id).c_str());
        }
        s->printf(" > %s %i (%i entry)\n", constexpr_cipher_suite_len, cipher_suite_len, cipher_suite_len / sizeof(uint16));
        for (auto i = 0; i < cipher_suite_len / sizeof(uint16); i++) {
            auto cs = t_binary_to_integer<uint16>(&cipher_suite[i << 1], sizeof(uint16));
            s->printf("   [%i] 0x%04x %s\n", i, cs, tlsadvisor->cipher_suite_string(cs).c_str());
        }
        s->printf(" > %s %i\n", constexpr_compression_method_len, compression_method_len);
        for (auto i = 0; i < compression_method_len; i++) {
            auto compr = t_binary_to_integer<uint8>(&compression_method[i], sizeof(uint8));
            s->printf("   [%i] 0x%02x %s\n", i, compr, tlsadvisor->compression_method_string(compr).c_str());
        }
        s->printf(" > %s 0x%04x(%i)\n", constexpr_extension_len, extension_len, extension_len);
        s->autoindent(0);

        for (return_t test = errorcode_t::success;;) {
            test = tls_dump_extension(hstype, s, session, stream, size, pos);
            if (errorcode_t::no_more == test) {
                break;
            } else if (errorcode_t::success == test) {
                continue;
            } else {
                ret = test;
                break;
            }
        }

        // server_key_update
        protection.set_item(tls_context_client_hello_random, random);
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

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        constexpr char constexpr_version[] = "version";
        constexpr char constexpr_random[] = "random";
        constexpr char constexpr_session_id_len[] = "session id len";
        constexpr char constexpr_session_id[] = "session id";
        constexpr char constexpr_cipher_suite[] = "cipher suite";
        constexpr char constexpr_compression_method[] = "compression method";
        constexpr char constexpr_extension_len[] = "extension len";
        constexpr char constexpr_extension[] = "extension";

        constexpr char constexpr_group_dtls[] = "dtls";
        constexpr char constexpr_cookie_len[] = "cookie len";
        constexpr char constexpr_cookie[] = "cookie";

        /* RFC 8446 4.1.3.  Server Hello */

        auto& protection = session->get_tls_protection();
        uint16 record_version = protection.get_record_version();
        uint16 version = 0;

        binary_t random;
        binary_t session_id;
        uint8 session_ids = 0;
        uint16 cipher_suite = 0;
        uint8 compression_method = 0;
        uint8 extension_len = 0;

        binary_t bin_server_hello;

        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_version) << new payload_member(binary_t(), constexpr_random)
               << new payload_member(uint8(0), constexpr_session_id_len) << new payload_member(binary_t(), constexpr_session_id)
               << new payload_member(uint16(0), true, constexpr_cipher_suite) << new payload_member(uint8(0), constexpr_compression_method)
               << new payload_member(uint16(0), true, constexpr_extension_len);

            pl.set_group(constexpr_group_dtls, (record_version >= dtls_12));

            pl.select(constexpr_random)->reserve(32);
            pl.set_reference_value(constexpr_session_id, constexpr_session_id_len);
            pl.read(stream, size, pos);

            // RFC 8446 4.1.1.  Cryptographic Negotiation
            // If PSK is being used, ... "pre_shared_key" extension indicating the selected key
            // When (EC)DHE is in use, ... "key_share" extension
            // When authenticating via a certificate, ... Certificate (Section 4.4.2) and CertificateVerify (Section 4.4.3)

            version = pl.t_value_of<uint16>(constexpr_version);

            pl.get_binary(constexpr_random, random);
            session_ids = pl.t_value_of<uint8>(constexpr_session_id_len);
            pl.get_binary(constexpr_session_id, session_id);
            cipher_suite = pl.t_value_of<uint16>(constexpr_cipher_suite);
            compression_method = pl.t_value_of<uint8>(constexpr_compression_method);
            extension_len = pl.t_value_of<uint16>(constexpr_extension_len);
        }

        s->autoindent(1);
        s->printf(" > %s 0x%04x (%s)\n", constexpr_version, version, tlsadvisor->tls_version_string(version).c_str());
        s->printf(" > %s\n", constexpr_random);
        if (random.size()) {
            // dump_memory(random, s, 16, 3, 0x0, dump_notrunc);
            s->printf("   %s\n", base16_encode(random).c_str());
        }
        s->printf(" > %s\n", constexpr_session_id);
        if (session_id.size()) {
            s->printf("   %s\n", base16_encode(session_id).c_str());
        }
        s->printf(" > %s 0x%04x %s\n", constexpr_cipher_suite, cipher_suite, tlsadvisor->cipher_suite_string(cipher_suite).c_str());
        s->printf(" > %s %i %s\n", constexpr_compression_method, compression_method, tlsadvisor->compression_method_string(compression_method).c_str());
        s->printf(" > %s 0x%02x(%i)\n", constexpr_extension_len, extension_len, extension_len);
        s->autoindent(0);

        for (return_t test = errorcode_t::success;;) {
            test = tls_dump_extension(hstype, s, session, stream, size, pos);
            if (errorcode_t::no_more == test) {
                break;
            } else if (errorcode_t::success == test) {
                continue;
            } else {
                ret = test;
                break;
            }
        }

        // cipher_suite
        protection.set_cipher_suite(cipher_suite);

        // server_key_update
        session->get_tls_protection().set_item(tls_context_server_hello_random, random);
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

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

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

            ticket_lifetime = pl.t_value_of<uint32>(constexpr_ticket_lifetime);
            ticket_age_add = pl.t_value_of<uint32>(constexpr_ticket_age_add);
            pl.get_binary(constexpr_ticket_nonce, ticket_nonce);
            pl.get_binary(constexpr_session_ticket, session_ticket);
            pl.get_binary(constexpr_ticket_extensions, ticket_extensions);
        }

        s->autoindent(1);
        s->printf(" > %s 0x%08x (%i secs)\n", constexpr_ticket_lifetime, ticket_lifetime, ticket_lifetime);
        s->printf(" > %s 0x%08x\n", constexpr_ticket_age_add, ticket_age_add);
        s->printf(" > %s %s\n", constexpr_ticket_nonce, base16_encode(ticket_nonce).c_str());
        s->printf(" > %s\n", constexpr_session_ticket);
        dump_memory(session_ticket, s, 16, 3, 0x0, dump_notrunc);
        s->printf(" > %s %s\n", constexpr_ticket_extensions, base16_encode(ticket_extensions).c_str());
        s->autoindent(0);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_encrypted_extensions(tls_handshake_type_t hstype, stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 8446 4.3.1.  Encrypted Extensions

        auto& protection = session->get_tls_protection();
        // if (protection.is_kindof_dtls() /* || (tls_0_rtt == protection.get_flow()) */) {
        if (protection.is_kindof_dtls() || (tls_0_rtt == protection.get_flow())) {
            // DTLS 1.3 ciphertext

            pos += 2;  // len
            for (return_t test = errorcode_t::success;;) {
                test = tls_dump_extension(hstype, s, session, stream, size, pos);
                if (errorcode_t::no_more == test) {
                    break;
                } else if (errorcode_t::success == test) {
                    continue;
                } else {
                    ret = test;
                    break;
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_certificate(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

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
            pl.set_group(constexpr_group_tls13, is_basedon_tls13(tls_version));  // tls_extension_supported_versions 0x002b server_hello
            pl.read(stream, size, pos);

            request_context_len = pl.t_value_of<uint8>(constexpr_request_context_len);
            certificates_len = pl.t_value_of<uint32>(constexpr_certificates_len);
            certificate_len = pl.t_value_of<uint32>(constexpr_certificate_len);
            pl.get_binary(constexpr_certificate, cert);
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

            pl.get_binary(constexpr_certificate_extensions, cert_extensions);
            record_type = pl.t_value_of<uint8>(constexpr_record_type);
        }

        s->autoindent(1);
        s->printf(" > %s %i\n", constexpr_request_context_len, request_context_len);
        s->printf(" > %s 0x%04x(%i)\n", constexpr_certificates_len, certificates_len, certificates_len);
        s->printf(" > %s 0x%04x(%i)\n", constexpr_certificate_len, certificate_len, certificate_len);
        dump_memory(cert, s, 16, 3, 0x00, dump_notrunc);
        s->printf(" > %s\n", constexpr_certificate_extensions);
        dump_memory(cert_extensions, s, 16, 3, 0x00, dump_notrunc);
        s->printf(" > %s 0x%02x (%s)\n", constexpr_record_type, record_type, tlsadvisor->content_type_string(record_type).c_str());
        s->autoindent(0);

        auto& servercert = session->get_tls_protection().get_keyexchange();
        keydesc desc(use_sig);
        if (role_server == role) {
            desc.set_kid("SC");
        } else {
            desc.set_kid("CC");
        }
        ret = keychain.load_der(&servercert, &cert[0], cert.size(), desc);
        if (errorcode_t::success == ret) {
            dump_key(servercert.find(desc.get_kid_cstr()), s, 15, 4, dump_notrunc);
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

            curve_info = pl.t_value_of<uint8>(constexpr_curve_info);
            curve = pl.t_value_of<uint16>(constexpr_curve);
            pubkey_len = pl.t_value_of<uint8>(constexpr_pubkey_len);
            pl.get_binary(constexpr_pubkey, pubkey);
            signature = pl.t_value_of<uint16>(constexpr_signature);
            sig_len = pl.t_value_of<uint16>(constexpr_sig_len);
            pl.get_binary(constexpr_sig, sig);
        }

        {
            // RFC 8422, EC Curve Type, 3, "named_curve", see ec_curve_type_desc (tls_ec_curve_type_desc_t)
            // 1 explicit_prime
            // 2 explicit_char2
            // 3 named_curve
            if (3 == curve_info) {
                crypto_keychain keychain;
                auto& keyexchange = protection.get_keyexchange();
                auto hint = advisor->hintof_tls_group(curve);
                uint32 nid = nidof(hint);
                if (nid) {
                    ret = keychain.add_ec(&keyexchange, nid, pubkey, binary_t(), binary_t(), keydesc("SKE"));
                } else {
                    ret = errorcode_t::not_supported;
                }
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
                crypto_key& key = session->get_tls_protection().get_keyexchange();
                auto pkey = key.any();
                ret = sign->verify(pkey, message, sig);
                sign->release();
            } else {
                ret = errorcode_t::not_supported;
            }
        }

        {
            s->autoindent(1);
            s->printf(" > %s %i (%s)\n", constexpr_curve_info, curve_info, tlsadvisor->ec_curve_type_string(curve_info).c_str());
            s->printf(" > %s 0x%04x %s\n", constexpr_curve, curve, tlsadvisor->supported_group_string(curve).c_str());
            s->printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
            dump_memory(pubkey, s, 16, 3, 0x0, dump_notrunc);
            s->printf(" > %s 0x%04x %s\n", constexpr_signature, signature, tlsadvisor->signature_scheme_string(signature).c_str());
            s->printf(" > %s %i\n", constexpr_sig_len, sig_len);
            dump_memory(sig, s, 16, 3, 0x0, dump_notrunc);
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

return_t asn1_der_ecdsa_signature(uint16 scheme, const binary_t& signature, binary_t& r, binary_t& s) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    __try2 {
        auto hint = tlsadvisor->hintof_signature_scheme(scheme);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        if (crypt_sig_ecdsa != hint->sigtype) {
            ret = errorcode_t::bad_request;
            __leave2;
        }
        auto sig = hint->sig;
        uint32 unitsize = 0;

        switch (sig) {
            case sig_sha256:
                unitsize = 32;
                break;
            case sig_sha384:
                unitsize = 48;
                break;
            case sig_sha512:
                unitsize = 66;
                break;
        }
        if (0 == unitsize) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        // ASN.1 DER
        constexpr char constexpr_sequence[] = "sequence";
        constexpr char constexpr_len[] = "len";
        constexpr char constexpr_rlen[] = "rlen";
        constexpr char constexpr_r[] = "r";
        constexpr char constexpr_slen[] = "slen";
        constexpr char constexpr_s[] = "s";
        payload pl;
        pl << new payload_member(uint8(0), constexpr_sequence) << new payload_member(uint8(0), constexpr_len)
           << new payload_member(uint8(0))                                                                 // 2 asn1_tag_integer
           << new payload_member(uint8(0), constexpr_rlen) << new payload_member(binary_t(), constexpr_r)  //
           << new payload_member(uint8(0))                                                                 // 2 asn1_tag_integer
           << new payload_member(uint8(0), constexpr_slen) << new payload_member(binary_t(), constexpr_s);

        pl.set_reference_value(constexpr_r, constexpr_rlen);
        pl.set_reference_value(constexpr_s, constexpr_slen);

        size_t spos = 0;
        pl.read(&signature[0], signature.size(), spos);

        pl.get_binary(constexpr_r, r);
        pl.get_binary(constexpr_s, s);

        if (r.size() > unitsize) {
            auto d = r.size() - unitsize;
            r.erase(r.begin(), r.begin() + d);
        }
        if (s.size() > unitsize) {
            auto d = s.size() - unitsize;
            s.erase(s.begin(), s.begin() + d);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_certificate_verify(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos, tls_role_t role) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        constexpr char constexpr_signature_alg[] = "signature algorithm";
        constexpr char constexpr_len[] = "len";
        constexpr char constexpr_signature[] = "signature";

        uint16 scheme = 0;
        uint16 len = 0;
        binary_t signature;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_signature_alg) << new payload_member(uint16(0), true, constexpr_len)
               << new payload_member(binary_t(), constexpr_signature);
            pl.set_reference_value(constexpr_signature, constexpr_len);
            pl.read(stream, size, pos);

            scheme = pl.t_value_of<uint16>(constexpr_signature_alg);
            len = pl.t_value_of<uint16>(constexpr_len);
            pl.get_binary(constexpr_signature, signature);
        }

        tls_protection& protection = session->get_tls_protection();

        // $ openssl x509 -pubkey -noout -in server.crt > server.pub
        // public key from server certificate or handshake 0x11 certificate
        crypto_key& key = protection.get_keyexchange();
        const char* kid = nullptr;
        if (role_server == role) {
            kid = "SC";  // Server Certificate
        } else {
            kid = "CC";  // Client Certificate (Client Authentication, optional)
        }
        auto pkey = key.find(kid);

        /**
         * RSASSA-PSS     | RSA     |
         * ECDSA          | ECDSA   | ASN.1 DER (30 || length || 02 || r_length || r || 02 || s_length || s)
         * EdDSA          | Ed25519 | 64 bytes
         * EdDSA          | Ed448   | 114 bytes
         * RSA-PCKS1 v1.5 | RSA     |
         *
         * ECDSA signature
         * hash     | R  | S  | R||S
         * sha2-256 | 32 | 32 | 64
         * sha2-384 | 48 | 48 | 96
         * sha2-512 | 66 | 66 | 132
         */
        auto kty = typeof_crypto_key(pkey);
        binary_t ecdsa_sig;
        binary_t ecdsa_sig_r, ecdsa_sig_s;
        switch (kty) {
            case kty_rsa:
            case kty_okp: {
            } break;
            case kty_ec: {
                asn1_der_ecdsa_signature(scheme, signature, ecdsa_sig_r, ecdsa_sig_s);
                binary_append(ecdsa_sig, ecdsa_sig_r);
                binary_append(ecdsa_sig, ecdsa_sig_s);
            } break;
        }

        basic_stream tosign;
        binary_t transcripthash;
        auto sign = protection.get_crypto_sign(scheme);
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
             */

            auto hash = protection.get_transcript_hash();  // hash(client_hello .. certificate)
            if (hash) {
                hash->digest(transcripthash);
                hash->release();
            }

            constexpr char constexpr_context_server[] = "TLS 1.3, server CertificateVerify";
            constexpr char constexpr_context_client[] = "TLS 1.3, client CertificateVerify";
            tosign.fill(64, 0x20);  // octet 32 (0x20) repeated 64 times
            if (role_server == role) {
                tosign << constexpr_context_server;  // context string
            } else {
                tosign << constexpr_context_client;
            }
            tosign.fill(1, 0x00);                                     // single 0 byte
            tosign.write(&transcripthash[0], transcripthash.size());  // content to be signed

            if (ecdsa_sig.empty()) {
                ret = sign->verify(pkey, tosign.data(), tosign.size(), signature);
            } else {
                ret = sign->verify(pkey, tosign.data(), tosign.size(), ecdsa_sig);
            }

            sign->release();
        } else {
            ret = errorcode_t::not_supported;
        }

        s->autoindent(1);
        s->printf(" > %s 0x%04x %s\n", constexpr_signature_alg, scheme, tlsadvisor->signature_scheme_string(scheme).c_str());
        s->printf(" > %s 0x%04x(%i)\n", constexpr_len, len, len);
        s->printf(" > transcript-hash\n");
        dump_memory(transcripthash, s, 16, 3, 0x00, dump_notrunc);
        s->printf(" > tosign\n");
        dump_memory(tosign, s, 16, 3, 0x00, dump_notrunc);
        s->printf(" > %s \e[1;33m%s\e[0m\n", constexpr_signature, (errorcode_t::success == ret) ? "true" : "false");
        dump_memory(signature, s, 16, 3, 0x00, dump_notrunc);
        if (ecdsa_sig.size()) {
            s->printf(" > ecdsa r\n");
            dump_memory(ecdsa_sig_r, s, 16, 3, 0x00, dump_notrunc);
            s->printf(" > ecdsa s\n");
            dump_memory(ecdsa_sig_s, s, 16, 3, 0x00, dump_notrunc);
        }
        s->autoindent(0);
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

            pubkey_len = pl.t_value_of<uint8>(constexpr_pubkey_len);
            pl.get_binary(constexpr_pubkey, pubkey);
        }

        {
            // kty, nid from server_key_exchange
            auto& protection = session->get_tls_protection();
            auto& keyexchange = protection.get_keyexchange();
            crypto_keychain keychain;
            uint32 nid = 0;
            auto pkey_ske = keyexchange.find("SKE");
            crypto_kty_t kty = typeof_crypto_key(pkey_ske);
            nidof_evp_pkey(pkey_ske, nid);
            if (nid) {
                if (kty_ec == kty || kty_okp == kty) {
                    ret = keychain.add_ec(&keyexchange, nid, pubkey, binary_t(), binary_t(), keydesc("CKE"));
                }
            } else {
                ret = errorcode_t::not_supported;
            }
        }

        {
            s->autoindent(1);
            s->printf(" > %s %i\n", constexpr_pubkey_len, pubkey_len);
            s->printf(" > %s\n", constexpr_pubkey);
            dump_memory(pubkey, s, 16, 3, 0x0, dump_notrunc);
            s->autoindent(0);
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
        const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto dlen = sizeof_digest(advisor->hintof_digest(hint_tls_alg->mac));

        constexpr char constexpr_verify_data[] = "verify data";

        binary_t verify_data;

        {
            payload pl;
            pl << new payload_member(binary_t(), constexpr_verify_data);
            pl.select(constexpr_verify_data)->reserve(dlen);
            pl.read(stream, size, pos);

            pl.get_binary(constexpr_verify_data, verify_data);
        }

        {
            // https://tls13.xargs.org/#server-handshake-finished/annotated
            binary_t fin_hash;
            auto hash = protection.get_transcript_hash();
            if (hash) {
                hash->digest(fin_hash);
                hash->release();
            }

            // calculate finished "tls13 finished"
            // fin_key : expanded
            // finished == maced
            tls_secret_t typeof_secret;
            binary_t fin_key;
            binary_t maced;
            auto tlsversion = protection.get_tls_version();
            if (is_basedon_tls13(tlsversion)) {
                typeof_secret = tls_secret_s_hs_traffic;
                if (role) {
                    typeof_secret = tls_secret_c_hs_traffic;
                }
                const binary_t& ht_secret = protection.get_item(typeof_secret);
                hash_algorithm_t hashalg = tlsadvisor->hash_alg_of(protection.get_cipher_suite());
                openssl_kdf kdf;
                binary_t context;
                if (session->get_tls_protection().is_kindof_dtls()) {
                    kdf.hkdf_expand_dtls13_label(fin_key, hashalg, dlen, ht_secret, str2bin("finished"), context);
                } else {
                    kdf.hkdf_expand_tls13_label(fin_key, hashalg, dlen, ht_secret, str2bin("finished"), context);
                }
                crypto_hmac_builder builder;
                crypto_hmac* hmac = builder.set(hashalg).set(fin_key).build();
                if (hmac) {
                    hmac->mac(fin_hash, maced);
                    hmac->release();
                }
            } else {
                binary_t seed;
                if (role_client == role) {
                    binary_append(seed, "client finished");
                } else {
                    binary_append(seed, "server finished");
                }
                binary_append(seed, fin_hash);

                typeof_secret = tls_secret_master;
                const binary_t& fin_key = protection.get_item(typeof_secret);
                auto hmac_alg = algof_mac1(hint_tls_alg);

                crypto_hmac_builder builder;
                auto hmac = builder.set(hmac_alg).set(fin_key).build();
                size_t size_maced = 12;
                if (hmac) {
                    binary_t temp = seed;
                    binary_t atemp;
                    binary_t ptemp;
                    while (maced.size() < size_maced) {
                        hmac->mac(temp, atemp);
                        hmac->update(atemp).update(seed).finalize(ptemp);
                        binary_append(maced, ptemp);
                        temp = atemp;
                    }
                    hmac->release();
                    maced.resize(size_maced);
                }
            }

            verify_data.resize(maced.size());
            if (verify_data != maced) {
                ret = errorcode_t::error_verify;
            }

            s->autoindent(1);
            s->printf("> %s\n", constexpr_verify_data);
            dump_memory(verify_data, s, 16, 3, 0x00, dump_notrunc);
            s->printf("  > secret (internal) 0x%08x\n", typeof_secret);
            s->printf("  > verify data %s \n", base16_encode(verify_data).c_str());
            s->printf("  > maced       %s \e[1;33m%s\e[0m\n", base16_encode(maced).c_str(), (errorcode_t::success == ret) ? "true" : "false");
            s->autoindent(0);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
