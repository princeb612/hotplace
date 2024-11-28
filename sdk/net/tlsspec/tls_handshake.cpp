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
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tlsspec/tlsspec.hpp>

namespace hotplace {
namespace net {

// step.1 ... understanding TLS Handshake

static return_t tls_dump_client_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_server_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_encrypted_extensions(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_certificate(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_certificate_verify(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
static return_t tls_dump_finished(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);

return_t tls_dump_handshake(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size < 4) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        // RFC 8446
        //  5.1.  Record Layer
        //  5.2.  Record Payload Protection

        tls_handshake_t* handshake = (tls_handshake_t*)stream;
        uint32 length = 0;
        b24_i32(handshake->length, length);
        if (size < 4 + length) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        auto type = handshake->msg_type;
        tls_advisor* advisor = tls_advisor::get_instance();

        s->autoindent(3);
        s->printf(" > handshake type %i(%02x) (%s)\n", type, type, advisor->handshake_type_string(type).c_str());
        s->autoindent(0);
        s->printf(" > length 0x%04x(%i)\n", length, length);

        pos += sizeof(tls_handshake_t);

        binary_t handshake_hash;
        auto lambda_do_transcript_hash = [&](tls_session* session, const byte_t* stream, size_t size, binary_t& digest) -> void {
            auto& protection = session->get_tls_protection();
            auto hash = protection.get_transcript_hash();
            hash->digest(stream, size, digest);

            s->printf("\e[1;35m> transcript hash\e[0m\n");
            s->printf("  %s\n", base16_encode(digest).c_str());
            s->printf("\e[1;35m  > input stream\e[0m\n");
            dump_memory(stream, size, s, 16, 6, 0, dump_notrunc);
            s->printf("\n");
        };

        switch (handshake->msg_type) {
            case tls_handshake_client_hello: /* 1 */ {
                ret = tls_dump_client_hello(s, session, stream, size, pos);
                // cipher_suite not selected yet
                // client_hello excluding 5-byte record headers
                session->set(session_item_t::item_client_hello, stream, size);  // temporary
            } break;
            case tls_handshake_server_hello: /* 2 */ {
                ret = tls_dump_server_hello(s, session, stream, size, pos);

                auto& protection = session->get_tls_protection();
                auto hash = protection.begin_transcript_hash();
                const binary_t& client_hello = session->get(session_item_t::item_client_hello);
                binary_t hello_hash;

                // hello_hash = hash(client_hello + server_hello)
                lambda_do_transcript_hash(session, &client_hello[0], client_hello.size(), handshake_hash);
                // server_hello excluding 5-byte record headers
                lambda_do_transcript_hash(session, stream, size, hello_hash);
                protection.set_item(tls_secret_hello_hash, hello_hash);

                session->erase(session_item_t::item_client_hello);
            } break;
            case tls_handshake_new_session_ticket: /* 4 */ {
                //
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

                // excluding 1-byte wrapped record trailers
                lambda_do_transcript_hash(session, stream, size - 1, handshake_hash);
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

                // excluding 1-byte wrapped record trailers
                lambda_do_transcript_hash(session, stream, size - 1, handshake_hash);
            } break;
            case tls_handshake_certificate_request: /* 13 */ {
                // RFC 4346 7.4.4. Certificate request
            } break;
            case tls_handshake_certificate_verify: /* 15 */ {
                // RFC 4346 7.4.8. Certificate verify
                ret = tls_dump_certificate_verify(s, session, stream, size, pos);

                lambda_do_transcript_hash(session, stream, size - 1, handshake_hash);
            } break;
            case tls_handshake_finished: /* 20 */ {
                ret = tls_dump_finished(s, session, stream, size, pos);
            } break;
            case tls_handshake_key_update: /* 24 */ {
                //
            } break;
            case tls_handshake_message_hash: /* 254 */ {
                //
            } break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_client_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
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
            payload plver;
            plver << new payload_member(uint16(0), true, constexpr_version);
            plver.read(stream, size, pos);

            version = t_to_int<uint16>(plver.select(constexpr_version));

            if (version < 0x0303) {
                // RFC 8996
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }

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

        binary_t random;
        binary_t session_id;
        binary_t cipher_suite;
        binary_t compression_method;
        pl.select(constexpr_random)->get_variant().to_binary(random);
        uint8 session_ids = t_to_int<uint8>(pl.select(constexpr_session_ids));
        pl.select(constexpr_session_id)->get_variant().to_binary(session_id);
        uint16 cipher_suites = t_to_int<uint16>(pl.select(constexpr_cipher_suites)) >> 1;  // bytes / sizeof(uint16)
        pl.select(constexpr_cipher_suite)->get_variant().to_binary(cipher_suite);
        uint8 compression_methods = t_to_int<uint8>(pl.select(constexpr_compression_methods));
        pl.select(constexpr_compression_method)->get_variant().to_binary(compression_method);
        uint8 extension_len = t_to_int<uint16>(pl.select(constexpr_extensions));

        s->autoindent(4);
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

        while (errorcode_t::success == tls_dump_extension(s, session, stream, size, pos)) {
        };
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_server_hello(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
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
            payload plver;
            plver << new payload_member(uint16(0), true, constexpr_version);
            plver.read(stream, size, pos);

            version = t_to_int<uint16>(plver.select(constexpr_version));

            if (version < 0x0303) {
                // RFC 8996
                // TLS 1.0, 1.1
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }

        payload pl;
        pl << new payload_member(binary_t(), constexpr_random) << new payload_member(uint8(0), constexpr_session_ids)
           << new payload_member(binary_t(), constexpr_session_id) << new payload_member(uint16(0), true, constexpr_cipher_suite)
           << new payload_member(uint8(0), constexpr_compression_method) << new payload_member(uint16(0), true, constexpr_extensions);

        pl.select(constexpr_random)->reserve(32);
        pl.set_reference_value(constexpr_session_id, constexpr_session_ids);
        pl.read(stream, size, pos);

        binary_t random;
        binary_t session_id;
        pl.select(constexpr_random)->get_variant().to_binary(random);
        uint8 session_ids = t_to_int<uint8>(pl.select(constexpr_session_ids));
        pl.select(constexpr_session_id)->get_variant().to_binary(session_id);
        uint16 cipher_suite = t_to_int<uint16>(pl.select(constexpr_cipher_suite));
        uint8 compression_method = t_to_int<uint8>(pl.select(constexpr_compression_method));
        uint8 extension_len = t_to_int<uint16>(pl.select(constexpr_extensions));

        s->autoindent(4);
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

        while (errorcode_t::success == tls_dump_extension(s, session, stream, size, pos)) {
        };

        // cipher_suite
        session->get_tls_protection().set_cipher_suite(cipher_suite);
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

        s->autoindent(4);

        constexpr char constexpr_request_context_len[] = "request context len";
        constexpr char constexpr_request_context[] = "request context";
        constexpr char constexpr_certificates_len[] = "certifcates len";
        constexpr char constexpr_certificate_len[] = "certifcate len";
        constexpr char constexpr_certificate[] = "certifcate";
        payload pl;
        pl << new payload_member(uint8(0), constexpr_request_context_len) << new payload_member(binary_t(), constexpr_request_context)
           << new payload_member(uint32_24_t(), constexpr_certificates_len) << new payload_member(uint32_24_t(), constexpr_certificate_len)
           << new payload_member(binary_t(), constexpr_certificate);
        pl.set_reference_value(constexpr_certificate, constexpr_certificate_len);
        pl.set_reference_value(constexpr_request_context, constexpr_request_context_len);
        pl.read(stream, size, pos);

        auto request_context_len = t_to_int<uint8>(pl.select(constexpr_request_context_len));
        auto certificates_len = t_to_int<uint32>(pl.select(constexpr_certificates_len));
        auto certificate_len = t_to_int<uint32>(pl.select(constexpr_certificate_len));
        binary_t cert;
        pl.select(constexpr_certificate)->get_variant().to_binary(cert);

        constexpr char constexpr_certificate_extensions[] = "certificate extensions";
        constexpr char constexpr_record_type[] = "record type";
        payload plext;
        plext << new payload_member(binary_t(), constexpr_certificate_extensions) << new payload_member(uint8(0), constexpr_record_type);
        plext.select(constexpr_certificate_extensions)->reserve(certificates_len - certificate_len - sizeof(uint24_t));
        plext.read(stream, size, pos);

        binary_t cert_extensions;
        plext.select(constexpr_certificate_extensions)->get_variant().to_binary(cert_extensions);
        auto record_type = t_to_int<uint8>(plext.select(constexpr_record_type));

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

        // certificate (DER, public key)
        if (0) {
            X509* x509 = nullptr;
            BIO* bio = BIO_new(BIO_s_mem());
            BIO_write(bio, &cert[0], cert.size());
            const byte_t* p = &cert[0];
            x509 = d2i_X509(nullptr, &p, cert.size());
            EVP_PKEY* pkey = X509_get_pubkey(x509);

            dump_key(pkey, s, 15, 4, dump_notrunc);

            BIO_free(bio);
            EVP_PKEY_free(pkey);
            X509_free(x509);
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

        payload pl;
        pl << new payload_member(uint16(0), true, constexpr_signature) << new payload_member(uint16(0), true, constexpr_len)
           << new payload_member(binary_t(), constexpr_handshake_hash) << new payload_member(uint8(0), constexpr_record);
        pl.set_reference_value(constexpr_handshake_hash, constexpr_len);
        pl.read(stream, size, pos);

        auto scheme = t_to_int<uint16>(pl.select(constexpr_signature));
        auto len = t_to_int<uint16>(pl.select(constexpr_len));
        binary_t handshake_hash;
        pl.select(constexpr_handshake_hash)->get_variant().to_binary(handshake_hash);
        auto record = t_to_int<uint8>(pl.select(constexpr_record));

        s->autoindent(4);
        s->printf(" > %s 0x%04x %s\n", constexpr_signature, scheme, advisor->signature_scheme_string(scheme).c_str());
        s->printf(" > %s 0x%04x(%i)\n", constexpr_len, len, len);
        s->printf(" > %s\n", constexpr_handshake_hash);
        dump_memory(handshake_hash, s, 16, 3, 0x00, dump_notrunc);
        s->printf("\n");
        s->autoindent(0);
        s->printf(" > %s %02x\n", constexpr_record, record);

        // tls_protection& protection = session->get_tls_protection();
        // ret = protection.certificate_verify(session, scheme, handshake_hash);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_dump_finished(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // tls_advisor* advisor = tls_advisor::get_instance();

        constexpr char constexpr_verify_data[] = "verify data";
        constexpr char constexpr_record[] = "record";

        payload pl;
        pl << new payload_member(binary_t(), constexpr_verify_data) << new payload_member(uint8(0), constexpr_record);
        pl.read(stream, size, pos);

        binary_t verify_data;
        pl.select(constexpr_verify_data)->get_variant().to_binary(verify_data);
        uint8 record = t_to_int<uint8>(pl.select(constexpr_record));

        s->autoindent(4);
        s->printf("> %s\n", constexpr_verify_data);
        dump_memory(verify_data, s, 16, 3, 0x00, dump_notrunc);
        s->printf("\n");
        s->printf("> %s %02x", constexpr_record, record);
        s->autoindent(0);
        s->printf("\n");

        {
            // https://tls13.xargs.org/#server-handshake-finished/annotated
            //
            // finished_key = HKDF-Expand-Label(key: server_secret, label: "finished", ctx: "", len: 48)
            // finished_hash = SHA384(Client Hello ... Server Cert Verify)
            // verify_data = HMAC-SHA384(key: finished_key, msg: finished_hash)
            //
            // ### excluding 5-byte record headers or 1-byte wrapped record trailers
            // $ fin_hash=$((
            //     tail -c +6 clienthello;
            //     tail -c +6 serverhello;
            //     perl -pe 's/.$// if eof' serverextensions;
            //     perl -pe 's/.$// if eof' servercert;
            //     perl -pe 's/.$// if eof' servercertverify) | openssl sha384)
            // $ sht_secret=23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622 (secret_handshake_server)
            // $ fin_key=$(./hkdf-384 expandlabel $sht_secret "finished" "" 48)
            // $ echo $fin_hash | xxd -r -p \
            //     | openssl dgst -sha384 -mac HMAC -macopt hexkey:$fin_key
            auto& protection = session->get_tls_protection();
            auto hash = protection.get_transcript_hash();
            binary_t fin_hash;
            hash->digest(stream, size, fin_hash);

            crypto_advisor* advisor = crypto_advisor::get_instance();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            const tls_alg_info_t* hint_tls_alg = tlsadvisor->hintof_tls_algorithm(protection.get_cipher_suite());
            // const hint_blockcipher_t* hint_cipher = advisor->hintof_blockcipher(hint_tls_alg->cipher);
            const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);

            // auto keysize = hint_cipher->keysize;
            auto dlen = hint_mac->digest_size;

            const binary_t& sht_secret = protection.get_item(tls_secret_handshake_server);
            hash_algorithm_t hashalg = tlsadvisor->hash_alg_of(protection.get_cipher_suite());
            binary_t fin_key;
            openssl_kdf kdf;
            binary_t context;
            kdf.hkdf_expand_label(fin_key, hashalg, dlen, sht_secret, str2bin("finished"), context);

            s->printf("sht_secret\n");
            dump_memory(sht_secret, s, 16, 3, 0x00, dump_notrunc);
            s->printf("\n");
            s->printf("fin_key\n");
            dump_memory(fin_key, s, 16, 3, 0x00, dump_notrunc);
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
