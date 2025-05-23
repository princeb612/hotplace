/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_certificate.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_request_context_len[] = "request context len";
constexpr char constexpr_request_context[] = "request context";
constexpr char constexpr_certificates_len[] = "certifcates len";
constexpr char constexpr_certificate_len[] = "certifcate len";
constexpr char constexpr_certificate[] = "certifcate";
constexpr char constexpr_group_tls13[] = "tls1.3";
constexpr char constexpr_certificate_extensions_len[] = "certificate extensions len";
constexpr char constexpr_certificate_extensions[] = "certificate extensions";
constexpr char constexpr_record_type[] = "record type";

tls_handshake_certificate::tls_handshake_certificate(tls_session* session) : tls_handshake(tls_hs_certificate, session) {}

return_t tls_handshake_certificate::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto session_status = session->get_session_status();
        uint32 session_status_prerequisite = session_status_client_hello | session_status_server_hello;
        if (protection.is_kindof_tls13()) {
            session_status_prerequisite |= session_status_encrypted_extensions;
        }
        if (session_status_prerequisite != (session_status_prerequisite & session_status)) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_unexpected_message);
            session->reset_session_status();
            ret = errorcode_t::error_handshake;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_certificate::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();
        auto hssize = get_size();

        {
            protection.update_transcript_hash(session, stream + hspos, hssize);
            if (from_server == dir) {
                session->update_session_status(session_status_server_cert);
            } else if (from_client == dir) {
                session->update_session_status(session_status_client_cert);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_certificate::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

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

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        auto& protection = session->get_tls_protection();

        binary_t cert;
        crypto_keychain keychain;
        uint8 request_context_len = 0;
        uint32 certificates_len = 0;
        uint32 certificate_len = 0;
        binary_t cert_extensions;
        uint16 cert_extensions_len = 0;
        {
            payload pl;
            pl << new payload_member(uint8(0), constexpr_request_context_len, constexpr_group_tls13)  // TLS 1.3
               << new payload_member(binary_t(), constexpr_request_context, constexpr_group_tls13)    // TLS 1.3
               << new payload_member(uint24_t(0), constexpr_certificates_len)                         //
               << new payload_member(uint24_t(0), constexpr_certificate_len)                          //
               << new payload_member(binary_t(), constexpr_certificate)                               //
               << new payload_member(uint16(0), true, constexpr_certificate_extensions_len);          //

            pl.set_reference_value(constexpr_certificate, constexpr_certificate_len);
            pl.set_reference_value(constexpr_request_context, constexpr_request_context_len);
            auto tls_version = session->get_tls_protection().get_tls_version();
            pl.set_group(constexpr_group_tls13, tlsadvisor->is_kindof_tls13(tls_version));  // tls1_ext_supported_versions 0x002b server_hello
            pl.read(stream, size, pos);

            request_context_len = pl.t_value_of<uint8>(constexpr_request_context_len);
            certificates_len = pl.t_value_of<uint32>(constexpr_certificates_len);
            certificate_len = pl.t_value_of<uint32>(constexpr_certificate_len);
            pl.get_binary(constexpr_certificate, cert);
            cert_extensions_len = pl.t_value_of<uint16>(constexpr_certificate_extensions_len);
        }

        get_extensions().read(session, dir, stream, pos + cert_extensions_len, pos);

        auto& servercert = protection.get_keyexchange();
        keydesc desc(use_sig);
        if (from_server == dir) {
            desc.set_kid(KID_TLS_SERVER_CERTIFICATE_PUBLIC);
        } else {
            desc.set_kid(KID_TLS_CLIENT_CERTIFICATE_PUBLIC);
        }
        ret = keychain.load_der(&servercert, &cert[0], cert.size(), desc);

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.autoindent(1);
            dbs.println(" > %s %i", constexpr_request_context_len, request_context_len);
            dbs.println(" > %s 0x%04x(%i)", constexpr_certificates_len, certificates_len, certificates_len);
            dbs.println(" > %s 0x%04x(%i)", constexpr_certificate_len, certificate_len, certificate_len);
            dump_memory(cert, &dbs, 16, 3, 0x00, dump_notrunc);
            dbs.println(" > %s 0x%04x(%i)", constexpr_certificate_extensions, cert_extensions_len, cert_extensions_len);
            dump_memory(cert_extensions, &dbs, 16, 3, 0x00, dump_notrunc);
            dump_key(servercert.find(desc.get_kid_cstr()), &dbs, 15, 4, dump_notrunc);
            dbs.autoindent(0);

            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_certificate::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();

        const char* kid = nullptr;
        if (from_server == dir) {
            kid = KID_TLS_SERVER_CERTIFICATE_PUBLIC;
        } else {
            kid = KID_TLS_CLIENT_CERTIFICATE_PUBLIC;
        }

        auto x509 = tlsadvisor->get_cert(session, kid);
        if (nullptr == x509) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_no_certificate);
            session->reset_session_status();
            ret = errorcode_t::error_certificate;
            __leave2;
        }

        binary_t certificate;
        crypto_keychain keychain;
        keychain.write_der(x509, certificate);

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.autoindent(1);
            dbs.println("> %s", constexpr_certificate);
            dump_memory(certificate, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.autoindent(0);

            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif

        {
            auto tls_version = session->get_tls_protection().get_tls_version();
            bool is_tls13 = tlsadvisor->is_kindof_tls13(tls_version);

            binary_t extensions;
            uint32 certificate_len = certificate.size();
            uint32 certificates_len = 3 /* uint24 */ + certificate_len;  // TLS 1.2
            if (is_tls13) {
                certificates_len += sizeof(uint16);
                get_extensions().write(dir, extensions);
            }

            payload pl;
            pl << new payload_member(uint8(0), constexpr_request_context_len, constexpr_group_tls13)                                 // TLS 1.3
               << new payload_member(binary_t(), constexpr_request_context, constexpr_group_tls13)                                   // TLS 1.3
               << new payload_member(uint24_t(certificates_len), constexpr_certificates_len)                                         // certificate + extensions
               << new payload_member(uint24_t(certificate_len), constexpr_certificate_len)                                           // certificate
               << new payload_member(certificate, constexpr_certificate)                                                             // certificate
               << new payload_member(uint16(extensions.size()), true, constexpr_certificate_extensions_len, constexpr_group_tls13);  // extensions

            pl.set_group(constexpr_group_tls13, is_tls13);  // tls1_ext_supported_versions 0x002b server_hello
            pl.write(bin);

            if (is_tls13) {
                binary_append(bin, extensions);
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
