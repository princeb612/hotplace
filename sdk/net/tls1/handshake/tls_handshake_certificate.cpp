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
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_certificate.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_request_context_len[] = "request context len";
constexpr char constexpr_request_context[] = "request context";
constexpr char constexpr_certificates_len[] = "certifcates len";
constexpr char constexpr_certificate_len[] = "certifcate len";
constexpr char constexpr_certificate[] = "certifcate";
constexpr char constexpr_group_tls13[] = "tls1.3";
constexpr char constexpr_certificate_extensions[] = "certificate extensions";
constexpr char constexpr_record_type[] = "record type";

tls_handshake_certificate::tls_handshake_certificate(tls_session* session) : tls_handshake(tls_hs_certificate, session) {}

return_t tls_handshake_certificate::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        {
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
                pl.set_group(constexpr_group_tls13, is_basedon_tls13(tls_version));  // tls1_ext_supported_versions 0x002b server_hello
                pl.read(stream, size, pos);

                request_context_len = pl.t_value_of<uint8>(constexpr_request_context_len);
                certificates_len = pl.t_value_of<uint32>(constexpr_certificates_len);
                certificate_len = pl.t_value_of<uint32>(constexpr_certificate_len);
                pl.get_binary(constexpr_certificate, cert);
            }

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

            if (debugstream) {
                debugstream->autoindent(1);
                debugstream->printf(" > %s %i\n", constexpr_request_context_len, request_context_len);
                debugstream->printf(" > %s 0x%04x(%i)\n", constexpr_certificates_len, certificates_len, certificates_len);
                debugstream->printf(" > %s 0x%04x(%i)\n", constexpr_certificate_len, certificate_len, certificate_len);
                dump_memory(cert, debugstream, 16, 3, 0x00, dump_notrunc);
                debugstream->printf(" > %s\n", constexpr_certificate_extensions);
                dump_memory(cert_extensions, debugstream, 16, 3, 0x00, dump_notrunc);
                debugstream->printf(" > %s 0x%02x (%s)\n", constexpr_record_type, record_type, tlsadvisor->content_type_string(record_type).c_str());
                debugstream->autoindent(0);
            }

            auto& servercert = session->get_tls_protection().get_keyexchange();
            keydesc desc(use_sig);
            if (from_server == dir) {
                desc.set_kid("SC");
            } else {
                desc.set_kid("CC");
            }
            ret = keychain.load_der(&servercert, &cert[0], cert.size(), desc);
            if (errorcode_t::success == ret) {
                if (debugstream) {
                    dump_key(servercert.find(desc.get_kid_cstr()), debugstream, 15, 4, dump_notrunc);
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_certificate::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = offsetof_header();
        auto hdrsize = get_header_size();
        auto& protection = session->get_tls_protection();

        protection.calc_transcript_hash(session, stream + hspos, hdrsize);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_certificate::do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
