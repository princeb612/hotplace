/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>
#include <hotplace/sdk/crypto/basic/evp_key.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_certificate_verify.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_signature_alg[] = "signature algorithm";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_signature[] = "signature";

static return_t construct_certificate_verify_message(tls_session* session, tls_direction_t dir, basic_stream& message);

tls_handshake_certificate_verify::tls_handshake_certificate_verify(tls_session* session) : tls_handshake(tls_hs_certificate_verify, session) {}

tls_handshake_certificate_verify::~tls_handshake_certificate_verify() {}

return_t tls_handshake_certificate_verify::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto session_status = session->get_session_status();
        uint32 session_status_prerequisite = 0;
        if (from_client == dir) {
            session_status_prerequisite = session_status_client_cert;
        } else {
            session_status_prerequisite = session_status_server_cert;
        }
        if (session_status_prerequisite != (session_status_prerequisite & session_status)) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_certificate_required);
            session->reset_session_status();
            ret = errorcode_t::error_handshake;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_certificate_verify::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        protection.update_transcript_hash(session, stream + hspos, get_size());

        if (from_client == dir) {
            session->update_session_status(session_status_client_cert_verified);
        } else {
            session->update_session_status(session_status_server_cert_verified);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_certificate_verify::sign_certverify(const EVP_PKEY* pkey, tls_direction_t dir, uint16& scheme, binary_t& signature) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();
        auto& protection_context = protection.get_protection_context();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        auto kty = ktyof_evp_pkey(pkey);
        scheme = protection_context.select_signature_algorithm(kty);

        crypto_sign_builder builder;
        auto sign = builder.set_tls_sign_scheme(scheme).build();
        if (sign) {
            basic_stream tosign;
            construct_certificate_verify_message(session, dir, tosign);

            ret = sign->sign(pkey, tosign.data(), tosign.size(), signature, sign_flag_format_der);

            sign->release();
        } else {
            ret = errorcode_t::not_supported;
        }
    }
    __finally2 {}

    return ret;
}

return_t tls_handshake_certificate_verify::verify_certverify(const EVP_PKEY* pkey, tls_direction_t dir, uint16 scheme, const binary_t& signature) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();

        crypto_sign_builder builder;
        auto sign = builder.set_tls_sign_scheme(scheme).build();
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

            basic_stream tosign;
            construct_certificate_verify_message(session, dir, tosign);

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
             *
             * RFC 3279 2.2.3 ECDSA Signature Algorithm
             *   When signing, the ECDSA algorithm generates two values.  These values
             *   are commonly referred to as r and s.  To easily transfer these two
             *   values as one signature, they MUST be ASN.1 encoded using the
             *   following ASN.1 structure:
             *
             *      Ecdsa-Sig-Value  ::=  SEQUENCE  {
             *           r     INTEGER,
             *           s     INTEGER  }
             */

            auto msgdata = tosign.data();
            auto msgsize = tosign.size();
            ret = sign->verify(pkey, msgdata, msgsize, signature, sign_flag_format_der);

            sign->release();
        } else {
            ret = errorcode_t::not_supported;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_certificate_verify::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // RFC 8446 2.  Protocol Overview
        // CertificateVerify:  A signature over the entire handshake using the
        //    private key corresponding to the public key in the Certificate
        //    message.  This message is omitted if the endpoint is not
        //    authenticating via a certificate.  [Section 4.4.3]

        // RFC 4346 7.4.8. Certificate verify

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();

        uint16 scheme = 0;
        uint16 len = 0;
        binary_t signature;
        {
            payload pl;
            pl << new payload_member(uint16(0), true, constexpr_signature_alg)  //
               << new payload_member(uint16(0), true, constexpr_len)            //
               << new payload_member(binary_t(), constexpr_signature);
            pl.set_reference_value(constexpr_signature, constexpr_len);
            pl.read(stream, size, pos);

            scheme = pl.t_value_of<uint16>(constexpr_signature_alg);
            len = pl.t_value_of<uint16>(constexpr_len);
            pl.get_binary(constexpr_signature, signature);
        }

        // $ openssl x509 -pubkey -noout -in server.crt > server.pub
        // public key from server certificate or handshake 0x11 certificate
        const char* kid = nullptr;
        if (from_server == dir) {
            kid = KID_TLS_SERVER_CERTIFICATE_PUBLIC;  // Server Certificate
        } else {
            kid = KID_TLS_CLIENT_CERTIFICATE_PUBLIC;  // Client Certificate (Client Authentication, optional)
        }

        auto pkey = tlsadvisor->get_key(session, kid);

        ret = verify_certverify(pkey, dir, scheme, signature);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.autoindent(1);
            dbs.println(" > %s 0x%04x %s", constexpr_signature_alg, scheme, tlsadvisor->signature_scheme_name(scheme).c_str());
            dbs.println(" > %s 0x%04x(%i)", constexpr_len, len, len);
            // dbs.println(" > tosign");
            // dump_memory(tosign, &dbs, 16, 3, 0x00, dump_notrunc);
            dbs.println(" > %s \e[1;33m%s\e[0m", constexpr_signature, (errorcode_t::success == ret) ? "true" : "false");
            if (check_trace_level(loglevel_debug)) {
                dump_memory(signature, &dbs, 16, 3, 0x00, dump_notrunc);
            }
            dbs.autoindent(0);

            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_handshake_certificate_verify::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();
        auto& protection_context = protection.get_protection_context();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        const char* kid = nullptr;  // Private Key
        if (from_server == dir) {
            kid = KID_TLS_SERVER_CERTIFICATE_PRIVATE;
        } else {
            kid = KID_TLS_CLIENT_CERTIFICATE_PRIVATE;
        }

        auto pkey = tlsadvisor->get_key(session, kid);
        if (nullptr == pkey) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_no_certificate);
            session->reset_session_status();
            ret = errorcode_t::error_certificate;
            __leave2;
        }

        uint16 scheme = 0;
        binary_t signature;
        ret = sign_certverify(pkey, dir, scheme, signature);

        payload pl;
        pl << new payload_member(uint16(scheme), true, constexpr_signature_alg)  //
           << new payload_member(uint16(signature.size()), true, constexpr_len)  //
           << new payload_member(signature, constexpr_signature);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

static return_t construct_certificate_verify_message(tls_session* session, tls_direction_t dir, basic_stream& message) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto& protection = session->get_tls_protection();

        binary_t transcripthash;
        auto hash = protection.get_transcript_hash();  // hash(client_hello .. certificate)
        if (hash) {
            hash->digest(transcripthash);
            hash->release();
        }

        constexpr char constexpr_context_server[] = "TLS 1.3, server CertificateVerify";
        constexpr char constexpr_context_client[] = "TLS 1.3, client CertificateVerify";
        message.fill(64, 0x20);  // octet 32 (0x20) repeated 64 times
        if (from_server == dir) {
            message << constexpr_context_server;  // context string
        } else {
            message << constexpr_context_client;
        }
        message.fill(1, 0x00);                                     // single 0 byte
        message.write(&transcripthash[0], transcripthash.size());  // content to be signed
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
