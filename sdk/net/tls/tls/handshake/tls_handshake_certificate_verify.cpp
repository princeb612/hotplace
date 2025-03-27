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
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_sign.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/transcript_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake_certificate_verify.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_signature_alg[] = "signature algorithm";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_signature[] = "signature";

static return_t construct_certificate_verify_message(tls_session* session, tls_direction_t dir, basic_stream& message);

tls_handshake_certificate_verify::tls_handshake_certificate_verify(tls_session* session) : tls_handshake(tls_hs_certificate_verify, session) {}

return_t tls_handshake_certificate_verify::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        protection.update_transcript_hash(session, stream + hspos, get_size());

        if (from_server == dir) {
            session->update_session_status(session_server_cert_verified);
        }
    }
    __finally2 {
        // do nothing
    }
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

        auto kty = typeof_crypto_key(pkey);
        scheme = protection_context.select_signature_algorithm(kty);

        crypto_sign_builder builder;
        auto sign = builder.set_tls_sign_scheme(scheme).build();
        if (sign) {
            basic_stream tosign;
            construct_certificate_verify_message(session, dir, tosign);

            ret = sign->sign(pkey, tosign.data(), tosign.size(), signature);

            auto kty = typeof_crypto_key(pkey);
            switch (kty) {
                case kty_rsa:
                case kty_okp: {
                } break;
                case kty_ec: {
                    // reform R || S to ASN.1 DER
                    binary_t ecdsa_sig = std::move(signature);
                    sig2der(ecdsa_sig, signature);
                } break;
            }

            sign->release();
        } else {
            ret = errorcode_t::not_supported;
        }
    }
    __finally2 {}

    return ret;
}

return_t tls_handshake_certificate_verify::verify_certverify(const EVP_PKEY* pkey, tls_direction_t dir, uint16 scheme, binary_t& signature) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == pkey) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();

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
        switch (kty) {
            case kty_rsa:
            case kty_okp: {
            } break;
            case kty_ec: {
                crypto_advisor* advisor = crypto_advisor::get_instance();
                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                auto hint = tlsadvisor->hintof_signature_scheme(scheme);
                auto sig = hint->sig;
                uint32 unitsize = 0;

                // B-163, B-233, B-283, B-409, B-571
                // K-163, K-233, B-283, K-409, K-571
                // P-192, P-224, P-256, K-384, K-521
                // secp160r1, secp256k1
                unitsize = advisor->sizeof_ecdsa(sig) >> 1;

                /**
                 * RFC 3279 2.2.3 ECDSA Signature Algorithm
                 * When signing, the ECDSA algorithm generates two values.  These values
                 * are commonly referred to as r and s.  To easily transfer these two
                 * values as one signature, they MUST be ASN.1 encoded using the
                 * following ASN.1 structure:
                 *
                 *    Ecdsa-Sig-Value  ::=  SEQUENCE  {
                 *         r     INTEGER,
                 *         s     INTEGER  }
                 */
                binary_t ecdsa_sig;
                der2sig(signature, unitsize, ecdsa_sig);  // ASN.1 DER to familiar R || S
                signature = std::move(ecdsa_sig);
            } break;
        }

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

            ret = sign->verify(pkey, tosign.data(), tosign.size(), signature);

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

        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();
        {
            // RFC 8446 2.  Protocol Overview
            // CertificateVerify:  A signature over the entire handshake using the
            //    private key corresponding to the public key in the Certificate
            //    message.  This message is omitted if the endpoint is not
            //    authenticating via a certificate.  [Section 4.4.3]

            // RFC 4346 7.4.8. Certificate verify

            tls_advisor* tlsadvisor = tls_advisor::get_instance();

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

            // $ openssl x509 -pubkey -noout -in server.crt > server.pub
            // public key from server certificate or handshake 0x11 certificate
            const char* kid = nullptr;
            if (from_server == dir) {
                kid = KID_TLS_SERVER_CERTIFICATE_PUBLIC;  // Server Certificate
            } else {
                kid = KID_TLS_CLIENT_CERTIFICATE_PUBLIC;  // Client Certificate (Client Authentication, optional)
            }
            crypto_key& key = protection.get_keyexchange();
            auto pkey = key.find(kid);

            ret = verify_certverify(pkey, dir, scheme, signature);

#if defined DEBUG
            if (istraceable()) {
                basic_stream dbs;
                dbs.autoindent(1);
                dbs.println(" > %s 0x%04x %s", constexpr_signature_alg, scheme, tlsadvisor->signature_scheme_name(scheme).c_str());
                dbs.println(" > %s 0x%04x(%i)", constexpr_len, len, len);
                // dbs.println(" > tosign");
                // dump_memory(tosign, &dbs, 16, 3, 0x00, dump_notrunc);
                dbs.println(" > %s \e[1;33m%s\e[0m", constexpr_signature, (errorcode_t::success == ret) ? "true" : "false");
                dump_memory(signature, &dbs, 16, 3, 0x00, dump_notrunc);
                dbs.autoindent(0);

                trace_debug_event(category_net, net_event_tls_read, &dbs);
            }
#endif
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_certificate_verify::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();
        auto& protection_context = protection.get_protection_context();

        const char* kid = nullptr;  // Private Key
        if (from_server == dir) {
            kid = KID_TLS_SERVER_CERTIFICATE_PRIVATE;
        } else {
            kid = KID_TLS_CLIENT_CERTIFICATE_PRIVATE;
        }

        crypto_key& key = protection.get_keyexchange();
        auto pkey = key.find(kid);

        if (nullptr == pkey) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_no_certificate);
            ret = error_certificate;
            __leave2;
        }

        uint16 scheme = 0;
        binary_t signature;
        ret = sign_certverify(pkey, dir, scheme, signature);

        payload pl;
        pl << new payload_member(uint16(scheme), true, constexpr_signature_alg) << new payload_member(uint16(signature.size()), true, constexpr_len)
           << new payload_member(signature, constexpr_signature);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

static return_t construct_certificate_verify_message(tls_session* session, tls_direction_t dir, basic_stream& message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

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
