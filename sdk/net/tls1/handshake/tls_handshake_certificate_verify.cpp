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
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/crypto/crypto/transcript_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/handshake/tls_handshake_certificate_verify.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_handshake_certificate_verify::tls_handshake_certificate_verify(tls_session* session) : tls_handshake(tls_hs_certificate_verify, session) {}

return_t tls_handshake_certificate_verify::do_postprocess(tls_direction_t dir, const byte_t* stream, size_t size, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }
        auto hspos = offsetof_header();
        auto& protection = session->get_tls_protection();

        protection.calc_transcript_hash(session, stream + hspos, get_size());
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
            ret = errorcode_t::success;
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
            ret = errorcode_t::success;
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

return_t tls_handshake_certificate_verify::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
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
            // CertificateVerify:  A signature over the entire handshake using the
            //    private key corresponding to the public key in the Certificate
            //    message.  This message is omitted if the endpoint is not
            //    authenticating via a certificate.  [Section 4.4.3]

            // RFC 4346 7.4.8. Certificate verify

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
            if (from_server == dir) {
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
                if (from_server == dir) {
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
                ret = errorcode_t::success;
            }

            if (debugstream) {
                debugstream->autoindent(1);
                debugstream->printf(" > %s 0x%04x %s\n", constexpr_signature_alg, scheme, tlsadvisor->signature_scheme_name(scheme).c_str());
                debugstream->printf(" > %s 0x%04x(%i)\n", constexpr_len, len, len);
                debugstream->printf(" > transcript-hash\n");
                dump_memory(transcripthash, debugstream, 16, 3, 0x00, dump_notrunc);
                debugstream->printf(" > tosign\n");
                dump_memory(tosign, debugstream, 16, 3, 0x00, dump_notrunc);
                debugstream->printf(" > %s \e[1;33m%s\e[0m\n", constexpr_signature, (errorcode_t::success == ret) ? "true" : "false");
                dump_memory(signature, debugstream, 16, 3, 0x00, dump_notrunc);
                if (ecdsa_sig.size()) {
                    debugstream->printf(" > ecdsa r\n");
                    dump_memory(ecdsa_sig_r, debugstream, 16, 3, 0x00, dump_notrunc);
                    debugstream->printf(" > ecdsa s\n");
                    dump_memory(ecdsa_sig_s, debugstream, 16, 3, 0x00, dump_notrunc);
                }
                debugstream->autoindent(0);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_certificate_verify::do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
