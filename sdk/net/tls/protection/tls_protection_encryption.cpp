/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_encryption.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/cipher_encrypt.hpp>
#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_cbc_hmac.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/asn.1/types.hpp>
#include <hotplace/sdk/net/tls/dtls_record_arrange.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

uint8 tls_protection::get_tag_size() {
    uint8 ret_value = 0;
    crypto_advisor *advisor = crypto_advisor::get_instance();
    tls_advisor *tlsadvisor = tls_advisor::get_instance();
    auto cs = get_cipher_suite();
    auto hint = tlsadvisor->hintof_cipher_suite(cs);
    auto hint_cipher = tlsadvisor->hintof_cipher(cs);
    if (hint && hint_cipher) {
        auto hmac_alg = hint->mac;
        auto hint_digest = advisor->hintof_digest(hmac_alg);

        auto cipher = hint_cipher->algorithm;
        auto mode = hint_cipher->mode;
        auto dlen = sizeof_digest(hint_digest);

        switch (mode) {
            case gcm:
            case mode_poly1305:  // RFC 7905
                ret_value = 16;
                break;
            case ccm:
                /**
                 * RFC 6655 AES-CCM Cipher Suites for Transport Layer Security (TLS)
                 *   3.  RSA-Based AES-CCM Cipher Suites
                 *     AEAD_AES_128_CCM and AEAD_AES_256_CCM described in [RFC5116].
                 *
                 *     Each uses AES-CCM; those that end in "_8" have an 8-octet
                 *     authentication tag, while the other ciphersuites have 16-octet
                 *     authentication tags.
                 *   6.1.  AES-128-CCM with an 8-Octet Integrity Check Value (ICV)
                 *   6.2.  AES-256-CCM with a 8-Octet Integrity Check Value (ICV)
                 *
                 * RFC 5116
                 *   5.3.  AEAD_AES_128_CCM
                 *   5.4.  AEAD_AES_256_CCM
                 */
                ret_value = hint_cipher->tsize;  // CCM (16), CCM_8 (8)
                break;
            default:
                ret_value = t_narrow_cast(dlen);
                break;
        }
    }
    return ret_value;
}

// RFC 2246 6.2.3 Record payload protection
// length of TLSCiphertext.fragment may not exceed 2^14 + 2048
#define TLS_CIPHERTEXT_MAXSIZE ((2 << 14) + 2048)

return_t tls_protection::encrypt(tls_session *session, tls_direction_t dir, const binary_t &plaintext, binary_t &ciphertext, const binary_t &additional, binary_t &tag,
                                 protection_space_t space) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (plaintext.size() > TLS_CIPHERTEXT_MAXSIZE) {
            ret = errorcode_t::exceed;
            __leave2;
        }

        auto record_version = get_lagacy_version();
        size_t content_header_size = 0;
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        auto cs = get_cipher_suite();
        auto is_cbc = tlsadvisor->is_kindof_cbc(cs);

        /**
         * RFC 7366
         * If a server receives an encrypt-then-MAC request extension from a client
         * and then selects a stream or Authenticated Encryption with Associated
         * Data (AEAD) ciphersuite, it MUST NOT send an encrypt-then-MAC
         * response extension back to the client.
         */
        if (is_cbc) {
            ret = encrypt_cbc_hmac(session, dir, plaintext, ciphertext, additional, tag);
        } else {
            ret = encrypt_aead(session, dir, plaintext, ciphertext, additional, tag, space);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::decrypt(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext,
                                 protection_space_t space) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size > TLS_CIPHERTEXT_MAXSIZE) {
            ret = errorcode_t::exceed;
            __leave2;
        }

        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        bool is_kindof_cbc = tlsadvisor->is_kindof_cbc(get_cipher_suite());
        if (is_kindof_cbc) {
            ret = decrypt_cbc_hmac(session, dir, stream, size, pos, plaintext);
        } else {
            ret = decrypt_aead(session, dir, stream, size, pos, plaintext, space);
        }
        if (errorcode_t::success != ret) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_decryption_failed);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::decrypt(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext, binary_t &aad,
                                 protection_space_t space) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto session_type = session->get_type();
        switch (session_type) {
            case session_type_tls:
            case session_type_dtls: {
                tls_advisor *tlsadvisor = tls_advisor::get_instance();
                bool is_kindof_cbc = tlsadvisor->is_kindof_cbc(get_cipher_suite());
                if (is_kindof_cbc) {
                    ret = decrypt_cbc_hmac(session, dir, stream, size, pos, plaintext);
                } else {
                    auto aadlen = aad.size();
                    auto tagsize = get_tag_size();
                    binary_t tag;

                    // ... aad(aadlen) encdata tag(tagsize)
                    //     \_ pos
                    binary_append(tag, stream + size - tagsize, tagsize);
                    ret = decrypt_aead(session, dir, stream, size - tagsize, pos + aadlen, plaintext, aad, tag, space);
                }
                if (errorcode_t::success != ret) {
                    session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_decryption_failed);
                }
            } break;
            case session_type_quic:
            case session_type_quic2: {
                ret = errorcode_t::not_supported;
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::decrypt(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext, const binary_t &aad,
                                 const binary_t &tag, protection_space_t space) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        bool is_kindof_cbc = tlsadvisor->is_kindof_cbc(get_cipher_suite());

        if (is_kindof_cbc) {
            ret = errorcode_t::not_supported;
        } else {
            ret = decrypt_aead(session, dir, stream, size, pos, plaintext, aad, tag, space);
            if (errorcode_t::success != ret) {
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_decryption_failed);
            }
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
