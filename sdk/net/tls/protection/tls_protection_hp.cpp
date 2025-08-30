/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          DTLS 1.3 ciphertext header protection
 *          QUIC header protection
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/cipher_encrypt.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_cbc_hmac.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_protection::get_protection_mask_key(tls_session *session, tls_direction_t dir, protection_space_t space, tls_secret_t &secret_key) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session_type = session->get_type();
        auto hsstatus = session->get_session_info(dir).get_status();

        switch (session_type) {
            case session_type_tls:
            case session_type_dtls: {
                if (is_kindof_dtls()) {
                    if (is_serverinitiated(dir)) {
                        if (tls_hs_finished == hsstatus) {
                            secret_key = tls_secret_application_server_sn_key;
                        } else {
                            secret_key = tls_secret_handshake_server_sn_key;
                        }
                    } else if (is_clientinitiated(dir)) {
                        if (tls_hs_finished == hsstatus) {
                            secret_key = tls_secret_application_client_sn_key;
                        } else {
                            secret_key = tls_secret_handshake_client_sn_key;
                        }
                    }
                }
            } break;
            case session_type_quic:
            case session_type_quic2: {
                if (protection_initial == space) {
                    if (is_serverinitiated(dir)) {
                        secret_key = tls_secret_initial_quic_server_hp;
                    } else if (is_clientinitiated(dir)) {
                        secret_key = tls_secret_initial_quic_client_hp;
                    }
                } else if (protection_handshake == space) {
                    if (is_serverinitiated(dir)) {
                        secret_key = tls_secret_handshake_quic_server_hp;
                    } else if (is_clientinitiated(dir)) {
                        secret_key = tls_secret_handshake_quic_client_hp;
                    }
                } else if (protection_application == space) {
                    if (is_serverinitiated(dir)) {
                        secret_key = tls_secret_application_quic_server_hp;
                    } else if (is_clientinitiated(dir)) {
                        secret_key = tls_secret_application_quic_client_hp;
                    }
                } else {
                    ret = errorcode_t::not_supported;
                }
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::protection_mask(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, binary_t &mask, size_t masklen,
                                         protection_space_t space) {
    return_t ret = errorcode_t::success;
    cipher_encrypt *cipher = nullptr;

    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor *advisor = crypto_advisor::get_instance();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        auto alg = aes128;  // DTLS, QUIC initial

        // QUIC handshake, application
        if (space == protection_handshake || space == protection_application) {
            auto cs = get_cipher_suite();
            auto hint_cs = tlsadvisor->hintof_cipher_suite(cs);
            auto hint_cipher = advisor->hintof_blockcipher(hint_cs->scheme);
            alg = hint_cipher->algorithm;
        }

        auto hint = advisor->hintof_blockcipher(alg);
        uint16 blocksize = sizeof_block(hint);
        if (masklen > blocksize) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // aes-128-ebc-encrypt

        uint16 recno = 0;
        uint16 rec_enc = 0;
        tls_secret_t secret_key;

        {
            get_protection_mask_key(session, dir, space, secret_key);

            cipher_encrypt_builder builder;
            cipher = builder.set(alg, ecb).build();
            if (cipher) {
                const auto &key = get_secrets().get(secret_key);
                auto samplesize = (size > blocksize) ? blocksize : size;
                ret = cipher->encrypt(key, binary_t(), stream, samplesize, mask);

                mask.resize(masklen);

#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    basic_stream dbs;
                    dbs.println("> protection");
                    dbs.println(" > key[%08x] %s (%s)", secret_key, base16_encode(key).c_str(), tlsadvisor->nameof_secret(secret_key).c_str());
                    dbs.println(" > sample %s", base16_encode(stream, samplesize).c_str());
                    dbs.println(" > mask %s", base16_encode(mask).c_str());
                    trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
                }
#endif
            }
        }
    }
    __finally2 {
        if (cipher) {
            cipher->release();
        }
    }

    return ret;
}

}  // namespace net
}  // namespace hotplace
