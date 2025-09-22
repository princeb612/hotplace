/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_ec_point_formats.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_key_share.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_psk_key_exchange_modes.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_signature_algorithms.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_groups.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_supported_versions.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_client_hello.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_server_hello.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_composer::construct_client_hello(tls_handshake** handshake, tls_session* session, std::function<return_t(tls_handshake*, tls_direction_t)> hook,
                                              uint16 minspec, uint16 maxspec) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        uint32 session_status = 0;
        auto session_type = session->get_type();
        auto& protection = session->get_tls_protection();
        bool is_dtls = (session_type_dtls == session_type);
        tls_handshake_client_hello* hs = nullptr;
        auto dir = from_client;

        tls_handshake_builder builder;
        *handshake = builder.build(tls_hs_client_hello, session, [&](tls_handshake* h) -> return_t {
            auto hs = (tls_handshake_client_hello*)h;

            // random
            {
                openssl_prng prng;

                binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
                time_t gmt_unix_time = time(nullptr);
                binary_append(random, gmt_unix_time, hton32);
                random.resize(sizeof(uint32));
                binary_t temp;
                prng.random(temp, 28);
                binary_append(random, temp);
                hs->set_random(random);
            }

            // cookie
            {
                session_status = session->get_session_status();
                if (session_status_hello_verify_request & session_status) {
                    const auto& cookie = protection.get_secrets().get(tls_context_cookie);
                    if (false == cookie.empty()) {
                        hs->set_cookie(cookie);
                    }
                }
            }

            {
                // cipher suites
                uint8 mask = tls_flag_secure | tls_flag_support;
                auto lambda_cs = [&](const tls_cipher_suite_t* cs) -> void {
                    if ((mask & cs->flags) && (cs->spec >= minspec) && (cs->spec <= maxspec)) {
                        hs->add_ciphersuite(cs->code);
                    }
                };
                tlsadvisor->enum_cipher_suites(lambda_cs);
            }

            hs->get_extensions()
                .add(tls_ext_ec_point_formats, dir, hs,
                     // ec_point_formats
                     // RFC 9325 4.2.1
                     // Note that [RFC8422] deprecates all but the uncompressed point format.
                     // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element, "uncompressed".
                     [](tls_extension* extension) -> return_t {
                         (*(tls_extension_ec_point_formats*)extension).add("uncompressed");
                         return success;
                     })
                .add(tls_ext_supported_groups, dir, hs,
                     // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
                     [](tls_extension* extension) -> return_t {
                         (*(tls_extension_supported_groups*)extension).add("x25519").add("secp256r1").add("x448").add("secp521r1").add("secp384r1");
                         return success;
                     })
                .add(tls_ext_signature_algorithms, dir, hs, [](tls_extension* extension) -> return_t {
                    (*(tls_extension_signature_algorithms*)extension)
                        .add("ecdsa_secp256r1_sha256")
                        .add("ecdsa_secp384r1_sha384")
                        .add("ecdsa_secp521r1_sha512")
                        .add("ed25519")
                        .add("ed448")
                        .add("rsa_pkcs1_sha256")
                        .add("rsa_pkcs1_sha384")
                        .add("rsa_pkcs1_sha512")
                        .add("rsa_pss_pss_sha256")
                        .add("rsa_pss_pss_sha384")
                        .add("rsa_pss_pss_sha512")
                        .add("rsa_pss_rsae_sha256")
                        .add("rsa_pss_rsae_sha384")
                        .add("rsa_pss_rsae_sha512");
                    return success;
                });

            if (tls_13 == maxspec) {
                // TLS 1.3
                hs->get_extensions()
                    .add(tls_ext_supported_versions, dir, hs,
                         [&](tls_extension* extension) -> return_t {
                             auto sv = (tls_extension_client_supported_versions*)extension;
                             (*sv).add(is_dtls ? dtls_13 : tls_13);
                             if (tls_12 == minspec) {
                                 (*sv).add(is_dtls ? dtls_12 : tls_12);
                             }
                             return success;
                         })
                    .add(tls_ext_psk_key_exchange_modes, dir, hs,
                         [](tls_extension* extension) -> return_t {
                             (*(tls_extension_psk_key_exchange_modes*)extension).add("psk_dhe_ke");
                             return success;
                         })
                    .add(tls_ext_key_share, dir, hs,  //
                         [&](tls_extension* extension) -> return_t {
                             tls_extension_client_key_share* keyshare = (tls_extension_client_key_share*)extension;
                             if (tls_flow_hello_retry_request != protection.get_flow()) {
                                 keyshare->clear();
                                 keyshare->add("x25519");
                             }
                             return success;
                         });
            }

            if (tls_12 == minspec) {
                if (session->get_keyvalue().get(session_conf_enable_encrypt_then_mac)) {
                    hs->get_extensions().add(tls_ext_encrypt_then_mac, dir, hs, nullptr);
                }
            }

            hs->get_extensions()
                .add(tls_ext_session_ticket, dir, hs, nullptr)
                .add(tls_ext_renegotiation_info, dir, hs, nullptr)
                .add(tls_ext_extended_master_secret, dir, hs, nullptr);

            if (hook) {
                ret = hook(hs, from_client);
            }

            return ret;
        });
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::construct_server_hello(tls_handshake** handshake, tls_session* session, std::function<return_t(tls_handshake*, tls_direction_t)> hook,
                                              uint16 minspec, uint16 maxspec) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == handshake || nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        uint16 cs = 0;
        uint16 tlsver = 0;
        auto dir = from_server;
        auto& protection = session->get_tls_protection();
        ret = protection.negotiate(session, minspec, maxspec, cs, tlsver);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        tls_handshake_builder builder;
        *handshake = builder.build(tls_hs_server_hello, session, [&](tls_handshake* h) -> return_t {
            auto hs = (tls_handshake_server_hello*)h;

            hs->set_cipher_suite(cs);

            if (tlsadvisor->is_kindof_tls13(tlsver)) {
                hs->get_extensions()
                    .add(tls_ext_supported_versions, dir, hs,
                         [&](tls_extension* extension) -> return_t {
                             (*(tls_extension_server_supported_versions*)extension).set(tlsver);
                             return success;
                         })
                    .add(tls_ext_key_share, dir, hs,  //
                         [](tls_extension* extension) -> return_t {
                             auto keyshare = (tls_extension_server_key_share*)extension;
                             keyshare->clear();
                             keyshare->add_keyshare();
                             return success;
                         });
            } else {
                hs->get_extensions()
                    .add(tls_ext_renegotiation_info, dir, hs, nullptr)
                    .add(tls_ext_ec_point_formats, dir, hs,
                         [](tls_extension* extension) -> return_t {
                             (*(tls_extension_ec_point_formats*)extension).add("uncompressed");
                             return success;
                         })
                    .add(tls_ext_supported_groups, dir, hs,  //
                         [](tls_extension* extension) -> return_t {
                             (*(tls_extension_supported_groups*)extension).add("x25519");
                             return success;
                         });
            }

            if (hook) {
                ret = hook(hs, from_server);
            }

            return ret;
        });
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
