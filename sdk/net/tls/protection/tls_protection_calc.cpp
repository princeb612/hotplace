/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_calc.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_aead.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hmac.hpp>
#include <hotplace/sdk/crypto/basic/evp_pkey.hpp>
#include <hotplace/sdk/crypto/basic/openssl_ecdh.hpp>
#include <hotplace/sdk/crypto/basic/openssl_hash.hpp>
#include <hotplace/sdk/crypto/basic/openssl_kdf.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/sslkeylog_exporter.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_quic_key[] = "quic key";
constexpr char constexpr_quic_iv[] = "quic iv";
constexpr char constexpr_quic_hp[] = "quic hp";
constexpr char constexpr_quic2_key[] = "quicv2 key";
constexpr char constexpr_quic2_iv[] = "quicv2 iv";
constexpr char constexpr_quic2_hp[] = "quicv2 hp";

return_t tls_protection::calc(tls_session* session, tls_handshake_type_t type, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    // RFC 8446 7.1.  Key Schedule
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session_type = session->get_type();
        auto flow = get_flow();
        tls_resumption_ticket early_data_ticket = session->get_early_data_ticket();
        bool use_early_data_ticket_parameters = (tls_flow_t::zero_rtt == flow) && (false == early_data_ticket.identity.empty()) &&
                                                (early_data_ticket.version == static_cast<uint16>(tls1_3)) && (0 != early_data_ticket.cipher_suite) &&
                                                (0 != early_data_ticket.max_early_data_size);
        // A fresh connection has no negotiated version yet. Early traffic
        // keys use the version and cipher suite bound to identity zero's PSK;
        // do not write those provisional parameters into _version.
        uint16 cipher_suite = use_early_data_ticket_parameters ? early_data_ticket.cipher_suite : get_cipher_suite();
        bool tls13_key_schedule = is_kindof_tls13() || use_early_data_ticket_parameters;

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        const char* label_quic_key = nullptr;
        const char* label_quic_iv = nullptr;
        const char* label_quic_hp = nullptr;

        if ((session_type_t::quic == session_type) || (session_type_t::quic2 == session_type)) {
            if (0 == cipher_suite) {
                cipher_suite = 0x1301;  // TLS_AES_128_GCM_SHA256
            }

            if (session_type_t::quic == session_type) {
                label_quic_key = constexpr_quic_key;
                label_quic_iv = constexpr_quic_iv;
                label_quic_hp = constexpr_quic_hp;
            } else {
                label_quic_key = constexpr_quic2_key;
                label_quic_iv = constexpr_quic2_iv;
                label_quic_hp = constexpr_quic2_hp;
            }
        }

        const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(cipher_suite);
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        const hint_blockcipher_t* hint_blockcipher = tlsadvisor->hintof_blockcipher(cipher_suite);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
        if (nullptr == hint_mac) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto keysize = hint_blockcipher->keysize;
        auto dlen = hint_mac->digest_size;
        auto hashalg = hint_mac->fetchname;

        openssl_kdf kdf;
        binary_t empty;      // empty
        binary_t empty_ikm;  // dlen 00..
        binary_t empty_hash;
        empty_hash = get_secrets().get(tls_secret_t::empty_hash);
        if (empty_hash.empty()) {
            openssl_digest dgst;
            ret = dgst.digest(hashalg, empty, empty_hash);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
        }
        empty_ikm.resize(dlen);

        auto lambda_expand_label = [this, &kdf](tls_secret_t sec, binary_t& okm, const char* hashalg, uint16 dlen, const binary_t& secret, const char* label,
                                                const binary_t& context) -> return_t {
            okm.clear();
            return_t result = is_kindof_dtls() ? kdf.hkdf_expand_dtls13_label(okm, hashalg, dlen, secret, label, context)
                                               : kdf.hkdf_expand_tls13_label(okm, hashalg, dlen, secret, label, context);
            if (errorcode_t::success != result) {
                okm.clear();
                get_secrets().assign(sec, binary_t());
                return result;
            }
            get_secrets().assign(sec, okm);  // copy
            return result;
        };
        auto lambda_extract = [this, &kdf](tls_secret_t sec, binary_t& prk, const char* hashalg, const binary_t& salt, const binary_t& ikm) -> return_t {
            prk.clear();
            return_t result = kdf.hmac_kdf_extract(prk, hashalg, salt, ikm);
            if (errorcode_t::success != result) {
                prk.clear();
                get_secrets().assign(sec, binary_t());
                return result;
            }
            get_secrets().assign(sec, prk);  // copy
            return result;
        };

        bool cond_trhash = true;
        if (tls_handshake_type_t::client_hello == type) {
            if ((session_type_t::quic == session_type) || (session_type_t::quic2 == session_type)) {
                cond_trhash = false;
            }
        }

        binary_t context_hash;
        // transcript hash
        if (cond_trhash) {
            auto tshash = get_transcript_hash();
            if (tshash) {
                ret = tshash->digest(context_hash);
                tshash->release();
                if (errorcode_t::success != ret) {
                    __leave2_trace(ret);
                }
            }
        }

        if (tls_handshake_type_t::client_hello == type) {
            /**
             *             0
             *             |
             *             v
             *   PSK ->  HKDF-Extract = Early Secret
             *             |
             *             +-----> Derive-Secret(., "ext binder"
             *             |                      | "res binder"
             *             |                      | "imp binder", "")
             *             |                     = binder_key
             *             |     ; RFC 9258 Importing External Pre-Shared Keys (PSKs)
             * for TLS 1.3 |       5.2.  Binder Key Derivation |       Imported PSKs
             * use the string "imp binder" rather than "ext binder" or "res binder"
             * when deriving binder_key.
             *             |
             *             +-----> Derive-Secret(., "c e traffic", ClientHello)
             *             |                     = client_early_traffic_secret
             *             |
             *             +-----> Derive-Secret(., "e exp master", ClientHello)
             *             |                     = early_exporter_master_secret
             *             v
             *       Derive-Secret(., "derived", "")
             *             |
             *             v
             */

            // res binder (see tls_extension_type_t::pre_shared_key)
            // exp master (see tls_secret_t::server_finished)

            if ((session_type_t::tls == session_type) || (session_type_t::dtls == session_type)) {
                if (tls13_key_schedule) {
                    if (tls_flow_t::zero_rtt == flow) {
                        // 0-RTT
                        const binary_t& secret_resumption_early = get_secrets().get(tls_secret_t::resumption_early);  // client finished
                        auto lambda_clear_early_data_secrets = [this]() -> void {
                            get_secrets().assign(tls_secret_t::c_e_traffic, binary_t());
                            get_secrets().assign(tls_secret_t::e_exp_master, binary_t());
                            get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t());
                            get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t());
                        };

                        // {client}  derive secret "tls13 c e traffic"
                        binary_t secret_c_e_traffic;
                        ret = lambda_expand_label(tls_secret_t::c_e_traffic, secret_c_e_traffic, hashalg, dlen, secret_resumption_early, "c e traffic", context_hash);
                        if (errorcode_t::success != ret) {
                            lambda_clear_early_data_secrets();
                            __leave2_trace(ret);
                        }
                        // {client}  derive secret "tls13 e exp master"
                        binary_t secret_e_exp_master;
                        ret = lambda_expand_label(tls_secret_t::e_exp_master, secret_e_exp_master, hashalg, dlen, secret_resumption_early, "e exp master", context_hash);
                        if (errorcode_t::success != ret) {
                            lambda_clear_early_data_secrets();
                            __leave2_trace(ret);
                        }
                        // {client}  derive write traffic keys for early application data
                        binary_t secret_c_e_traffic_key;
                        ret = lambda_expand_label(tls_secret_t::c_e_traffic_key, secret_c_e_traffic_key, hashalg, keysize, secret_c_e_traffic, "key", empty);
                        if (errorcode_t::success != ret) {
                            lambda_clear_early_data_secrets();
                            __leave2_trace(ret);
                        }
                        binary_t secret_c_e_traffic_iv;
                        ret = lambda_expand_label(tls_secret_t::c_e_traffic_iv, secret_c_e_traffic_iv, hashalg, 12, secret_c_e_traffic, "iv", empty);
                        if (errorcode_t::success != ret) {
                            lambda_clear_early_data_secrets();
                            __leave2_trace(ret);
                        }

#if defined DEBUG
                        if (istraceable(trace_category_t::trace_category_net)) {
                            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                                dbs.println("* TLS 1.3 key schedule - ClientHello (0-RTT)");
                                dbs.println(" > session type %i, handshake type %i, direction %i", static_cast<int>(session_type), static_cast<int>(type),
                                            static_cast<int>(dir));
                                dbs.println(" > flow %i", static_cast<int>(flow));
                                dbs.println(" > cipher suite 0x%04x (%s)", cipher_suite, tlsadvisor->nameof_tls_cipher_suite(cipher_suite).c_str());
                                dbs.println(" > hash %s, digest length %u, key length %u", hashalg, static_cast<unsigned int>(dlen), static_cast<unsigned int>(keysize));
                                dbs.println(" > transcript hash (%u bytes) %s", static_cast<unsigned int>(context_hash.size()), base16_encode(context_hash).c_str());
                                dbs.println(" > resumption_early length %u", static_cast<unsigned int>(secret_resumption_early.size()));
                                dbs.println(" > c e traffic length %u", static_cast<unsigned int>(secret_c_e_traffic.size()));
                                dbs.println(" > e exp master length %u", static_cast<unsigned int>(secret_e_exp_master.size()));
                                dbs.println(" > c e traffic key length %u", static_cast<unsigned int>(secret_c_e_traffic_key.size()));
                                dbs.println(" > c e traffic iv length %u", static_cast<unsigned int>(secret_c_e_traffic_iv.size()));
                            });
                        }
#endif
                    }
                } else {
                    if (tls_flow_t::renegotiation == flow) {
                        // TODO
                    }
                }
            } else if ((session_type_t::quic == session_type) || (session_type_t::quic2 == session_type)) {
                const binary_t& salt = get_secrets().get(tls_secret_t::quic_dcid);
                if ((false == salt.empty()) && get_secrets().get(tls_secret_t::initial_quic).empty()) {
                    binary_t bin_initial_salt;
                    if (session_type_t::quic == session_type) {
                        // RFC 9001 5.2.  Initial Secrets
                        bin_initial_salt = std::move(base16_decode("0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a"));
                    } else if (session_type_t::quic2 == session_type) {
                        // RFC 9369 3.3.1.  Initial Salt
                        bin_initial_salt = std::move(base16_decode("0x0dede3def700a6db819381be6e269dcbf9bd2ed9"));
                    }  // else do not reach

                    openssl_kdf kdf;
                    binary_t bin;
                    binary_t bin_initial_secret;
                    binary_t bin_client_initial_secret;
                    binary_t bin_server_initial_secret;
                    binary_t context;
                    auto alg = hash_algorithm_t::sha2_256;

                    /**
                     * RFC 5869
                     * RFC 8446 7.1.  Key Schedule
                     * RFC 9001 5.2.  Initial Secrets
                     * RFC 9001 A.1.  Keys
                     * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
                     * RFC 9001 A.5.  ChaCha20-Poly1305 Short Header Packet
                     */

                    auto lambda_clear_initial_quic = [this]() -> void {
                        get_secrets().assign(tls_secret_t::initial_quic, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_client, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_client_key, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_client_iv, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_client_hp, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_server, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_server_key, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_server_iv, binary_t());
                        get_secrets().assign(tls_secret_t::initial_quic_server_hp, binary_t());
                    };

                    ret = kdf.hmac_kdf_extract(bin_initial_secret, alg, bin_initial_salt, salt);
                    if (errorcode_t::success != ret) {
                        bin_initial_secret.clear();
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }

                    auto lambda_hkdf_expand_tls13_label = [this, &kdf](tls_secret_t sec, binary_t& okm, hash_algorithm_t alg, uint16 length, const binary_t& secret,
                                                                       const char* label, const binary_t& context) -> return_t {
                        okm.clear();
                        return_t result = kdf.hkdf_expand_tls13_label(okm, alg, length, secret, label, context);
                        if (errorcode_t::success != result) {
                            okm.clear();
                            get_secrets().assign(sec, binary_t());
                            return result;
                        }
                        get_secrets().assign(sec, okm);  // copy
                        return result;
                    };

                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_client, bin_client_initial_secret, alg, 32, bin_initial_secret, "client in", context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_client_key, bin, alg, 16, bin_client_initial_secret, label_quic_key, context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_client_iv, bin, alg, 12, bin_client_initial_secret, label_quic_iv, context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_client_hp, bin, alg, 16, bin_client_initial_secret, label_quic_hp, context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_server, bin_server_initial_secret, alg, 32, bin_initial_secret, "server in", context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_server_key, bin, alg, 16, bin_server_initial_secret, label_quic_key, context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_server_iv, bin, alg, 12, bin_server_initial_secret, label_quic_iv, context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    ret = lambda_hkdf_expand_tls13_label(tls_secret_t::initial_quic_server_hp, bin, alg, 16, bin_server_initial_secret, label_quic_hp, context);
                    if (errorcode_t::success != ret) {
                        lambda_clear_initial_quic();
                        __leave2_trace(ret);
                    }
                    get_secrets().assign(tls_secret_t::initial_quic, bin_initial_secret);
                }
            }
        } else if (tls_handshake_type_t::server_hello == type) {
            // ~ TLS 1.2 see client_key_exchange, server_key_exchange
            // TLS 1.3 server_hello legacy_version

            /**
             *   (EC)DHE -> HKDF-Extract = Handshake Secret
             *             |
             *             +-----> Derive-Secret(., "c hs traffic",
             *             |                     ClientHello...ServerHello)
             *             |                     = tls_secret_t::client_handshake_traffic_secret
             *             |
             *             +-----> Derive-Secret(., "s hs traffic",
             *             |                     ClientHello...ServerHello)
             *             |                     = tls_secret_t::server_handshake_traffic_secret
             *             v
             *       Derive-Secret(., "derived", "")
             *             |
             *             v
             */

            if (is_kindof_tls13()) {
                binary_t secret_handshake_client;
                binary_t secret_handshake_server;
                auto lambda_clear_server_hello_outputs = [this](bool preserve_injected_traffic_secrets) -> void {
                    if (false == preserve_injected_traffic_secrets) {
                        get_secrets().assign(tls_secret_t::early_secret, binary_t());
                        get_secrets().assign(tls_secret_t::handshake_derived, binary_t());
                        get_secrets().assign(tls_secret_t::handshake, binary_t());
                        get_secrets().assign(tls_secret_t::c_hs_traffic, binary_t());
                        get_secrets().assign(tls_secret_t::s_hs_traffic, binary_t());
                        get_secrets().assign(tls_secret_t::application_derived, binary_t());
                        get_secrets().assign(tls_secret_t::application, binary_t());
                        get_secrets().assign(tls_secret_t::shared_secret, binary_t());
                    }
                    get_secrets().assign(tls_secret_t::handshake_client_key, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_client_iv, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_server_key, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_server_iv, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_client_sn_key, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_server_sn_key, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_quic_client_key, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_quic_client_iv, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_quic_client_hp, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_quic_server_key, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_quic_server_iv, binary_t());
                    get_secrets().assign(tls_secret_t::handshake_quic_server_hp, binary_t());
                };

                if (use_pre_master_secret()) {
                    // from SSLKEYLOGFILE
                    secret_handshake_client = get_secrets().get(tls_secret_t::c_hs_traffic);
                    secret_handshake_server = get_secrets().get(tls_secret_t::s_hs_traffic);
                } else {
                    // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes
                    //  psk_ke      ... pre_shared_key
                    //  psk_dhe_ke  ... key_share
                    binary_t shared_secret;

                    uint16 selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
                    uint16 selected_psk_mode = t_narrow_cast(session->get_keyvalue().get(session_server_psk_key_exchange_mode));
                    bool use_psk_ke = (0xffff != selected_identity) && (0 == selected_psk_mode);
                    if (use_psk_ke) {
                        // RFC 8446 7.1: psk_ke supplies Hash.length zero bytes as the (EC)DHE input.
                        shared_secret.assign(dlen, 0);
                    } else {
                        const EVP_PKEY* pkey_priv = nullptr;
                        const EVP_PKEY* pkey_pub = nullptr;

                        auto group = get_protection_context().get0_keyshare_group();
                        auto hint_group = advisor->hintof_tls_group(group);
                        if (hint_group) {
                            if (tls_flag_pqc & hint_group->flags) {
                                // tls_extension_key_share
                                shared_secret = get_secrets().get(tls_secret_t::shared_secret);
                                uint16 group = t_narrow_cast(session->get_session_info(from_server).get_keyvalue().get(session_hrr));
                                if (group) {
                                    session->get_session_info(from_server).get_keyvalue().remove(session_hrr);
                                    ret = errorcode_t::warn_retry;
                                    __leave2_trace(ret);
                                }
                            } else {
                                pkey_priv = get_key().find_group(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE, group);
                                if (pkey_priv) {
                                    // in server ... priv(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE) + pub(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC)
                                    pkey_pub = get_key().find_group(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC, group);  // client_hello
                                } else {
                                    // in client ... priv(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE) + pub(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC)
                                    pkey_priv = get_key().find_group(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE, group);
                                    pkey_pub = get_key().find_group(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC, group);  // server_hello
                                }

                                // warn_retry
                                // If the server selects an (EC)DHE group and the client did not offer a compatible "key_share" extension in the initial
                                // ClientHello, the server MUST respond with a HelloRetryRequest (Section 4.1.4) message.

                                if (nullptr == pkey_priv || nullptr == pkey_pub) {
                                    ret = errorcode_t::warn_retry;  // HRR
                                    __leave2_trace(ret);
                                }

                                uint16 group_enforced = session->get_keyvalue().get(session_conf_enforce_key_share_group);
                                if (group_enforced) {
                                    // enforcing
                                    auto pkey_ch = get_key().find_group(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE, group);
                                    if (nullptr == pkey_ch) {
                                        pkey_ch = get_key().find_group(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC, group);
                                    }
                                    if (nullptr == pkey_ch) {
                                        ret = errorcode_t::warn_retry;
                                        __leave2_trace(ret);  // HRR
                                    }
                                }

                                ret = dh_key_agreement(pkey_priv, pkey_pub, shared_secret);
                                if (errorcode_t::success != ret) {
                                    lambda_clear_server_hello_outputs(use_pre_master_secret());
                                    __leave2_trace(ret);
                                }
                            }
                        } else {
                            ret = errorcode_t::warn_retry;  // HRR
                            __leave2_trace(ret);
                        }
                    }

                    // RFC 8446 7.1: the early secret is derived from the
                    // selected PSK, independently of whether 0-RTT was offered
                    // or accepted. Flow describes the record/transcript path;
                    // it must not decide whether the handshake uses the PSK.
                    binary_t early_secret;
                    if (0xffff != selected_identity) {
                        early_secret = get_secrets().get(tls_secret_t::resumption_early);
                        if (early_secret.empty()) {
                            ret = errorcode_t::bad_request;
                            lambda_clear_server_hello_outputs(use_pre_master_secret());
                            __leave2_trace(ret);
                        }
                        get_secrets().assign(tls_secret_t::early_secret, early_secret);
                    } else {
                        binary_t salt;
                        salt.resize(1);
                        ret = lambda_extract(tls_secret_t::early_secret, early_secret, hashalg, salt, empty_ikm);
                        if (errorcode_t::success != ret) {
                            lambda_clear_server_hello_outputs(use_pre_master_secret());
                            __leave2_trace(ret);
                        }
                        // The final ServerHello selected no PSK. The cached
                        // resumption secret is no longer needed by this
                        // handshake and must not remain as stale session state.
                        get_secrets().assign(tls_secret_t::resumption_early, binary_t());
                    }

                    binary_t secret_handshake_derived;
                    ret = lambda_expand_label(tls_secret_t::handshake_derived, secret_handshake_derived, hashalg, dlen, early_secret, "derived", empty_hash);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }

                    binary_t secret_handshake;
                    ret = lambda_extract(tls_secret_t::handshake, secret_handshake, hashalg, secret_handshake_derived, shared_secret);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }

                    // tls_secret_t::client_handshake_traffic_secret
                    ret = lambda_expand_label(tls_secret_t::c_hs_traffic, secret_handshake_client, hashalg, dlen, secret_handshake, "c hs traffic", context_hash);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    // tls_secret_t::server_handshake_traffic_secret
                    ret = lambda_expand_label(tls_secret_t::s_hs_traffic, secret_handshake_server, hashalg, dlen, secret_handshake, "s hs traffic", context_hash);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }

#if defined DEBUG
                    if (istraceable(trace_category_t::trace_category_net)) {
                        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                            dbs.println("* TLS 1.3 key schedule - ServerHello");
                            dbs.println(" > flow %i", static_cast<int>(flow));
                            dbs.println(" > cipher suite 0x%04x (%s)", cipher_suite, tlsadvisor->nameof_tls_cipher_suite(cipher_suite).c_str());
                            dbs.println(" > hash %s", hashalg);
                            uint16 selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
                            uint16 selected_psk_mode = t_narrow_cast(session->get_keyvalue().get(session_server_psk_key_exchange_mode));
                            if (0xffff != selected_identity) {
                                dbs.println(" > PSK selected identity %u, key exchange mode %s", selected_identity,
                                            (0 == selected_psk_mode) ? "psk_ke" : ((1 == selected_psk_mode) ? "psk_dhe_ke" : "unknown"));
                            } else {
                                auto group = get_protection_context().get0_keyshare_group();
                                dbs.println(" > key share group 0x%04x", static_cast<uint16>(group));
                            }
                            dbs.println(" > transcript hash %s", base16_encode(context_hash).c_str());
                            dbs.println(" > resumption_early %s", base16_encode(get_secrets().get(tls_secret_t::resumption_early)).c_str());
                            dbs.println(" > shared secret %s", base16_encode(shared_secret).c_str());
                            dbs.println(" > handshake derived %s", base16_encode(secret_handshake_derived).c_str());
                            dbs.println(" > handshake secret %s", base16_encode(secret_handshake).c_str());
                            dbs.println(" > c hs traffic %s", base16_encode(secret_handshake_client).c_str());
                            dbs.println(" > s hs traffic %s", base16_encode(secret_handshake_server).c_str());
                        });
                    }
#endif

                    binary_t secret_application_derived;
                    ret = lambda_expand_label(tls_secret_t::application_derived, secret_application_derived, hashalg, dlen, secret_handshake, "derived", empty_hash);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    binary_t secret_application;
                    ret = lambda_extract(tls_secret_t::application, secret_application, hashalg, secret_application_derived, empty_ikm);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }

                    auto sslkeylog = sslkeylog_exporter::get_instance();
                    sslkeylog->log(session, tls_secret_t::c_hs_traffic);
                    sslkeylog->log(session, tls_secret_t::s_hs_traffic);

                    // move
                    get_secrets().assign(tls_secret_t::shared_secret, std::move(shared_secret));
                }

                // calc
                binary_t okm;
                {
                    ret = lambda_expand_label(tls_secret_t::handshake_client_key, okm, hashalg, keysize, secret_handshake_client, "key", empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_client_iv, okm, hashalg, 12, secret_handshake_client, "iv", empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_server_key, okm, hashalg, keysize, secret_handshake_server, "key", empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_server_iv, okm, hashalg, 12, secret_handshake_server, "iv", empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                }
                if (is_kindof_dtls()) {
                    ret = lambda_expand_label(tls_secret_t::handshake_client_sn_key, okm, hashalg, keysize, secret_handshake_client, "sn", empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_server_sn_key, okm, hashalg, keysize, secret_handshake_server, "sn", empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                }
                if ((session_type_t::quic == session_type) || (session_type_t::quic2 == session_type)) {
                    ret = lambda_expand_label(tls_secret_t::handshake_quic_client_key, okm, hashalg, keysize, secret_handshake_client, label_quic_key, empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_quic_client_iv, okm, hashalg, 12, secret_handshake_client, label_quic_iv, empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_quic_client_hp, okm, hashalg, keysize, secret_handshake_client, label_quic_hp, empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_quic_server_key, okm, hashalg, keysize, secret_handshake_server, label_quic_key, empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_quic_server_iv, okm, hashalg, 12, secret_handshake_server, label_quic_iv, empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                    ret = lambda_expand_label(tls_secret_t::handshake_quic_server_hp, okm, hashalg, keysize, secret_handshake_server, label_quic_hp, empty);
                    if (errorcode_t::success != ret) {
                        lambda_clear_server_hello_outputs(use_pre_master_secret());
                        __leave2_trace(ret);
                    }
                }
            }
        } else if (tls_handshake_type_t::end_of_early_data == type) {
            auto lambda_clear_end_of_early_data_outputs = [&]() -> void {
                get_secrets().assign(tls_secret_t::handshake_client_key, binary_t());
                get_secrets().assign(tls_secret_t::handshake_client_iv, binary_t());
                get_secrets().assign(tls_secret_t::handshake_server_key, binary_t());
                get_secrets().assign(tls_secret_t::handshake_server_iv, binary_t());
            };

            binary_t okm;
            const binary_t& secret_c_hs_traffic = get_secrets().get(tls_secret_t::c_hs_traffic);
            ret = lambda_expand_label(tls_secret_t::handshake_client_key, okm, hashalg, keysize, secret_c_hs_traffic, "key", empty);
            if (errorcode_t::success != ret) {
                lambda_clear_end_of_early_data_outputs();
                __leave2_trace(ret);
            }
            ret = lambda_expand_label(tls_secret_t::handshake_client_iv, okm, hashalg, 12, secret_c_hs_traffic, "iv", empty);
            if (errorcode_t::success != ret) {
                lambda_clear_end_of_early_data_outputs();
                __leave2_trace(ret);
            }
            const binary_t& secret_s_hs_traffic = get_secrets().get(tls_secret_t::s_hs_traffic);
            ret = lambda_expand_label(tls_secret_t::handshake_server_key, okm, hashalg, keysize, secret_s_hs_traffic, "key", empty);
            if (errorcode_t::success != ret) {
                lambda_clear_end_of_early_data_outputs();
                __leave2_trace(ret);
            }
            ret = lambda_expand_label(tls_secret_t::handshake_server_iv, okm, hashalg, 12, secret_s_hs_traffic, "iv", empty);
            if (errorcode_t::success != ret) {
                lambda_clear_end_of_early_data_outputs();
                __leave2_trace(ret);
            }
        } else if ((tls_handshake_type_t::finished == type) && is_serverinitiated(dir)) {
            /**
             *   0 -> HKDF-Extract = Master Secret
             *             |
             *             +-----> Derive-Secret(., "c ap traffic",
             *             |                     ClientHello...server Finished)
             *             |                     = tls_secret_t::client_application_traffic_secret_0
             *             |
             *             +-----> Derive-Secret(., "s ap traffic",
             *             |                     ClientHello...server Finished)
             *             |                     = tls_secret_t::server_application_traffic_secret_0
             *             |
             *             +-----> Derive-Secret(., "exp master",
             *             |                     ClientHello...server Finished)
             *             |                     = secret_exporter_master
             */

            auto lambda_clear_server_finished_outputs = [&](bool preserve_injected_traffic_secrets) -> void {
                if (!preserve_injected_traffic_secrets) {
                    get_secrets().assign(tls_secret_t::c_ap_traffic, binary_t());
                    get_secrets().assign(tls_secret_t::s_ap_traffic, binary_t());
                    get_secrets().assign(tls_secret_t::exp_master, binary_t());
                }
                get_secrets().assign(tls_secret_t::application_client_key, binary_t());
                get_secrets().assign(tls_secret_t::application_client_iv, binary_t());
                get_secrets().assign(tls_secret_t::application_server_key, binary_t());
                get_secrets().assign(tls_secret_t::application_server_iv, binary_t());
                get_secrets().assign(tls_secret_t::application_server_sn_key, binary_t());
                get_secrets().assign(tls_secret_t::application_quic_client_key, binary_t());
                get_secrets().assign(tls_secret_t::application_quic_client_iv, binary_t());
                get_secrets().assign(tls_secret_t::application_quic_client_hp, binary_t());
                get_secrets().assign(tls_secret_t::application_quic_server_key, binary_t());
                get_secrets().assign(tls_secret_t::application_quic_server_iv, binary_t());
                get_secrets().assign(tls_secret_t::application_quic_server_hp, binary_t());
                get_secrets().assign(tls_secret_t::server_finished, binary_t());
            };

            // tls_secret_t::client_application_traffic_secret_0
            binary_t secret_application_client;
            // tls_secret_t::server_application_traffic_secret_0
            binary_t secret_application_server;
            // secret_exporter_master
            binary_t secret_exporter_master;

            if (use_pre_master_secret()) {
                // from SSLKEYLOGFILE
                secret_application_client = get_secrets().get(tls_secret_t::c_ap_traffic);
                secret_application_server = get_secrets().get(tls_secret_t::s_ap_traffic);
                secret_exporter_master = get_secrets().get(tls_secret_t::exp_master);
            } else {
                const binary_t& secret_application = get_secrets().get(tls_secret_t::application);
                ret = lambda_expand_label(tls_secret_t::c_ap_traffic, secret_application_client, hashalg, dlen, secret_application, "c ap traffic", context_hash);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::s_ap_traffic, secret_application_server, hashalg, dlen, secret_application, "s ap traffic", context_hash);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::exp_master, secret_exporter_master, hashalg, dlen, secret_application, "exp master", context_hash);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }

                if (is_kindof_tls13()) {
                    auto sslkeylog = sslkeylog_exporter::get_instance();
                    sslkeylog->log(session, tls_secret_t::c_ap_traffic);
                    sslkeylog->log(session, tls_secret_t::s_ap_traffic);
                    sslkeylog->log(session, tls_secret_t::exp_master);
                }
            }

            // calc
            binary_t okm;
            {
                ret = lambda_expand_label(tls_secret_t::application_client_key, okm, hashalg, keysize, secret_application_client, "key", empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_client_iv, okm, hashalg, 12, secret_application_client, "iv", empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_server_key, okm, hashalg, keysize, secret_application_server, "key", empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_server_iv, okm, hashalg, 12, secret_application_server, "iv", empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
            }
            if (is_kindof_dtls()) {
                ret = lambda_expand_label(tls_secret_t::application_server_sn_key, okm, hashalg, keysize, secret_application_server, "sn", empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
            }
            if ((session_type_t::quic == session_type) || (session_type_t::quic2 == session_type)) {
                ret = lambda_expand_label(tls_secret_t::application_quic_client_key, okm, hashalg, keysize, secret_application_client, label_quic_key, empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_quic_client_iv, okm, hashalg, 12, secret_application_client, label_quic_iv, empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_quic_client_hp, okm, hashalg, keysize, secret_application_client, label_quic_hp, empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_quic_server_key, okm, hashalg, keysize, secret_application_server, label_quic_key, empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_quic_server_iv, okm, hashalg, 12, secret_application_server, label_quic_iv, empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
                ret = lambda_expand_label(tls_secret_t::application_quic_server_hp, okm, hashalg, keysize, secret_application_server, label_quic_hp, empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_server_finished_outputs(use_pre_master_secret());
                    __leave2_trace(ret);
                }
            }

            if (errorcode_t::success != ret) {
                lambda_clear_server_finished_outputs(use_pre_master_secret());
                __leave2_trace(ret);
            }
            get_secrets().assign(tls_secret_t::server_finished, context_hash);  // copy
        } else if ((tls_handshake_type_t::finished == type) && is_clientinitiated(dir)) {
            /**
             *   0 -> HKDF-Extract = Master Secret
             *             |
             *             +-----> Derive-Secret(., "res master",
             *                                   ClientHello...client Finished)
             *                                   = resumption_master_secret
             */

            auto lambda_clear_client_finished_outputs = [&]() -> void {
                get_secrets().assign(tls_secret_t::res_master, binary_t());
                get_secrets().assign(tls_secret_t::resumption, binary_t());
                get_secrets().assign(tls_secret_t::resumption_early, binary_t());
                get_secrets().assign(tls_secret_t::application_client_sn_key, binary_t());
            };

            binary_t secret_resumption_master;
            const binary_t& secret_application = get_secrets().get(tls_secret_t::application);
            ret = lambda_expand_label(tls_secret_t::res_master, secret_resumption_master, hashalg, dlen, secret_application, "res master", context_hash);
            if (errorcode_t::success != ret) {
                lambda_clear_client_finished_outputs();
                __leave2_trace(ret);
            }

            binary_t secret_resumption;
            binary_t reshash;
            reshash.resize(2);
            ret = lambda_expand_label(tls_secret_t::resumption, secret_resumption, hashalg, dlen, secret_resumption_master, "resumption", reshash);
            if (errorcode_t::success != ret) {
                lambda_clear_client_finished_outputs();
                __leave2_trace(ret);
            }

            // RFC 8448 4.  Resumed 0-RTT Handshake
            binary_t resumption_early_secret;
            ret = lambda_extract(tls_secret_t::resumption_early, resumption_early_secret, hashalg, empty_ikm, secret_resumption);
            if (errorcode_t::success != ret) {
                lambda_clear_client_finished_outputs();
                __leave2_trace(ret);
            }

            binary_t okm;
            if (is_kindof_dtls()) {
                const auto& secret_application_client = get_secrets().get(tls_secret_t::c_ap_traffic);
                ret = lambda_expand_label(tls_secret_t::application_client_sn_key, okm, hashalg, keysize, secret_application_client, "sn", empty);
                if (errorcode_t::success != ret) {
                    lambda_clear_client_finished_outputs();
                    __leave2_trace(ret);
                }
            }

        } else if (tls_handshake_type_t::client_key_exchange == type) {
            crypto_hmac_builder builder;
            binary_t master_secret;
            hash_algorithm_t hmac_alg = algof_mac(hint_tls_alg);
            const binary_t& client_hello_random = get_secrets().get(tls_secret_t::client_hello_random);
            const binary_t& server_hello_random = get_secrets().get(tls_secret_t::server_hello_random);

            if (use_pre_master_secret()) {
                master_secret = get_secrets().get(tls_secret_t::master);
            } else {
                /**
                 * RFC 2246 8.1. Computing the master secret
                 * RFC 5246 8.1.  Computing the Master Secret
                 * master_secret = PRF(pre_master_secret, "master secret",
                 *                     ClientHello.random + ServerHello.random)
                 *                     [0..47];
                 */

                binary_t pre_master_secret;
                {
                    // auto group = get_protection_context().get0_supported_group();

                    const EVP_PKEY* pkey_priv = nullptr;
                    const EVP_PKEY* pkey_pub = nullptr;
                    auto pkey_ske = get_key().find(KID_TLS_SERVER_KEY_EXCHANGE);
                    auto pkey_cke = get_key().find(KID_TLS_CLIENT_KEY_EXCHANGE);
                    bool test = false;
                    is_private_key(pkey_ske, test);
                    if (test) {
                        pkey_priv = pkey_ske;
                        pkey_pub = pkey_cke;
                    } else {
                        pkey_priv = pkey_cke;
                        pkey_pub = pkey_ske;
                    }
                    if (nullptr == pkey_priv || nullptr == pkey_pub) {
                        ret = errorcode_t::not_found;
                        __leave2;
                    }
                    ret = dh_key_agreement(pkey_priv, pkey_pub, pre_master_secret);
                    if (errorcode_t::success != ret) {
                        __leave2;
                    }
                }

#if defined DEBUG
                if (istraceable(trace_category_t::trace_category_net)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                        dbs.printf(ANSI_ESCAPE "1;36m");
                        dbs.println("> hmac alg %x", hmac_alg);
                        dbs.println("> client hello random %s", base16_encode(client_hello_random).c_str());
                        dbs.println("> server hello random %s", base16_encode(server_hello_random).c_str());
                        dbs.println("> pre master secret %s", base16_encode(pre_master_secret).c_str());
                        dbs.printf(ANSI_ESCAPE "0m");
                    });
                }
#endif

                auto hmac_master = builder.set(hmac_alg).set(pre_master_secret).build();
                if (hmac_master) {
                    /**
                     * master secret
                     * RFC 2246 5. HMAC and the pseudorandom function
                     * RFC 2246 8.1. Computing the master secret
                     *   master_secret = PRF(pre_master_secret, "master secret",
                     *                       ClientHello.random + ServerHello.random)
                     *                       [0..47];
                     * RFC 2246 5. HMAC and the pseudorandom function
                     * RFC 5246 5.  HMAC and the Pseudorandom Function
                     *   P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                     *                          HMAC_hash(secret, A(2) + seed) +
                     *                          HMAC_hash(secret, A(3) + seed) + ...
                     *   A() is defined as:
                     *       A(0) = seed
                     *       A(i) = HMAC_hash(secret, A(i-1))
                     *   PRF(secret, label, seed) = P_<hash>(secret, label + seed)
                     *
                     * extended master secret
                     * RFC 7627 Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
                     *   session_hash = Hash(handshake_messages)
                     *   master_secret = PRF(pre_master_secret, "extended master secret",
                     *                       session_hash)
                     *                       [0..47];
                     */
                    binary_t seed;
                    size_t size_master_secret = 48;

                    auto use_ems = session->get_keyvalue().get(session_extended_master_secret);
                    if (use_ems) {
                        binary_append(seed, "extended master secret");
                        binary_append(seed, context_hash);
                    } else {
                        binary_append(seed, "master secret");
                        binary_append(seed, client_hello_random);
                        binary_append(seed, server_hello_random);
                    }

                    binary_t temp = seed;
                    binary_t atemp;
                    binary_t ptemp;
                    while (master_secret.size() < size_master_secret) {
                        hmac_master->mac(temp, atemp);
                        hmac_master->update(atemp).update(seed).finalize(ptemp);
                        binary_append(master_secret, ptemp);
                        temp = atemp;
                    }

                    master_secret.resize(48);  // 48 bytes

                    hmac_master->release();

                    auto sslkeylog = sslkeylog_exporter::get_instance();
                    sslkeylog->log(session, tls_secret_t::master);
                } else {
                    ret = errorcode_t::not_supported;
                    __leave2;
                }
            }

#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                // CLIENT_RANDOM
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                    std::string keylog_client_random = base16_encode(get_secrets().get(tls_secret_t::client_hello_random));
                    std::string keylog_master_secret = base16_encode(master_secret);
                    dbs.printf(ANSI_ESCAPE "1;36m");
                    dbs.println("# CLIENT_RANDOM %s %s", keylog_client_random.c_str(), keylog_master_secret.c_str());
                    dbs.printf(ANSI_ESCAPE "0m");
                });
            }
#endif

            auto cs = get_cipher_suite();
            ret = calc_keyblock(hmac_alg, master_secret, client_hello_random, server_hello_random, cs);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }

            // Publish the master secret only after the key block is ready.
            get_secrets().assign(tls_secret_t::master, std::move(master_secret));
        }

        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        // move
        get_secrets().assign(tls_secret_t::empty_hash, std::move(empty_hash));
        if (cond_trhash) {
            get_secrets().assign(tls_secret_t::transcript_hash, std::move(context_hash));
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
