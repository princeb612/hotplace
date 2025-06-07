/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_aead.hpp>
#include <sdk/crypto/basic/crypto_hash.hpp>
#include <sdk/crypto/basic/crypto_hmac.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/basic/transcript_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_quic_key[] = "quic key";
constexpr char constexpr_quic_iv[] = "quic iv";
constexpr char constexpr_quic_hp[] = "quic hp";
constexpr char constexpr_quic2_key[] = "quicv2 key";
constexpr char constexpr_quic2_iv[] = "quicv2 iv";
constexpr char constexpr_quic2_hp[] = "quicv2 hp";

return_t tls_protection::calc(tls_session *session, tls_hs_type_t type, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    // RFC 8446 7.1.  Key Schedule
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session_type = session->get_type();
        uint16 cipher_suite = get_cipher_suite();

        crypto_advisor *advisor = crypto_advisor::get_instance();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        const char *label_quic_key = nullptr;
        const char *label_quic_iv = nullptr;
        const char *label_quic_hp = nullptr;

        if ((session_type_quic == session_type) || (session_type_quic2 == session_type)) {
            if (0 == cipher_suite) {
                cipher_suite = 0x1301;  // TLS_AES_128_GCM_SHA256
            }

            if (session_type_quic == session_type) {
                label_quic_key = constexpr_quic_key;
                label_quic_iv = constexpr_quic_iv;
                label_quic_hp = constexpr_quic_hp;
            } else {
                label_quic_key = constexpr_quic2_key;
                label_quic_iv = constexpr_quic2_iv;
                label_quic_hp = constexpr_quic2_hp;
            }
        }

        const tls_cipher_suite_t *hint_tls_alg = tlsadvisor->hintof_cipher_suite(cipher_suite);
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        const hint_blockcipher_t *hint_blockcipher = tlsadvisor->hintof_blockcipher(cipher_suite);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        const hint_digest_t *hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
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

        empty_hash = _kv[tls_context_empty_hash];
        if (empty_hash.empty()) {
            openssl_digest dgst;
            dgst.digest(hashalg, empty, empty_hash);
            _kv[tls_context_empty_hash] = empty_hash;
        }
        empty_ikm.resize(dlen);

        auto lambda_expand_label = [&](tls_secret_t sec, binary_t &okm, const char *hashalg, uint16 dlen, const binary_t &secret, const char *label,
                                       const binary_t &context) -> void {
            okm.clear();
            if (is_kindof_dtls()) {
                kdf.hkdf_expand_dtls13_label(okm, hashalg, dlen, secret, label, context);
            } else {
                kdf.hkdf_expand_tls13_label(okm, hashalg, dlen, secret, label, context);
            }
            _kv[sec] = okm;
        };
        auto lambda_extract = [&](tls_secret_t sec, binary_t &prk, const char *hashalg, const binary_t &salt, const binary_t &ikm) -> void {
            kdf.hmac_kdf_extract(prk, hashalg, salt, ikm);
            _kv[sec] = prk;
        };

        binary_t context_hash;
        // transcript hash
        auto tshash = get_transcript_hash();
        if (tshash) {
            tshash->digest(context_hash);
            tshash->release();
            _kv[tls_context_transcript_hash] = context_hash;
        }

        auto flow = get_flow();

        if (tls_hs_client_hello == type) {
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

            // res binder (see tls_ext_pre_shared_key)
            // exp master (see tls_context_server_finished)

            if ((session_type_tls == session_type) || (session_type_dtls == session_type)) {
                if (is_kindof_tls13()) {
                    if (tls_flow_0rtt == flow) {
                        // 0-RTT
                        const binary_t &secret_resumption_early = get_item(tls_secret_resumption_early);  // client finished

                        // {client}  derive secret "tls13 c e traffic"
                        binary_t secret_c_e_traffic;
                        lambda_expand_label(tls_secret_c_e_traffic, secret_c_e_traffic, hashalg, dlen, secret_resumption_early, "c e traffic", context_hash);
                        // {client}  derive secret "tls13 e exp master"
                        binary_t secret_e_exp_master;
                        lambda_expand_label(tls_secret_e_exp_master, secret_e_exp_master, hashalg, dlen, secret_resumption_early, "e exp master", context_hash);
                        // {client}  derive write traffic keys for early application data
                        binary_t secret_c_e_traffic_key;
                        lambda_expand_label(tls_secret_c_e_traffic_key, secret_c_e_traffic_key, hashalg, keysize, secret_c_e_traffic, "key", empty);
                        binary_t secret_c_e_traffic_iv;
                        lambda_expand_label(tls_secret_c_e_traffic_iv, secret_c_e_traffic_iv, hashalg, 12, secret_c_e_traffic, "iv", empty);
                    }
                } else {
                    if (tls_flow_renegotiation == flow) {
                        // TODO
                    }
                }
            } else if ((session_type_quic == session_type) || (session_type_quic2 == session_type)) {
                const binary_t &salt = get_item(tls_context_quic_dcid);
                if ((false == salt.empty()) && get_item(tls_secret_initial_quic).empty()) {
                    binary_t bin_initial_salt;
                    if (session_type_quic == session_type) {
                        // RFC 9001 5.2.  Initial Secrets
                        bin_initial_salt = std::move(base16_decode("0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a"));
                    } else if (session_type_quic2 == session_type) {
                        // RFC 9369 3.3.1.  Initial Salt
                        bin_initial_salt = std::move(base16_decode("0x0dede3def700a6db819381be6e269dcbf9bd2ed9"));
                    }  // else do not reach

                    openssl_kdf kdf;
                    binary_t bin;
                    binary_t bin_initial_secret;
                    binary_t bin_client_initial_secret;
                    binary_t bin_server_initial_secret;
                    binary_t context;
                    auto alg = sha2_256;

                    /**
                     * RFC 5869
                     * RFC 8446 7.1.  Key Schedule
                     * RFC 9001 5.2.  Initial Secrets
                     * RFC 9001 A.1.  Keys
                     * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
                     * RFC 9001 A.5.  ChaCha20-Poly1305 Short Header Packet
                     */

                    ret = kdf.hmac_kdf_extract(bin_initial_secret, alg, bin_initial_salt, salt);
                    _kv[tls_secret_initial_quic] = bin_initial_secret;

                    kdf.hkdf_expand_tls13_label(bin_client_initial_secret, alg, 32, bin_initial_secret, "client in", context);
                    _kv[tls_secret_initial_quic_client] = bin_client_initial_secret;

                    kdf.hkdf_expand_tls13_label(bin, alg, keysize, bin_client_initial_secret, label_quic_key, context);
                    _kv[tls_secret_initial_quic_client_key] = bin;

                    kdf.hkdf_expand_tls13_label(bin, alg, 12, bin_client_initial_secret, label_quic_iv, context);
                    _kv[tls_secret_initial_quic_client_iv] = bin;

                    kdf.hkdf_expand_tls13_label(bin, alg, 16, bin_client_initial_secret, label_quic_hp, context);
                    _kv[tls_secret_initial_quic_client_hp] = bin;

                    kdf.hkdf_expand_tls13_label(bin_server_initial_secret, alg, 32, bin_initial_secret, "server in", context);
                    _kv[tls_secret_initial_quic_server] = bin_server_initial_secret;

                    kdf.hkdf_expand_tls13_label(bin, alg, keysize, bin_server_initial_secret, label_quic_key, context);
                    _kv[tls_secret_initial_quic_server_key] = bin;

                    kdf.hkdf_expand_tls13_label(bin, alg, 12, bin_server_initial_secret, label_quic_iv, context);
                    _kv[tls_secret_initial_quic_server_iv] = bin;

                    kdf.hkdf_expand_tls13_label(bin, alg, 16, bin_server_initial_secret, label_quic_hp, context);
                    _kv[tls_secret_initial_quic_server_hp] = bin;
                }
            }
        } else if (tls_hs_server_hello == type) {
            // ~ TLS 1.2 see client_key_exchange, server_key_exchange
            // TLS 1.3 server_hello legacy_version

            /**
             *   (EC)DHE -> HKDF-Extract = Handshake Secret
             *             |
             *             +-----> Derive-Secret(., "c hs traffic",
             *             |                     ClientHello...ServerHello)
             *             |                     = client_handshake_traffic_secret
             *             |
             *             +-----> Derive-Secret(., "s hs traffic",
             *             |                     ClientHello...ServerHello)
             *             |                     = server_handshake_traffic_secret
             *             v
             *       Derive-Secret(., "derived", "")
             *             |
             *             v
             */

            if (is_kindof_tls13()) {
                binary_t secret_handshake_client;
                binary_t secret_handshake_server;

                if (use_pre_master_secret()) {
                    // from SSLKEYLOGFILE
                    secret_handshake_client = get_item(tls_secret_c_hs_traffic);
                    secret_handshake_server = get_item(tls_secret_s_hs_traffic);
                } else {
                    // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes
                    //  psk_ke      ... pre_shared_key
                    //  psk_dhe_ke  ... key_share
                    binary_t shared_secret;
                    {
                        const EVP_PKEY *pkey_priv = nullptr;
                        const EVP_PKEY *pkey_pub = nullptr;

                        pkey_priv = get_keyexchange().find(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE);
                        if (pkey_priv) {
                            // in server ... priv(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE) + pub(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC)
                            pkey_pub = get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);  // client_hello
                        } else {
                            // in client ... priv(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE) + pub(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC)
                            pkey_priv = get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
                            pkey_pub = get_keyexchange().find(KID_TLS_SERVERHELLO_KEYSHARE_PUBLIC);  // server_hello
                        }

                        // warn_retry
                        // If the server selects an (EC)DHE group and the client did not offer a compatible "key_share" extension in the initial ClientHello,
                        // the server MUST respond with a HelloRetryRequest (Section 4.1.4) message.

                        if (nullptr == pkey_priv || nullptr == pkey_pub) {
                            if (is_kindof_tls13()) {
                                ret = errorcode_t::warn_retry;  // HRR
                            }
                            __leave2;
                        }

                        uint16 group_enforced = session->get_keyvalue().get(session_conf_enforce_key_share_group);
                        if (group_enforced) {
                            auto hint = tlsadvisor->hintof_tls_group(group_enforced);
                            // enforcing
                            auto pkey_ch = get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
                            if (nullptr == pkey_ch) {
                                pkey_ch = get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC);
                            }
                            uint32 nid = 0;
                            nidof_evp_pkey(pkey_ch, nid);
                            if (nid != hint->nid) {
                                ret = errorcode_t::warn_retry;
                                __leave2;  // HRR
                            }
                        } else {
                            uint32 nid_priv = 0;
                            uint32 nid_pub = 0;
                            nidof_evp_pkey(pkey_priv, nid_priv);
                            nidof_evp_pkey(pkey_pub, nid_pub);
                            if (nid_priv != nid_pub) {
                                ret = errorcode_t::warn_retry;
                                __leave2;  // HRR
                            }
                        }

                        ret = dh_key_agreement(pkey_priv, pkey_pub, shared_secret);

                        _kv[tls_context_shared_secret] = shared_secret;
                    }

                    binary_t early_secret;
                    {
                        binary_t salt;
                        salt.resize(1);
                        lambda_extract(tls_secret_early_secret, early_secret, hashalg, salt, empty_ikm);
                    }

                    binary_t secret_handshake_derived;
                    switch (flow) {
                        case tls_flow_1rtt:
                        case tls_flow_hello_retry_request: {
                            lambda_expand_label(tls_secret_handshake_derived, secret_handshake_derived, hashalg, dlen, early_secret, "derived", empty_hash);
                        } break;
                        case tls_flow_0rtt: {
                            const binary_t &secret_resumption_early = get_item(tls_secret_resumption_early);
                            lambda_expand_label(tls_secret_handshake_derived, secret_handshake_derived, hashalg, dlen, secret_resumption_early, "derived",
                                                empty_hash);
                        } break;
                        case tls_flow_renegotiation: {
                            // TODO
                        } break;
                    }

                    binary_t secret_handshake;
                    lambda_extract(tls_secret_handshake, secret_handshake, hashalg, secret_handshake_derived, shared_secret);

                    // client_handshake_traffic_secret
                    lambda_expand_label(tls_secret_c_hs_traffic, secret_handshake_client, hashalg, dlen, secret_handshake, "c hs traffic", context_hash);
                    // server_handshake_traffic_secret
                    lambda_expand_label(tls_secret_s_hs_traffic, secret_handshake_server, hashalg, dlen, secret_handshake, "s hs traffic", context_hash);

                    binary_t secret_application_derived;
                    lambda_expand_label(tls_secret_application_derived, secret_application_derived, hashalg, dlen, secret_handshake, "derived", empty_hash);
                    binary_t secret_application;
                    lambda_extract(tls_secret_application, secret_application, hashalg, secret_application_derived, empty_ikm);
                }

                // calc
                binary_t okm;
                {
                    lambda_expand_label(tls_secret_handshake_client_key, okm, hashalg, keysize, secret_handshake_client, "key", empty);
                    lambda_expand_label(tls_secret_handshake_client_iv, okm, hashalg, 12, secret_handshake_client, "iv", empty);
                    lambda_expand_label(tls_secret_handshake_server_key, okm, hashalg, keysize, secret_handshake_server, "key", empty);
                    lambda_expand_label(tls_secret_handshake_server_iv, okm, hashalg, 12, secret_handshake_server, "iv", empty);
                }
                if (is_kindof_dtls()) {
                    lambda_expand_label(tls_secret_handshake_client_sn_key, okm, hashalg, keysize, secret_handshake_client, "sn", empty);
                    lambda_expand_label(tls_secret_handshake_server_sn_key, okm, hashalg, keysize, secret_handshake_server, "sn", empty);
                }
                if ((session_type_quic == session_type) || (session_type_quic2 == session_type)) {
                    lambda_expand_label(tls_secret_handshake_quic_client_key, okm, hashalg, keysize, secret_handshake_client, label_quic_key, empty);
                    lambda_expand_label(tls_secret_handshake_quic_client_iv, okm, hashalg, 12, secret_handshake_client, label_quic_iv, empty);
                    lambda_expand_label(tls_secret_handshake_quic_client_hp, okm, hashalg, keysize, secret_handshake_client, label_quic_hp, empty);
                    lambda_expand_label(tls_secret_handshake_quic_server_key, okm, hashalg, keysize, secret_handshake_server, label_quic_key, empty);
                    lambda_expand_label(tls_secret_handshake_quic_server_iv, okm, hashalg, 12, secret_handshake_server, label_quic_iv, empty);
                    lambda_expand_label(tls_secret_handshake_quic_server_hp, okm, hashalg, keysize, secret_handshake_server, label_quic_hp, empty);
                }
            }
        } else if (tls_hs_end_of_early_data == type) {
            binary_t okm;
            const binary_t &secret_c_hs_traffic = get_item(tls_secret_c_hs_traffic);
            lambda_expand_label(tls_secret_handshake_client_key, okm, hashalg, keysize, secret_c_hs_traffic, "key", empty);
            lambda_expand_label(tls_secret_handshake_client_iv, okm, hashalg, 12, secret_c_hs_traffic, "iv", empty);
            const binary_t &secret_s_hs_traffic = get_item(tls_secret_s_hs_traffic);
            lambda_expand_label(tls_secret_handshake_server_key, okm, hashalg, keysize, secret_s_hs_traffic, "key", empty);
            lambda_expand_label(tls_secret_handshake_server_iv, okm, hashalg, 12, secret_s_hs_traffic, "iv", empty);
        } else if ((tls_hs_finished == type) && (from_server == dir)) {
            /**
             *   0 -> HKDF-Extract = Master Secret
             *             |
             *             +-----> Derive-Secret(., "c ap traffic",
             *             |                     ClientHello...server Finished)
             *             |                     = client_application_traffic_secret_0
             *             |
             *             +-----> Derive-Secret(., "s ap traffic",
             *             |                     ClientHello...server Finished)
             *             |                     = server_application_traffic_secret_0
             *             |
             *             +-----> Derive-Secret(., "exp master",
             *             |                     ClientHello...server Finished)
             *             |                     = secret_exporter_master
             */

            // client_application_traffic_secret_0
            binary_t secret_application_client;
            // server_application_traffic_secret_0
            binary_t secret_application_server;
            // secret_exporter_master
            binary_t secret_exporter_master;

            _kv[tls_context_server_finished] = context_hash;

            if (use_pre_master_secret()) {
                // from SSLKEYLOGFILE
                secret_application_client = get_item(tls_secret_c_ap_traffic);
                secret_application_server = get_item(tls_secret_s_ap_traffic);
                secret_exporter_master = get_item(tls_secret_exp_master);
            } else {
                const binary_t &secret_application = get_item(tls_secret_application);
                lambda_expand_label(tls_secret_c_ap_traffic, secret_application_client, hashalg, dlen, secret_application, "c ap traffic", context_hash);
                lambda_expand_label(tls_secret_s_ap_traffic, secret_application_server, hashalg, dlen, secret_application, "s ap traffic", context_hash);
                lambda_expand_label(tls_secret_exp_master, secret_exporter_master, hashalg, dlen, secret_application, "exp master", context_hash);
            }

            // calc
            binary_t okm;
            {
                lambda_expand_label(tls_secret_application_client_key, okm, hashalg, keysize, secret_application_client, "key", empty);
                lambda_expand_label(tls_secret_application_client_iv, okm, hashalg, 12, secret_application_client, "iv", empty);
                lambda_expand_label(tls_secret_application_server_key, okm, hashalg, keysize, secret_application_server, "key", empty);
                lambda_expand_label(tls_secret_application_server_iv, okm, hashalg, 12, secret_application_server, "iv", empty);
            }
            if (is_kindof_dtls()) {
                lambda_expand_label(tls_secret_application_server_sn_key, okm, hashalg, keysize, secret_application_server, "sn", empty);
            }
            if ((session_type_quic == session_type) || (session_type_quic2 == session_type)) {
                lambda_expand_label(tls_secret_application_quic_client_key, okm, hashalg, keysize, secret_application_client, label_quic_key, empty);
                lambda_expand_label(tls_secret_application_quic_client_iv, okm, hashalg, 12, secret_application_client, label_quic_iv, empty);
                lambda_expand_label(tls_secret_application_quic_client_hp, okm, hashalg, keysize, secret_application_client, label_quic_hp, empty);
                lambda_expand_label(tls_secret_application_quic_server_key, okm, hashalg, keysize, secret_application_server, label_quic_key, empty);
                lambda_expand_label(tls_secret_application_quic_server_iv, okm, hashalg, 12, secret_application_server, label_quic_iv, empty);
                lambda_expand_label(tls_secret_application_quic_server_hp, okm, hashalg, keysize, secret_application_server, label_quic_hp, empty);
            }
        } else if ((tls_hs_finished == type) && (from_client == dir)) {
            /**
             *   0 -> HKDF-Extract = Master Secret
             *             |
             *             +-----> Derive-Secret(., "res master",
             *                                   ClientHello...client Finished)
             *                                   = secret_resumption_master
             */

            binary_t secret_resumption_master;
            const binary_t &secret_application = get_item(tls_secret_application);
            lambda_expand_label(tls_secret_res_master, secret_resumption_master, hashalg, dlen, secret_application, "res master", context_hash);

            binary_t secret_resumption;
            binary_t reshash;
            reshash.resize(2);
            lambda_expand_label(tls_secret_resumption, secret_resumption, hashalg, dlen, secret_resumption_master, "resumption", reshash);

            // RFC 8448 4.  Resumed 0-RTT Handshake
            binary_t resumption_early_secret;
            lambda_extract(tls_secret_resumption_early, resumption_early_secret, hashalg, empty_ikm, secret_resumption);

            binary_t okm;
            if (is_kindof_dtls()) {
                auto const &secret_application_client = get_item(tls_secret_c_ap_traffic);
                lambda_expand_label(tls_secret_application_client_sn_key, okm, hashalg, keysize, secret_application_client, "sn", empty);
            }

        } else if (tls_hs_client_key_exchange == type) {
            crypto_hmac_builder builder;
            binary_t master_secret;
            hash_algorithm_t hmac_alg = algof_mac(hint_tls_alg);
            const binary_t &client_hello_random = get_item(tls_context_client_hello_random);
            const binary_t &server_hello_random = get_item(tls_context_server_hello_random);

            if (use_pre_master_secret()) {
                master_secret = get_item(tls_secret_master);
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
                    const EVP_PKEY *pkey_priv = nullptr;
                    const EVP_PKEY *pkey_pub = nullptr;
                    auto pkey_ske = get_keyexchange().find(KID_TLS_SERVER_KEY_EXCHANGE);
                    auto pkey_cke = get_keyexchange().find(KID_TLS_CLIENT_KEY_EXCHANGE);
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
                if (istraceable()) {
                    basic_stream dbs;
                    dbs.printf("\e[1;36m");
                    dbs.println("> hmac alg %x", hmac_alg);
                    dbs.println("> client hello random %s", base16_encode(client_hello_random).c_str());
                    dbs.println("> server hello random %s", base16_encode(server_hello_random).c_str());
                    dbs.println("> pre master secret %s", base16_encode(pre_master_secret).c_str());
                    dbs.printf("\e[0m");
                    trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
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
                    hash_context_t *hmac_handle = nullptr;
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

                    set_item(tls_secret_master, master_secret);

                    hmac_master->release();
                } else {
                    ret = errorcode_t::not_supported;
                    __leave2;
                }
            }

#if defined DEBUG
            if (istraceable()) {
                // CLIENT_RANDOM
                basic_stream dbs;
                std::string keylog_client_random = std::move(base16_encode(get_item(tls_context_client_hello_random)));
                std::string keylog_master_secret = std::move(base16_encode(master_secret));
                dbs.printf("\e[1;36m");
                dbs.println("# CLIENT_RANDOM %s %s", keylog_client_random.c_str(), keylog_master_secret.c_str());
                dbs.printf("\e[0m");
                trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
            }
#endif

            auto cs = get_cipher_suite();
            ret = calc_keyblock(hmac_alg, master_secret, client_hello_random, server_hello_random, cs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::calc_keyblock(hash_algorithm_t hmac_alg, const binary_t &master_secret, const binary_t &client_hello_random,
                                       const binary_t &server_hello_random, uint16 cs) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        crypto_hmac_builder builder;
        auto hmac_expansion = builder.set(hmac_alg).set(master_secret).build();
        if (hmac_expansion) {
            bool is_cbc = tlsadvisor->is_kindof_cbc(cs);

            /**
             * key expansion
             * RFC 2246 5. HMAC and the pseudorandom function
             * RFC 2246 6.3. Key calculation
             * RFC 5246 6.3.  Key Calculation
             * key_block = PRF(SecurityParameters.master_secret,
             *                    "key expansion",
             *                    SecurityParameters.server_random +
             *                    SecurityParameters.client_random);
             *
             * client_write_MAC_secret[SecurityParameters.hash_size]
             * server_write_MAC_secret[SecurityParameters.hash_size]
             * client_write_key[SecurityParameters.key_material_length]
             * server_write_key[SecurityParameters.key_material_length]
             * client_write_IV[SecurityParameters.IV_size]
             * server_write_IV[SecurityParameters.IV_size]
             */
            binary_t seed;
            binary_append(seed, "key expansion");
            binary_append(seed, server_hello_random);
            binary_append(seed, client_hello_random);

            auto hint_blockcipher = tlsadvisor->hintof_blockcipher(cs);
            auto hint_digest = tlsadvisor->hintof_digest(cs);
            auto hint_cipher = tlsadvisor->hintof_cipher(cs);
            if (nullptr == hint_blockcipher || nullptr == hint_digest) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            auto mode = typeof_mode(hint_cipher);
            auto keysize = sizeof_key(hint_blockcipher);
            // TLS 1.2 GCM nonce = fixed iv (4) + explitcit iv (8) = 12
            auto ivsize = 0;
            switch (mode) {
                case cbc: {
                    ivsize = sizeof_iv(hint_blockcipher);
                } break;
                case mode_poly1305: {
                    ivsize = 12;
                } break;
                case ccm:
                case gcm: {
                    ivsize = 4;
                } break;
            }
            auto dlen = (is_cbc) ? sizeof_digest(hint_digest) : 0;
            size_t size_keycalc = (dlen << 1) + (keysize << 1) + (ivsize << 1);
            size_t offset = 0;

            // until enough output has been generated
            binary_t p;
            binary_t temp = seed;
            binary_t atemp;
            binary_t ptemp;
            while (p.size() < size_keycalc) {
                hmac_expansion->mac(temp, atemp);
                hmac_expansion->update(atemp).update(seed).finalize(ptemp);
                binary_append(p, ptemp);
                temp = atemp;
            }

            binary_t secret_client_mac_key;
            binary_t secret_server_mac_key;
            binary_t secret_client_key;
            binary_t secret_server_key;
            binary_t secret_client_iv;
            binary_t secret_server_iv;

            // partition
            p.resize(size_keycalc);

            if (is_cbc) {
                binary_append(secret_client_mac_key, &p[offset], dlen);
                offset += dlen;
                binary_append(secret_server_mac_key, &p[offset], dlen);
                offset += dlen;
            }

            binary_append(secret_client_key, &p[offset], keysize);
            offset += keysize;
            binary_append(secret_server_key, &p[offset], keysize);
            offset += keysize;
            binary_append(secret_client_iv, &p[offset], ivsize);
            offset += ivsize;
            binary_append(secret_server_iv, &p[offset], ivsize);
            offset += ivsize;

            if (is_cbc) {
                set_item(tls_secret_client_mac_key, secret_client_mac_key);
                set_item(tls_secret_server_mac_key, secret_server_mac_key);
            }
            set_item(tls_secret_client_key, secret_client_key);
            set_item(tls_secret_server_key, secret_server_key);
            set_item(tls_secret_client_iv, secret_client_iv);
            set_item(tls_secret_server_iv, secret_server_iv);

#if defined DEBUG
            if (istraceable()) {
                basic_stream dbs;
                dbs.printf("\e[1;36m");
                dbs.println("> cipher_suite %s", tlsadvisor->hintof_cipher_suite(cs)->name_iana);
                dbs.println("> master_secret %s", base16_encode(master_secret).c_str());
                dbs.println("> client_hello_random %s", base16_encode(client_hello_random).c_str());
                dbs.println("> server_hello_random %s", base16_encode(server_hello_random).c_str());
                dbs.println("> keyblock %s", base16_encode(p).c_str());
                if (is_cbc) {
                    dbs.println("> secret_client_mac_key[%08x] %s (%zi-octet)", tls_secret_client_mac_key, base16_encode(secret_client_mac_key).c_str(),
                                secret_client_mac_key.size());
                    dbs.println("> secret_server_mac_key[%08x] %s (%zi-octet)", tls_secret_server_mac_key, base16_encode(secret_server_mac_key).c_str(),
                                secret_server_mac_key.size());
                }
                dbs.println("> secret_client_key[%08x] %s (%zi-octet)", tls_secret_client_key, base16_encode(secret_client_key).c_str(),
                            secret_client_key.size());
                dbs.println("> secret_server_key[%08x] %s (%zi-octet)", tls_secret_server_key, base16_encode(secret_server_key).c_str(),
                            secret_server_key.size());
                dbs.println("> secret_client_iv[%08x] %s (%zi-octet)", tls_secret_client_iv, base16_encode(secret_client_iv).c_str(), secret_client_iv.size());
                dbs.println("> secret_server_iv[%08x] %s (%zi-octet)", tls_secret_server_iv, base16_encode(secret_server_iv).c_str(), secret_server_iv.size());
                dbs.printf("\e[0m");
                trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
            }
#endif

            hmac_expansion->release();
        } else {
            ret = errorcode_t::not_supported;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::calc_psk(tls_session *session, const binary_t &binder_hash, const binary_t &psk_binder) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        set_item(tls_context_resumption_binder_hash, binder_hash);  // debug

        // RFC 8448 4.  Resumed 0-RTT Handshake

        openssl_kdf kdf;
        // PRK
        binary_t context_resumption_binder_key;
        const binary_t &secret_resumption_early = get_item(tls_secret_resumption_early);
        const binary_t &context_empty_hash = get_item(tls_context_empty_hash);
        kdf.hkdf_expand_tls13_label(context_resumption_binder_key, sha2_256, 32, secret_resumption_early, "res binder", context_empty_hash);
        set_item(tls_context_resumption_binder_key, context_resumption_binder_key);

        // expanded
        binary_t context_resumption_finished_key;
        binary_t empty_ikm;
        kdf.hkdf_expand_tls13_label(context_resumption_finished_key, sha2_256, 32, context_resumption_binder_key, "finished", empty_ikm);
        set_item(tls_context_resumption_finished_key, context_resumption_finished_key);

        // finished
        binary_t context_resumption_finished;
        openssl_mac mac;
        mac.hmac(sha2_256, context_resumption_finished_key, binder_hash, context_resumption_finished);
        set_item(tls_context_resumption_finished, context_resumption_finished);

        if (psk_binder != context_resumption_finished) {
            ret = errorcode_t::mismatch;
        }
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

return_t tls_protection::calc_finished(tls_direction_t dir, hash_algorithm_t alg, uint16 dlen, tls_secret_t &typeof_secret, binary_t &maced) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (hash_alg_unknown == alg) {
            ret = errorcode_t::unknown;
            __leave2;
        }
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        auto cs = get_cipher_suite();
        const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(cs);

        // https://tls13.xargs.org/#server-handshake-finished/annotated
        binary_t fin_hash;
        auto hash = get_transcript_hash();
        if (hash) {
            hash->digest(fin_hash);
            hash->release();
        }

        // calculate finished "tls13 finished"
        // fin_key : expanded
        // finished == maced

        binary_t fin_key;
        if (is_kindof_tls13()) {
            if (from_server == dir) {
                typeof_secret = tls_secret_s_hs_traffic;
            } else {
                typeof_secret = tls_secret_c_hs_traffic;
            }
            const binary_t &ht_secret = get_item(typeof_secret);
            hash_algorithm_t hashalg = tlsadvisor->hash_alg_of(get_cipher_suite());
            openssl_kdf kdf;
            binary_t context;
            if (is_kindof_dtls()) {
                kdf.hkdf_expand_dtls13_label(fin_key, hashalg, dlen, ht_secret, "finished", context);
            } else {
                kdf.hkdf_expand_tls13_label(fin_key, hashalg, dlen, ht_secret, "finished", context);
            }
            crypto_hmac_builder builder;
            crypto_hmac *hmac = builder.set(hashalg).set(fin_key).build();
            if (hmac) {
                hmac->mac(fin_hash, maced);
                hmac->release();
            }
#if defined DEBUG
            if (istraceable()) {
                basic_stream dbs;
                dbs.println("> finished");
                dbs.println("  key   %s", base16_encode(fin_key).c_str());
                dbs.println("  hash  %s", base16_encode(fin_hash).c_str());
                dbs.println("  maced %s", base16_encode(maced).c_str());
                trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
            }
#endif
        } else {
            binary_t seed;
            if (from_client == dir) {
                binary_append(seed, "client finished");
            } else {
                binary_append(seed, "server finished");
            }
            binary_append(seed, fin_hash);

            typeof_secret = tls_secret_master;
            const binary_t &fin_key = get_item(typeof_secret);

            crypto_hmac_builder builder;
            auto hmac = builder.set(alg).set(fin_key).build();
            size_t size_maced = 12;
            if (hmac) {
                binary_t temp = seed;
                binary_t atemp;
                binary_t ptemp;
                while (maced.size() < size_maced) {
                    hmac->mac(temp, atemp);
                    hmac->update(atemp).update(seed).finalize(ptemp);
                    binary_append(maced, ptemp);
                    temp = atemp;
                }
                hmac->release();
                maced.resize(size_maced);
            }
#if defined DEBUG
            if (istraceable()) {
                basic_stream dbs;
                dbs.println("> finished");
                dbs.println("  key   %s", base16_encode(fin_key).c_str());
                dbs.println("  hash  %s", base16_encode(fin_hash).c_str());
                dbs.println("  maced %s", base16_encode(maced).c_str());
                trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
            }
#endif
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
