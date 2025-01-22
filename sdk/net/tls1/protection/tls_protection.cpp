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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/evp_key.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/crypto/crypto_aead.hpp>
#include <sdk/crypto/crypto/crypto_hash.hpp>
#include <sdk/crypto/crypto/crypto_hmac.hpp>
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/crypto/crypto/transcript_hash.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_protection.hpp>
#include <sdk/net/tls1/tls_session.hpp>
// debug
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {
namespace net {

tls_protection::tls_protection(uint8 mode)
    : _mode(mode), _flow(tls_1_rtt), _ciphersuite(0), _record_version(tls_12), _version(tls_10), _transcript_hash(nullptr), _use_pre_master_secret(false) {}

tls_protection::~tls_protection() {
    if (_transcript_hash) {
        _transcript_hash->release();
    }
}

uint8 tls_protection::get_mode() { return _mode; }

tls_message_flow_t tls_protection::get_flow() { return _flow; }

void tls_protection::set_flow(tls_message_flow_t flow) { _flow = flow; }

uint16 tls_protection::get_cipher_suite() { return _ciphersuite; }

void tls_protection::set_cipher_suite(uint16 ciphersuite) { _ciphersuite = ciphersuite; }

uint16 tls_protection::get_record_version() { return _record_version; }

void tls_protection::set_record_version(uint16 version) { _record_version = version; }

bool tls_protection::is_kindof_tls() { return (false == tls_advisor::get_instance()->is_kindof_dtls(_record_version)); }

bool tls_protection::is_kindof_dtls() { return tls_advisor::get_instance()->is_kindof_dtls(_record_version); }

uint16 tls_protection::get_tls_version() { return _version; }

void tls_protection::set_tls_version(uint16 version) { _version = version; }

transcript_hash *tls_protection::get_transcript_hash() {
    critical_section_guard guard(_lock);
    if (nullptr == _transcript_hash) {
        if (get_cipher_suite()) {
            tls_advisor *tlsadvisor = tls_advisor::get_instance();
            auto cipher_suite = get_cipher_suite();
            const tls_cipher_suite_t *hint_tls_alg = tlsadvisor->hintof_cipher_suite(cipher_suite);
            auto hashalg = algof_mac(hint_tls_alg);
            transcript_hash_builder builder;
            _transcript_hash = builder.set(hashalg).build();

            if (istraceable()) {
                constexpr char constexpr_transcript_hash[] = "starting transcript_hash";
                constexpr char constexpr_cipher_suite[] = "cipher suite";
                crypto_advisor *advisor = crypto_advisor::get_instance();
                tls_advisor *tlsadvisor = tls_advisor::get_instance();
                auto mdname = advisor->nameof_md(hashalg);
                basic_stream dbs;
                dbs.printf("# %s\n", constexpr_transcript_hash);
                dbs.printf(" > %s 0x%04x %s\n", constexpr_cipher_suite, cipher_suite, tlsadvisor->cipher_suite_string(cipher_suite).c_str());
                dbs.printf(" > %s\n", mdname);
                trace_debug_event(category_debug_internal, 0, &dbs);
            }
        }
    }
    if (_transcript_hash) {
        _transcript_hash->addref();
    }
    return _transcript_hash;
}

return_t tls_protection::calc_transcript_hash(tls_session *session, const byte_t *stream, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        auto hash = get_transcript_hash();
        if (hash) {
            if (is_kindof_dtls()) {
                basic_stream bs;
                // DTLS
                size_t offset_version = 12;
                size_t sizeof_reconstruction_data = 8;
                //  0.. 3 handshake header
                hash->update(stream, sizeof(tls_handshake_t));
                //  4..11 handshake reconstruction data (8 bytes)
                //
                // 12.. $ handshake, extension
                hash->update(stream + offset_version, size - offset_version);
            } else {
                // TLS
                // hash->digest(stream, size, digest);
                hash->update(stream, size);
            }

            hash->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::calc_transcript_hash(tls_session *session, const byte_t *stream, size_t size, binary_t &digest) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        calc_transcript_hash(session, stream, size);

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        auto hash = get_transcript_hash();
        if (hash) {
            hash->digest(digest);
            hash->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
};

return_t tls_protection::reset_transcript_hash(tls_session *session) {
    return_t ret = errorcode_t::success;
    auto hash = get_transcript_hash();
    if (hash) {
        hash->reset();
        hash->release();
    }
    return ret;
}

return_t tls_protection::calc_context_hash(tls_session *session, hash_algorithm_t alg, const byte_t *stream, size_t size, binary_t &digest) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || (size && (nullptr == stream))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // The hash does not include DTLS-only bytes in the records.
        // --> The hash does not include handshake reconstruction data bytes in the
        // records.

        transcript_hash_builder builder;
        auto hash = builder.set(alg).build();
        if (hash) {
            if (is_kindof_dtls()) {
                basic_stream bs;
                // DTLS
                size_t offset_version = 12;
                size_t sizeof_reconstruction_data = 8;
                //  0.. 3 handshake header
                hash->update(stream, sizeof(tls_handshake_t));
                //  4..11 handshake reconstruction data (8 bytes)
                //
                // 12.. $ handshake, extension
                hash->update(stream + offset_version, size - offset_version);
                hash->digest(digest);
            } else {
                // TLS
                // hash->digest(stream, size, digest);
                hash->update(stream, size);
                hash->digest(digest);
            }

            hash->release();
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

crypto_key &tls_protection::get_keyexchange() { return _keyexchange; }

void tls_protection::use_pre_master_secret(bool use) { _use_pre_master_secret = use; }

bool tls_protection::use_pre_master_secret() { return _use_pre_master_secret; }

return_t tls_protection::calc(tls_session *session, tls_hs_type_t type, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    // RFC 8446 7.1.  Key Schedule
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint16 cipher_suite = get_cipher_suite();

        crypto_advisor *advisor = crypto_advisor::get_instance();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        const tls_cipher_suite_t *hint_tls_alg = tlsadvisor->hintof_cipher_suite(cipher_suite);
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        const hint_blockcipher_t *hint_cipher = advisor->hintof_blockcipher(hint_tls_alg->cipher);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        const hint_digest_t *hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
        if (nullptr == hint_mac) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto keysize = hint_cipher->keysize;
        auto dlen = hint_mac->digest_size;
        auto hashalg = hint_mac->fetchname;

        openssl_kdf kdf;
        binary_t empty;      // empty
        binary_t empty_ikm;  // dlen 00..
        binary_t empty_hash;

        {
            openssl_digest dgst;
            binary_t empty;
            dgst.digest(hashalg, empty, empty_hash);
            _kv[tls_context_empty_hash] = empty_hash;
        }
        empty_ikm.resize(dlen);

        auto lambda_expand_label = [&](tls_secret_t sec, binary_t &okm, const char *hashalg, uint16 dlen, const binary_t &secret, const char *label,
                                       const binary_t &context) -> void {
            okm.clear();
            if (session->get_tls_protection().is_kindof_dtls()) {
                kdf.hkdf_expand_dtls13_label(okm, hashalg, dlen, secret, str2bin(label), context);
            } else {
                kdf.hkdf_expand_tls13_label(okm, hashalg, dlen, secret, str2bin(label), context);
            }
            _kv[sec] = okm;
        };
        auto lambda_extract = [&](tls_secret_t sec, binary_t &prk, const char *hashalg, const binary_t &salt, const binary_t &ikm) -> void {
            kdf.hmac_kdf_extract(prk, hashalg, salt, ikm);
            _kv[sec] = prk;
        };

        binary_t context_hash;
        // server_hello~ or 0-RTT client_hello~
        auto tshash = get_transcript_hash();
        if (tshash) {
            tshash->digest(context_hash);
            tshash->release();
            _kv[tls_context_transcript_hash] = context_hash;
        }

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

            // res binder (see tls1_ext_pre_shared_key)
            // exp master (see tls_context_server_finished)

            if (tls_0_rtt == get_flow()) {
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
                    pkey_priv = get_keyexchange().find("server");
                    if (pkey_priv) {
                        // in server ... priv("server") + pub("CH")
                        pkey_pub = get_keyexchange().find("CH");  // client_hello
                    } else {
                        // in client ... priv("client") + pub("SH")
                        pkey_priv = get_keyexchange().find("client");
                        pkey_pub = get_keyexchange().find("SH");  // server_hello
                    }

                    if (nullptr == pkey_priv || nullptr == pkey_pub) {
                        auto tlsversion = get_tls_version();
                        if (is_basedon_tls13(tlsversion)) {
                            ret = errorcode_t::not_found;
                        }
                        __leave2;
                    }

                    uint32 nid_priv = 0;
                    uint32 nid_pub = 0;
                    nidof_evp_pkey(pkey_priv, nid_priv);
                    nidof_evp_pkey(pkey_pub, nid_pub);
                    if (nid_priv != nid_pub) {
                        ret = errorcode_t::different_type;
                        __leave2;  // HRR
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
                switch (get_flow()) {
                    case tls_1_rtt:
                    case tls_hello_retry_request: {
                        lambda_expand_label(tls_secret_handshake_derived, secret_handshake_derived, hashalg, dlen, early_secret, "derived", empty_hash);
                    } break;
                    case tls_0_rtt: {
                        const binary_t &secret_resumption_early = get_item(tls_secret_resumption_early);
                        lambda_expand_label(tls_secret_handshake_derived, secret_handshake_derived, hashalg, dlen, secret_resumption_early, "derived",
                                            empty_hash);
                    } break;
                }

                binary_t secret_handshake;
                lambda_extract(tls_secret_handshake, secret_handshake, hashalg, secret_handshake_derived, shared_secret);

                switch (get_flow()) {
                    case tls_1_rtt:
                    case tls_0_rtt: {
                        // client_handshake_traffic_secret
                        lambda_expand_label(tls_secret_c_hs_traffic, secret_handshake_client, hashalg, dlen, secret_handshake, "c hs traffic", context_hash);
                        // server_handshake_traffic_secret
                        lambda_expand_label(tls_secret_s_hs_traffic, secret_handshake_server, hashalg, dlen, secret_handshake, "s hs traffic", context_hash);
                    } break;
                    case tls_hello_retry_request: {
                        // client_handshake_traffic_secret
                        lambda_expand_label(tls_secret_c_hs_traffic, secret_handshake_client, hashalg, dlen, secret_handshake, "c hs traffic", context_hash);
                        // server_handshake_traffic_secret
                        lambda_expand_label(tls_secret_s_hs_traffic, secret_handshake_server, hashalg, dlen, secret_handshake, "s hs traffic", context_hash);
                    } break;
                }

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
            if (tls_mode_dtls & get_mode()) {
                lambda_expand_label(tls_secret_handshake_client_sn_key, okm, hashalg, keysize, secret_handshake_client, "sn", empty);
                lambda_expand_label(tls_secret_handshake_server_sn_key, okm, hashalg, keysize, secret_handshake_server, "sn", empty);
            }
            if (tls_mode_quic & get_mode()) {
                lambda_expand_label(tls_secret_handshake_quic_client_key, okm, hashalg, keysize, secret_handshake_client, "quic key", empty);
                lambda_expand_label(tls_secret_handshake_quic_client_iv, okm, hashalg, 12, secret_handshake_client, "quic iv", empty);
                lambda_expand_label(tls_secret_handshake_quic_client_hp, okm, hashalg, keysize, secret_handshake_client, "quic hp", empty);
                lambda_expand_label(tls_secret_handshake_quic_server_key, okm, hashalg, keysize, secret_handshake_server, "quic key", empty);
                lambda_expand_label(tls_secret_handshake_quic_server_iv, okm, hashalg, 12, secret_handshake_server, "quic iv", empty);
                lambda_expand_label(tls_secret_handshake_quic_server_hp, okm, hashalg, keysize, secret_handshake_server, "quic hp", empty);
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
            if (tls_mode_dtls & get_mode()) {
                lambda_expand_label(tls_secret_application_server_sn_key, okm, hashalg, keysize, secret_application_server, "sn", empty);
            }

            if (tls_mode_quic & get_mode()) {
                lambda_expand_label(tls_secret_application_quic_client_key, okm, hashalg, keysize, secret_application_client, "quic key", empty);
                lambda_expand_label(tls_secret_application_quic_client_iv, okm, hashalg, 12, secret_application_client, "quic iv", empty);
                lambda_expand_label(tls_secret_application_quic_client_hp, okm, hashalg, keysize, secret_application_client, "quic hp", empty);
                lambda_expand_label(tls_secret_application_quic_server_key, okm, hashalg, keysize, secret_application_server, "quic key", empty);
                lambda_expand_label(tls_secret_application_quic_server_iv, okm, hashalg, 12, secret_application_server, "quic iv", empty);
                lambda_expand_label(tls_secret_application_quic_server_hp, okm, hashalg, keysize, secret_application_server, "quic hp", empty);
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
            if (tls_mode_dtls & get_mode()) {
                auto const &secret_application_client = get_item(tls_secret_c_ap_traffic);
                lambda_expand_label(tls_secret_application_client_sn_key, okm, hashalg, keysize, secret_application_client, "sn", empty);
            }

        } else if (tls_hs_client_key_exchange == type) {
            /**
             * RFC 5246 8.1.  Computing the Master Secret
             * master_secret = PRF(pre_master_secret, "master secret",
             *                     ClientHello.random + ServerHello.random)
             *                     [0..47];
             */

            hash_algorithm_t hmac_alg = algof_mac(hint_tls_alg);

            binary_t pre_master_secret;
            binary_t master_secret;
            const binary_t &client_hello_random = get_item(tls_context_client_hello_random);
            const binary_t &server_hello_random = get_item(tls_context_server_hello_random);

            {
                const EVP_PKEY *pkey_priv = nullptr;
                const EVP_PKEY *pkey_pub = nullptr;
                if (from_server == dir) {
                    pkey_priv = get_keyexchange().find("server");
                    pkey_pub = get_keyexchange().find("CKE");
                } else {
                    pkey_priv = get_keyexchange().find("client");
                    pkey_pub = get_keyexchange().find("SKE");
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

            crypto_hmac_builder builder;
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
                 */
                binary_t seed;
                hash_context_t *hmac_handle = nullptr;
                size_t size_master_secret = 48;

                binary_append(seed, str2bin("master secret"));
                binary_append(seed, client_hello_random);
                binary_append(seed, server_hello_random);

                binary_t temp = seed;
                binary_t atemp;
                binary_t ptemp;
                while (master_secret.size() < size_master_secret) {
                    hmac_master->mac(temp, atemp);
                    hmac_master->update(atemp).update(seed).finalize(ptemp);
                    binary_append(master_secret, ptemp);
                    temp = atemp;
                }

                master_secret.resize(48);

                set_item(tls_secret_master, master_secret);

                hmac_master->release();
            } else {
                ret = errorcode_t::not_supported;
                __leave2;
            }

            auto hmac_expansion = builder.set(hmac_alg).set(master_secret).build();
            if (hmac_expansion) {
                /**
                 * key expansion
                 * RFC 2246 5. HMAC and the pseudorandom function
                 * RFC 2246 6.3. Key calculation
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
                binary_append(seed, str2bin("key expansion"));
                binary_append(seed, server_hello_random);
                binary_append(seed, client_hello_random);

                uint16 ciphersuite = get_cipher_suite();
                auto hint_cipher = tlsadvisor->hintof_blockcipher(ciphersuite);
                auto hint_digest = tlsadvisor->hintof_digest(ciphersuite);
                if (nullptr == hint_cipher || nullptr == hint_digest) {
                    ret = errorcode_t::not_supported;
                    __leave2;
                }
                auto keysize = sizeof_key(hint_cipher);
                auto ivsize = sizeof_iv(hint_cipher);
                auto dlen = sizeof_digest(hint_digest);
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
                binary_append(secret_client_mac_key, &p[offset], dlen);
                offset += dlen;
                binary_append(secret_server_mac_key, &p[offset], dlen);
                offset += dlen;
                binary_append(secret_client_key, &p[offset], keysize);
                offset += keysize;
                binary_append(secret_server_key, &p[offset], keysize);
                offset += keysize;
                binary_append(secret_client_iv, &p[offset], ivsize);
                offset += ivsize;
                binary_append(secret_server_iv, &p[offset], ivsize);
                offset += ivsize;

                set_item(tls_secret_client_mac_key, secret_client_mac_key);
                set_item(tls_secret_server_mac_key, secret_server_mac_key);
                set_item(tls_secret_client_key, secret_client_key);
                set_item(tls_secret_server_key, secret_server_key);
                set_item(tls_secret_client_iv, secret_client_iv);
                set_item(tls_secret_server_iv, secret_server_iv);

                hmac_expansion->release();
            } else {
                ret = errorcode_t::not_supported;
                __leave2;
            }
        }
    }
    __finally2 {
        // do nothing
    }
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

void tls_protection::get_item(tls_secret_t type, binary_t &item) { item = _kv[type]; }

const binary_t &tls_protection::get_item(tls_secret_t type) { return _kv[type]; }

void tls_protection::set_item(tls_secret_t type, const binary_t &item) { _kv[type] = item; }

void tls_protection::set_item(tls_secret_t type, const byte_t *stream, size_t size) {
    if (stream) {
        binary_t bin;
        bin.insert(bin.end(), stream, stream + size);
        _kv[type] = std::move(bin);
    }
}

void tls_protection::clear_item(tls_secret_t type) {
    auto iter = _kv.find(type);
    if (_kv.end() != iter) {
        _kv.erase(iter);
    }
}

size_t tls_protection::get_header_size() {
    size_t ret_value = 0;
    auto record_version = get_record_version();
    size_t content_header_size = 0;
    tls_advisor *tlsadvisor = tls_advisor::get_instance();
    if (tlsadvisor->is_kindof_dtls(record_version)) {
        content_header_size = RTL_FIELD_SIZE(tls_content_t, dtls);
    } else {
        content_header_size = RTL_FIELD_SIZE(tls_content_t, tls);
    }
    ret_value = content_header_size;
    return ret_value;
}

uint8 tls_protection::get_tag_size() {
    uint8 ret_value = 0;
    crypto_advisor *advisor = crypto_advisor::get_instance();
    tls_advisor *tlsadvisor = tls_advisor::get_instance();
    const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
    if (hint) {
        auto hmac_alg = hint->mac;
        auto hint_digest = advisor->hintof_digest(hmac_alg);

        auto cipher = hint->cipher;
        auto mode = hint->mode;
        auto dlen = sizeof_digest(hint_digest);

        switch (mode) {
            case gcm:
            case mode_poly1305:
                ret_value = 16;
                break;
            case ccm:
                ret_value = 14;
                break;
            case ccm8:
                ret_value = 8;
                break;
            default:
                ret_value = dlen;
                break;
        }
    }
    return ret_value;
}

return_t tls_protection::build_iv(tls_session *session, tls_secret_t type, binary_t &iv, uint64 recordno) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        iv = get_item(type);
        if (iv.empty()) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        for (uint64 i = 0; i < 8; i++) {
            iv[12 - 1 - i] ^= ((recordno >> (i * 8)) & 0xff);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::get_tls13_key(tls_session *session, tls_direction_t dir, tls_secret_t &secret_key, tls_secret_t &secret_iv) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto hsstatus = session->get_session_info(dir).get_status();

        if (from_client == dir) {
            auto flow = get_flow();
            if (tls_1_rtt == flow || tls_hello_retry_request == flow) {
                if (tls_hs_finished == hsstatus) {
                    secret_key = tls_secret_application_client_key;
                    secret_iv = tls_secret_application_client_iv;
                } else {
                    secret_key = tls_secret_handshake_client_key;
                    secret_iv = tls_secret_handshake_client_iv;
                }
            } else {
                // 1-RTT
                // 0-RTT
                // client_hello         c e traffic
                // end_of_early_data    c hs traffic
                // finished             c ap traffic
                switch (hsstatus) {
                    case tls_hs_end_of_early_data: {
                        secret_key = tls_secret_handshake_client_key;
                        secret_iv = tls_secret_handshake_client_iv;
                    } break;
                    case tls_hs_finished: {
                        secret_key = tls_secret_application_client_key;
                        secret_iv = tls_secret_application_client_iv;
                    } break;
                    case tls_hs_client_hello:
                    default: {
                        // use early traffic
                        secret_key = tls_secret_c_e_traffic_key;
                        secret_iv = tls_secret_c_e_traffic_iv;
                    } break;
                }
            }
        } else {
            // from_server
            if (tls_hs_finished == hsstatus) {
                secret_key = tls_secret_application_server_key;
                secret_iv = tls_secret_application_server_iv;
            } else {
                secret_key = tls_secret_handshake_server_key;
                secret_iv = tls_secret_handshake_server_iv;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::get_tls1_key(tls_session *session, tls_direction_t dir, tls_secret_t &secret_key, tls_secret_t &secret_mac_key) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_client == dir) {
            secret_key = tls_secret_client_key;
            secret_mac_key = tls_secret_client_mac_key;
        } else {
            secret_key = tls_secret_server_key;
            secret_mac_key = tls_secret_server_mac_key;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::encrypt_tls13(tls_session *session, tls_direction_t dir, const binary_t &plaintext, binary_t &ciphertext, const binary_t &aad,
                                       binary_t &tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto record_version = get_record_version();
        size_t content_header_size = 0;
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        auto cipher = crypt_alg_unknown;
        auto mode = mode_unknown;
        uint8 tagsize = 0;

        {
            const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
            if (nullptr == hint) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            cipher = hint->cipher;
            mode = hint->mode;
        }

        crypt_context_t *handle = nullptr;
        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_iv;
        get_tls13_key(session, dir, secret_key, secret_iv);

        uint64 record_no = 0;
        record_no = session->get_recordno(dir, true);

        auto const &key = get_item(secret_key);
        auto const &iv = get_item(secret_iv);
        binary_t nonce = iv;
        build_iv(session, secret_iv, nonce, record_no);
        ret = crypt.encrypt(cipher, mode, key, nonce, plaintext, ciphertext, aad, tag);

        if (istraceable()) {
            basic_stream dbs;
            dbs.autoindent(3);
            dbs.printf(" > encrypt\n");
            dbs.printf(" > key[%08x] %s\n", secret_key, base16_encode(key).c_str());
            dbs.printf(" > iv [%08x] %s\n", secret_iv, base16_encode(iv).c_str());
            dbs.printf(" > record no %i\n", record_no);
            dbs.printf(" > nonce %s\n", base16_encode(nonce).c_str());
            dbs.printf(" > aad %s\n", base16_encode(aad).c_str());
            dbs.printf(" > tag %s\n", base16_encode(tag).c_str());
            dbs.printf(" > plaintext\n");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.printf(" > ciphertext\n");
            dump_memory(ciphertext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.autoindent(0);
            trace_debug_event(category_tls1, tls_event_write, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::encrypt_tls1(tls_session *session, tls_direction_t dir, const binary_t &plaintext, binary_t &ciphertext, binary_t &maced) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const byte_t *stream = &plaintext[0];

        crypto_advisor *advisor = crypto_advisor::get_instance();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto hint_cipher = advisor->hintof_blockcipher(hint->cipher);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto ivsize = sizeof_iv(hint_cipher);

        auto record_version = get_record_version();
        size_t content_header_size = get_header_size();

        crypt_context_t *handle = nullptr;
        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_mac_key;
        get_tls1_key(session, dir, secret_key, secret_mac_key);

        uint64 record_no = 0;
        record_no = session->get_recordno(dir, true);

        const binary_t &key = get_item(secret_key);
        binary_t iv;
        binary_append(iv, stream + content_header_size, ivsize);
        size_t bpos = content_header_size + ivsize;

        ret = crypt.open(&handle, hint->cipher, hint->mode, key, iv);
        if (errorcode_t::success == ret) {
            crypt.set(handle, crypt_ctrl_padding, 0);
            ret = crypt.encrypt(handle, &plaintext[0], plaintext.size(), ciphertext);
            crypt.close(handle);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // MAC
        binary_t content;
        binary_t verifydata;
        binary_t maced;
        const binary_t &mackey = get_item(secret_mac_key);
        {
            auto hmac_alg = hint->mac;  // do not promote insecure algorithm (ex. don'tcall algof_mac)
            auto hint_digest = advisor->hintof_digest(hmac_alg);
            auto dlen = sizeof_digest(hint_digest);

            uint8 pad = *plaintext.rbegin();
            size_t plaintextsize = plaintext.size() - pad - 1;

            size_t datalen = plaintextsize - dlen;
            binary_append(content, uint64(record_no), hton64);     // sequence
            binary_append(content, stream, 3);                     // rechdr (content_type, version)
            binary_append(content, uint16(datalen), hton16);       // datalen
            binary_append(content, &plaintext[0], datalen);        // data
            binary_append(verifydata, &plaintext[datalen], dlen);  // verifydata

            crypto_hmac_builder builder;
            auto hmac = builder.set(hint->mac).set(mackey).build();
            if (hmac) {
                hmac->update(content).finalize(maced);
                hmac->release();
            }
            // if (maced != verifydata) {
            //     ret = errorcode_t::mismatch;
            // }
        }

        if (istraceable()) {
            basic_stream dbs;
            dbs.autoindent(3);
            dbs.printf(" > key %s\n", base16_encode(key).c_str());
            dbs.printf(" > iv %s\n", base16_encode(iv).c_str());
            dbs.printf(" > mackey %s\n", base16_encode(mackey).c_str());
            dbs.printf(" > record no %i\n", record_no);
            dbs.printf(" > ciphertext\n");
            dump_memory(ciphertext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.printf(" > plaintext\n");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.printf(" > content\n");
            dump_memory(content, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.autoindent(0);

            trace_debug_event(category_tls1, tls_event_write, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt_tls13(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t content_header_size = 0;
        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        size_t aadlen = get_header_size();

        binary_t aad;
        binary_append(aad, stream + pos, aadlen);

        ret = decrypt_tls13(session, dir, stream, size, pos, plaintext, aad);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt_tls13(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext,
                                       const binary_t &aad) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto cipher = crypt_alg_unknown;
        auto mode = mode_unknown;
        uint8 tagsize = get_tag_size();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        {
            const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
            if (nullptr == hint) {
                ret = errorcode_t::not_supported;
                __leave2;
            }
            cipher = hint->cipher;
            mode = hint->mode;
            // switch (mode) {
            //     case gcm:
            //     case ccm:
            //         tagsize = 16;
            //         break;
            //     case ccm8:
            //         tagsize = 8;
            //         break;
            //     default:
            //         break;
            // }
        }

        auto record_version = get_record_version();
        binary_t tag;

        // ... aad(aadlen) encdata tag(tagsize)
        //     \_ pos
        size_t aadlen = aad.size();
        binary_append(tag, stream + pos + aadlen + size - tagsize, tagsize);

        crypt_context_t *handle = nullptr;
        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_iv;
        get_tls13_key(session, dir, secret_key, secret_iv);

        uint64 record_no = 0;
        record_no = session->get_recordno(dir, true);

        auto const &key = get_item(secret_key);
        auto const &iv = get_item(secret_iv);
        binary_t nonce = iv;
        build_iv(session, secret_iv, nonce, record_no);
        ret = crypt.decrypt(cipher, mode, key, nonce, stream + pos + aadlen, size - tagsize, plaintext, aad, tag);

        if (istraceable()) {
            basic_stream dbs;
            dbs.autoindent(3);
            dbs.printf(" > decrypt\n");
            dbs.printf(" > key[%08x] %s\n", secret_key, base16_encode(key).c_str());
            dbs.printf(" > iv [%08x] %s\n", secret_iv, base16_encode(iv).c_str());
            dbs.printf(" > record no %i\n", record_no);
            dbs.printf(" > nonce %s\n", base16_encode(nonce).c_str());
            dbs.printf(" > aad %s\n", base16_encode(aad).c_str());
            dbs.printf(" > tag %s\n", base16_encode(tag).c_str());
            dbs.printf(" > ciphertext\n");
            dump_memory(stream + pos + aadlen, size - tagsize, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.printf(" > plaintext\n");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.autoindent(0);

            trace_debug_event(category_tls1, tls_event_read, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt_tls1(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor *advisor = crypto_advisor::get_instance();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(get_cipher_suite());
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto hint_cipher = advisor->hintof_blockcipher(hint->cipher);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto ivsize = sizeof_iv(hint_cipher);

        auto record_version = get_record_version();
        size_t content_header_size = get_header_size();

        crypt_context_t *handle = nullptr;
        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_mac_key;
        get_tls1_key(session, dir, secret_key, secret_mac_key);

        uint64 record_no = 0;
        record_no = session->get_recordno(dir, true);

        const binary_t &key = get_item(secret_key);
        binary_t iv;
        binary_append(iv, stream + content_header_size, ivsize);
        size_t bpos = content_header_size + ivsize;

        auto enc_alg = hint->cipher;
        auto hmac_alg = hint->mac; // do not promote insecure algorithm
        const binary_t &mackey = get_item(secret_mac_key);
        binary_t verifydata;
        binary_t aad;
        binary_append(aad, uint64(record_no), hton64);  // sequence
        binary_append(aad, stream, 3);                  // rechdr (content_type, version)
        size_t plainsize = 0;

        ret = crypt.cbc_hmac_tls_decrypt(enc_alg, hmac_alg, key, mackey, iv, aad, stream + bpos, size - bpos, plaintext, plainsize);

        if (istraceable()) {
            basic_stream dbs;
            dbs.autoindent(3);
            dbs.printf(" > key %s\n", base16_encode(key).c_str());
            dbs.printf(" > iv %s\n", base16_encode(iv).c_str());
            dbs.printf(" > mackey %s\n", base16_encode(mackey).c_str());
            dbs.printf(" > record no %i\n", record_no);
            dbs.printf(" > ciphertext\n");
            dump_memory(stream + bpos, size - bpos, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.printf(" > plaintext\n");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.autoindent(0);

            trace_debug_event(category_tls1, tls_event_read, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::get_ecdsa_signature(uint16 scheme, const binary_t &asn1der, binary_t &signature) {
    return_t ret = errorcode_t::success;

    __try2 {
        signature.clear();

        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        auto hint = tlsadvisor->hintof_signature_scheme(scheme);
        if (nullptr == hint) {
            ret = errorcode_t::success;
            __leave2;
        }
        if (crypt_sig_ecdsa != hint->sigtype) {
            ret = different_type;
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
        pl.read(&asn1der[0], asn1der.size(), spos);

        binary_t r;
        binary_t s;

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

        binary_append(signature, r);
        binary_append(signature, s);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::construct_certificate_verify_message(tls_direction_t dir, basic_stream &message) {
    return_t ret = errorcode_t::success;

    binary_t transcripthash;
    auto hash = get_transcript_hash();  // hash(client_hello .. certificate)
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
    message.fill(1, 0x00);  // single 0 byte
    message.write(&transcripthash[0],
                  transcripthash.size());  // content to be signed

    return ret;
}

return_t tls_protection::calc_finished(tls_direction_t dir, hash_algorithm_t alg, uint16 dlen, tls_secret_t &typeof_secret, binary_t &maced) {
    return_t ret = errorcode_t::success;

    tls_advisor *tlsadvisor = tls_advisor::get_instance();

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
    auto tlsversion = get_tls_version();
    if (is_basedon_tls13(tlsversion)) {
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
            kdf.hkdf_expand_dtls13_label(fin_key, hashalg, dlen, ht_secret, str2bin("finished"), context);
        } else {
            kdf.hkdf_expand_tls13_label(fin_key, hashalg, dlen, ht_secret, str2bin("finished"), context);
        }
        crypto_hmac_builder builder;
        crypto_hmac *hmac = builder.set(hashalg).set(fin_key).build();
        if (hmac) {
            hmac->mac(fin_hash, maced);
            hmac->release();
        }
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
    }
    return ret;
}

protection_context &tls_protection::get_protection_context() { return _handshake_context; }

}  // namespace net
}  // namespace hotplace
