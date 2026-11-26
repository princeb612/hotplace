/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_encryption_aead.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/cipher_encrypt.hpp>
#include <hotplace/sdk/crypto/basic/crypto_cbc_hmac.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/dtls_record_arrange.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

namespace {

constexpr uint64 tls1_3_aes_gcm_max_records = 23726566ULL;        // floor(2^24.5)
constexpr uint64 tls1_3_aes_gcm_max_plaintext = 388736063996ULL;  // floor(2^38.5) bytes
constexpr uint64 tls1_3_aes_ccm_max_records = (1ULL << 21);       // conservative multi-key profile bound
constexpr uint64 tls1_3_aes_ccm_max_plaintext = (1ULL << 35);     // 2^35 bytes per key

static bool tls1_3_key_usage_limit(uint16 cipher_suite, uint64& max_records, uint64& max_plaintext) {
    switch (cipher_suite) {
        case 0x1301:  // TLS_AES_128_GCM_SHA256
        case 0x1302:  // TLS_AES_256_GCM_SHA384
            // RFC 9846 §5.5: 2^24.5 full-size records; the byte ceiling is
            // derived from the corresponding 2^38.5-byte full-size volume.
            max_records = tls1_3_aes_gcm_max_records;
            max_plaintext = tls1_3_aes_gcm_max_plaintext;
            return true;
        case 0x1304:  // TLS_AES_128_CCM_SHA256
        case 0x1305:  // TLS_AES_128_CCM_8_SHA256
            // Conservative local policy based on draft-irtf-cfrg-aead-limits-13 §7.3:
            // target AEA <= 2^-57, at most five traffic keys, L <= 2^11 blocks,
            // C <= 2^33 blocks per key, q <= 5 * 2^21, v = 1, and o <= 2^64.
            // This is a work-in-progress profile bound, not a TLS RFC numeric limit.
            max_records = tls1_3_aes_ccm_max_records;
            max_plaintext = tls1_3_aes_ccm_max_plaintext;
            return true;
        case 0x1303:  // TLS_CHACHA20_POLY1305_SHA256
            // ChaCha20-Poly1305's TLS sequence number is the limiting bound.
            max_records = ~static_cast<uint64>(0);
            max_plaintext = ~static_cast<uint64>(0);
            return true;
        default:
            return false;
    }
}

static bool tls1_3_is_alert_plaintext(const binary_t& plaintext) {
    size_t type_pos = plaintext.size();
    while (type_pos && (0 == plaintext[type_pos - 1])) {
        --type_pos;
    }
    return (3 == type_pos) && (tls_content_type_t::alert == (tls_content_type_t)plaintext[type_pos - 1]);
}

}  // namespace

constexpr char constexpr_content_type[] = "record content type";
constexpr char constexpr_record_version[] = "record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_tls[] = "tls";
constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_record_no[] = "record no";
constexpr char constexpr_dtls_epoch[] = "epoch";
constexpr char constexpr_dtls_record_seq[] = "sequence number";

return_t tls_protection::build_iv(tls_session* session, binary_t& nonce, const binary_t& iv, uint64 recordno) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (iv.empty()) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        //          0123456789abc
        //  IV      IIIIIIIIIIIII
        //  RECNO       NNNNNNNNN
        //  NONCE   IIIIXXXXXXXXX

        nonce = iv;
        for (uint64 i = 0; i < 8; i++) {
            auto v = iv[12 - 1 - i];
            auto n = ((recordno >> (i * 8)) & 0xff);
            nonce[12 - 1 - i] = uint8(v ^ n);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::build_tls1_2_aad_from_record(tls_session* session, tls_direction_t dir, binary_t& aad, const binary_t& record_header, uint64 record_no,
                                                      uint8 size_nonce_explicit) {
    return_t ret = errorcode_t::success;

    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    uint8 content_type = 0;
    uint16 record_version = 0;
    uint16 len = 0;
    bool cond_dtls = false;
    uint16 key_epoch = 0;
    uint64 dtls_record_seq = 0;

    {
        payload pl;
        pl << new payload_member(uint8(0), constexpr_content_type)                              // tls, dtls
           << new payload_member(uint16(0), true, constexpr_record_version)                     // tls, dtls
           << new payload_member(uint16(0), true, constexpr_dtls_epoch, constexpr_group_dtls)   // dtls
           << new payload_member(uint48_t(0), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
           << new payload_member(uint16(0), true, constexpr_len);                               // tls, dtls

        auto lambda_check_dtls = [&tlsadvisor](payload* pl, payload_member* item) -> void {
            auto ver = pl->t_value_of<uint16>(item);
            t_enum_type<tls_version_t> etver(ver);
            pl->set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(etver));
        };
        pl.set_condition(constexpr_record_version, lambda_check_dtls);
        size_t apos = 0;
        ret = pl.read(record_header.data(), record_header.size(), apos);
        if (errorcode_t::success != ret) {
            return ret;
        }

        content_type = pl.t_value_of<uint8>(constexpr_content_type);
        record_version = pl.t_value_of<uint16>(constexpr_record_version);
        len = pl.t_value_of<uint16>(constexpr_len);
        cond_dtls = pl.get_group_condition(constexpr_group_dtls);
        if (cond_dtls) {
            key_epoch = pl.t_value_of<uint16>(constexpr_dtls_epoch);
            dtls_record_seq = pl.t_value_of<uint64>(constexpr_dtls_record_seq);
        }
    }
    {
        /**
         * RFC 5246 6.2.3.3.  AEAD Ciphers
         *   additional_data = seq_num + TLSCompressed.type +
         *                     TLSCompressed.version + TLSCompressed.length;
         *   AEADEncrypted = AEAD-Encrypt(write_key, nonce, plaintext,
         *                                additional_data)
         *   TLSCompressed.fragment = AEAD-Decrypt(write_key, nonce,
         *                                         AEADEncrypted,
         *                                         additional_data)
         *
         * uint64(seq_num) || uint8(type) || uint16(version) || uint16(cipertext.size)
         *
         * RFC 6347 4.1.2.1.  MAC
         *   The DTLS MAC is the same as that of TLS 1.2. However, rather than
         *   using TLS's implicit sequence number, the sequence number used to
         *   compute the MAC is the 64-bit value formed by concatenating the epoch
         *   and the sequence number in the order they appear on the wire.  Note
         *   that the DTLS epoch + sequence number is the same length as the TLS
         *   sequence number.
         *
         * uint16(epoch) || uint48(seq_num) || uint8(type) || uint16(version) || uint16(cipertext.size)
         */

        len -= (size_nonce_explicit + get_tag_size(session, dir));

        payload pl;
        pl << new payload_member(uint64(record_no), true, constexpr_record_no, constexpr_group_tls)
           << new payload_member(uint16(key_epoch), true, constexpr_dtls_epoch, constexpr_group_dtls)         // dtls
           << new payload_member(uint48_t(dtls_record_seq), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
           << new payload_member(uint8(content_type), constexpr_content_type)                                 // tls, dtls
           << new payload_member(uint16(record_version), true, constexpr_record_version)                      // tls, dtls
           << new payload_member(uint16(len), true, constexpr_len);                                           // tls, dtls

        pl.set_group(constexpr_group_tls, (false == cond_dtls));
        pl.set_group(constexpr_group_dtls, (true == cond_dtls));
        pl.write(aad);
    }
    return ret;
}

return_t tls_protection::write_aad(tls_session* session, tls_direction_t dir, binary_t& aad, tls_content_type_t content_type, tls_version_t version, uint64 recno,
                                   uint16 epoch, uint64 dtlsseq, uint16 bodysize) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        auto& secrets = protection.get_secrets();

        auto record_version = protection.get_lagacy_version();
        auto tagsize = protection.get_tag_size(session, dir);
        auto cs = protection.get_cipher_suite(session, dir);
        auto hint_blockcipher = tlsadvisor->hintof_blockcipher(cs);
        if (nullptr == hint_blockcipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto ivsize = sizeof_iv(hint_blockcipher);
        auto hint_cipher = tlsadvisor->hintof_cipher(cs);
        auto mode = typeof_mode(hint_cipher);
        auto is_tls = protection.is_kindof_tls();
        auto is_tls12 = protection.is_kindof_tls1_2();
        auto is_cbc = false;
        bool etm = false;
        uint16 key_epoch = 0;
        uint64 dtls_record_seq = 0;
        uint16 len = 0;

        secrets.erase(tls_secret_t::nonce_explicit);
        bool tls12_aead = false;
        // uint8 sizeof_nonce_explicit = 0;

        /**
         * RFC 5246 6.2.3.3.  AEAD Ciphers
         *   additional_data = seq_num + TLSCompressed.type +
         *                     TLSCompressed.version + TLSCompressed.length;
         *   AEADEncrypted = AEAD-Encrypt(write_key, nonce, plaintext,
         *                                additional_data)
         *   TLSCompressed.fragment = AEAD-Decrypt(write_key, nonce,
         *                                         AEADEncrypted,
         *                                         additional_data)
         *
         * uint64(seq_num) || uint8(type) || uint16(version) || uint16(cipertext_wo_tag.size)
         *
         * RFC 6347 4.1.2.1.  MAC
         *   The DTLS MAC is the same as that of TLS 1.2. However, rather than
         *   using TLS's implicit sequence number, the sequence number used to
         *   compute the MAC is the 64-bit value formed by concatenating the epoch
         *   and the sequence number in the order they appear on the wire.  Note
         *   that the DTLS epoch + sequence number is the same length as the TLS
         *   sequence number.
         *
         * uint16(epoch) || uint48(seq_num) || uint8(type) || uint16(version) || uint16(cipertext_wo_tag.size)
         */

        if (is_tls12) {
            // TLS 1.2, DTLS 1.2
            is_cbc = tlsadvisor->is_kindof_cbc(cs);
            etm = session->get_keyvalue().get(session_encrypt_then_mac);
            if (is_cbc) {
                // CBC
                if (etm) {
                    // Encrypt-then-Mac
                    len = bodysize + tagsize;
                } else {
                    // Mac-then-Encrypt
                    len = bodysize + tagsize + ivsize;
                }
            } else if (crypt_mode_t::ccm == mode || crypt_mode_t::gcm == mode) {
                tls12_aead = true;
                // sizeof_nonce_explicit = 8;

                // CCM, GCM
                len = bodysize;

                // sketch ...
                // tls_secret_t::nonce_explicit 12-octet
                openssl_prng prng;
                binary_t temp;
                prng.random(temp, 8);
                secrets.assign(tls_secret_t::nonce_explicit, std::move(temp));
            } else if (crypt_mode_t::poly1305 == mode) {
                tls12_aead = true;
                len = bodysize;
            }
        } else {
            // TLS 1.3, DTLS 1.3
            len = bodysize + tagsize;
        }

        uint64 record_no = 0;
        if (is_tls) {
            record_no = session->get_recordno(dir);
        } else {
            auto& kv = session->get_session_info(dir).get_keyvalue();
            key_epoch = t_narrow_cast(kv.get(session_dtls_epoch));
            dtls_record_seq = kv.get(session_dtls_seq);
        }

        payload pl;
        if (tls12_aead) {
            pl << new payload_member(uint64(record_no), true, constexpr_record_no, constexpr_group_tls)           // tls
               << new payload_member(uint16(key_epoch), true, constexpr_dtls_epoch, constexpr_group_dtls)         // dtls
               << new payload_member(uint48_t(dtls_record_seq), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint8(content_type), constexpr_content_type)                                 // tls, dtls
               << new payload_member(uint16(record_version), true, constexpr_record_version)                      // tls, dtls
               << new payload_member(uint16(len), true, constexpr_len);                                           // tls, dtls

            pl.set_group(constexpr_group_tls, (true == is_tls));
            pl.set_group(constexpr_group_dtls, (false == is_tls));
        } else {
            /**
             * AAD
             *   CBC  uint8(type) || uint16(version)
             *   AEAD uint8(type) || uint16(version) || uint16(len)
             */
            pl << new payload_member(uint8(content_type), constexpr_content_type)                                 // tls, dtls
               << new payload_member(uint16(record_version), true, constexpr_record_version)                      // tls, dtls
               << new payload_member(uint16(key_epoch), true, constexpr_dtls_epoch, constexpr_group_dtls)         // dtls
               << new payload_member(uint48_t(dtls_record_seq), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(len), true, constexpr_len);                                           // tls, dtls

            pl.set_group(constexpr_group_dtls, false == is_tls);
        }

        pl.write(aad);
    }
    __finally2 {}

    return ret;
}

return_t tls_protection::get_aead_key(tls_session* session, tls_direction_t dir, protection_space_t space, tls_secret_t& secret_key, tls_secret_t& secret_iv) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session_type = session->get_type();
        auto hsstatus = session->get_session_info(dir).get_status();

        switch (session_type) {
            case session_type_t::tls:
            case session_type_t::dtls: {
                // A fresh resumption connection has not negotiated its version
                // when it installs the ClientHello early-data keys. Select the
                // TLS 1.3 traffic-secret slots from the ticket-bound parameters.
                if (is_kindof_tls1_3() || is_kindof_tls1_3_early_data(session)) {
                    // TLS 1.3
                    if (is_clientinitiated(dir)) {
                        // TLS, DTLS
                        auto flow = get_flow();
                        if (tls_flow_t::one_rtt == flow || tls_flow_t::hello_retry_request == flow) {
                            if (tls_handshake_type_t::finished == hsstatus) {
                                secret_key = tls_secret_t::application_client_key;
                                secret_iv = tls_secret_t::application_client_iv;
                            } else {
                                secret_key = tls_secret_t::handshake_client_key;
                                secret_iv = tls_secret_t::handshake_client_iv;
                            }
                        } else {
                            // EndOfEarlyData itself is protected with the early
                            // traffic key. The following client Finished switches
                            // to the handshake traffic key.
                            // client_hello         c e traffic (including EndOfEarlyData)
                            // end_of_early_data    c hs traffic
                            // finished             c ap traffic
                            switch (hsstatus) {
                                case tls_handshake_type_t::end_of_early_data: {
                                    secret_key = tls_secret_t::handshake_client_key;
                                    secret_iv = tls_secret_t::handshake_client_iv;
                                } break;
                                case tls_handshake_type_t::finished: {
                                    secret_key = tls_secret_t::application_client_key;
                                    secret_iv = tls_secret_t::application_client_iv;
                                } break;
                                case tls_handshake_type_t::client_hello:
                                default: {
                                    secret_key = tls_secret_t::c_e_traffic_key;
                                    secret_iv = tls_secret_t::c_e_traffic_iv;
                                } break;
                            }
                        }
                    } else if (is_serverinitiated(dir)) {
                        // from_server
                        if (tls_handshake_type_t::finished == hsstatus) {
                            secret_key = tls_secret_t::application_server_key;
                            secret_iv = tls_secret_t::application_server_iv;
                        } else {
                            secret_key = tls_secret_t::handshake_server_key;
                            secret_iv = tls_secret_t::handshake_server_iv;
                        }
                    }
                } else {
                    // TLS 1.2
                    if (is_clientinitiated(dir)) {
                        secret_key = tls_secret_t::client_key;
                        secret_iv = tls_secret_t::client_iv;
                    } else if (is_serverinitiated(dir)) {
                        secret_key = tls_secret_t::server_key;
                        secret_iv = tls_secret_t::server_iv;
                    }
                }
            } break;
            case session_type_t::quic:
            case session_type_t::quic2: {
                // QUIC
                if (is_clientinitiated(dir)) {
                    if (protection_space_t::initial == space) {
                        secret_key = tls_secret_t::initial_quic_client_key;
                        secret_iv = tls_secret_t::initial_quic_client_iv;
                    } else if (protection_space_t::handshake == space) {
                        secret_key = tls_secret_t::handshake_quic_client_key;
                        secret_iv = tls_secret_t::handshake_quic_client_iv;
                    } else if (protection_space_t::application == space) {
                        secret_key = tls_secret_t::application_quic_client_key;
                        secret_iv = tls_secret_t::application_quic_client_iv;
                    } else {
                        ret = errorcode_t::invalid_parameter;
                    }
                } else if (is_serverinitiated(dir)) {
                    if (protection_space_t::initial == space) {
                        secret_key = tls_secret_t::initial_quic_server_key;
                        secret_iv = tls_secret_t::initial_quic_server_iv;
                    } else if (protection_space_t::handshake == space) {
                        secret_key = tls_secret_t::handshake_quic_server_key;
                        secret_iv = tls_secret_t::handshake_quic_server_iv;
                    } else if (protection_space_t::application == space) {
                        secret_key = tls_secret_t::application_quic_server_key;
                        secret_iv = tls_secret_t::application_quic_server_iv;
                    } else {
                        ret = errorcode_t::invalid_parameter;
                    }
                }
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::encrypt_aead(tls_session* session, tls_direction_t dir, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag,
                                      protection_space_t space) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        uint16 cs = 0;
        switch (space) {
            case protection_space_t::initial:
                // AEAD_AES_128_GCM, SHA256
                cs = 0x1301;
                break;
            default:
                cs = get_cipher_suite(session, dir);
                break;
        }
        auto hint_cipher = tlsadvisor->hintof_cipher(cs);

        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_iv;
        get_aead_key(session, dir, space, secret_key, secret_iv);

        uint64 record_no = session->get_recordno(dir, space);
        bool track_tls13_usage =
            (session_type_t::tls == session->get_type()) && (is_kindof_tls1_3() || is_kindof_tls1_3_early_data(session)) && (protection_space_t::tls == space);
        bool track_tls13_plaintext = false;
        if (track_tls13_usage) {
            uint64 max_records = 0;
            uint64 max_plaintext = 0;
            if (false == tls1_3_key_usage_limit(cs, max_records, max_plaintext)) {
                auto& session_info = session->get_session_info(dir);
                if (false == session_info.has_alert(tls_alertlevel_t::fatal)) {
                    session_info.push_alert(tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                }
                ret = errorcode_t::internal_error;
                __leave2;
            }

            track_tls13_plaintext = (~static_cast<uint64>(0) != max_plaintext);
            auto& usage = session->get_session_info(dir).get_keyvalue();
            uint64 used_plaintext = usage.get(session_tls13_key_usage_bytes);
            // Early-data traffic keys cannot use the reserved Alert record.
            bool alert_record = (tls_secret_t::c_e_traffic_key != secret_key) && tls1_3_is_alert_plaintext(plaintext);
            uint64 record_limit = alert_record ? (max_records - 1) : (max_records - 2);
            bool record_limit_reached = (record_no >= record_limit);
            bool plaintext_limit_reached = false;
            if (~static_cast<uint64>(0) != max_plaintext) {
                uint64 plaintext_limit = alert_record ? (max_plaintext - 3) : (max_plaintext - 6);
                plaintext_limit_reached = (used_plaintext > plaintext_limit) || (plaintext.size() > (plaintext_limit - used_plaintext));
            }
            if (record_limit_reached || plaintext_limit_reached) {
                // The library has no KeyUpdate sender yet. Fail closed before
                // using this key beyond its TLS 1.3 confidentiality limit.
                // Reserve one record and three plaintext bytes for a fatal Alert.
                // Keep a further record and three bytes unused so the connection
                // closes strictly before the cryptographic usage ceiling.
                auto& session_info = session->get_session_info(dir);
                if (false == session_info.has_alert(tls_alertlevel_t::fatal)) {
                    session_info.push_alert(tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
                }
                ret = errorcode_t::exceed;
                __leave2;
            }
        }

        ret = advance_recordno(session, dir, record_no, space);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        const auto& key = get_secrets().get(secret_key);
        const auto& iv = get_secrets().get(secret_iv);
        binary_t nonce;
        encrypt_option_t options[] = {{crypt_ctrl_t::nsize, hint_cipher->nsize}, {crypt_ctrl_t::tsize, hint_cipher->tsize}, {}};

        auto alg = typeof_alg(hint_cipher);
        auto mode = typeof_mode(hint_cipher);
        if (is_kindof_tls1_2()) {
            if (crypt_mode_t::poly1305 == mode) {
                if (is_kindof_dtls()) {
                    // in case of DTLS 1.2 chacha20-poly1305, true == is_kindof_dtls()
                    // in case of CBC-HMAC, session_type_t::dtls == session->get_type
                    auto& kv = session->get_session_info(dir).get_keyvalue();
                    uint16 epoch = t_narrow_cast(kv.get(session_dtls_epoch));
                    uint64 seq = kv.get(session_dtls_seq);
                    record_no = session->get_dtls_record_arrange().make_epoch_seq(epoch, seq);
                }
                build_iv(session, nonce, iv, record_no);
                ret = crypt.encrypt(alg, mode, key, nonce, plaintext, ciphertext, aad, tag, options);
            } else if (crypt_mode_t::ccm == mode || crypt_mode_t::gcm == mode) {
                const binary_t& nonce_explicit = get_secrets().get(tls_secret_t::nonce_explicit);
                binary_append(nonce, iv);
                binary_append(nonce, nonce_explicit);
                ret = crypt.encrypt(alg, mode, key, nonce, plaintext, ciphertext, aad, tag, options);
                ciphertext.insert(ciphertext.begin(), nonce_explicit.begin(), nonce_explicit.end());
            }
        } else {
            build_iv(session, nonce, iv, record_no);
            ret = crypt.encrypt(alg, mode, key, nonce, plaintext, ciphertext, aad, tag, options);
        }

        if ((errorcode_t::success == ret) && track_tls13_plaintext) {
            auto& usage = session->get_session_info(dir).get_keyvalue();
            uint64 used_plaintext = usage.get(session_tls13_key_usage_bytes);
            usage.set(session_tls13_key_usage_bytes, used_plaintext + plaintext.size());
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                dbs.println("> encrypt");
                dbs.println(" > key[%08x] %s (%s)", secret_key, base16_encode(key).c_str(), tlsadvisor->nameof_secret(secret_key).c_str());
                dbs.println(" > iv [%08x] %s (%s)", secret_iv, base16_encode(iv).c_str(), tlsadvisor->nameof_secret(secret_iv).c_str());
                dbs.println(" > record no %i (space %s)", record_no, tlsadvisor->nameof_protection_space(space).c_str());
                dbs.println(" > nonce %s", base16_encode(nonce).c_str());
                dbs.println(" > aad %s", base16_encode(aad).c_str());
                dbs.println(" > tag %s", base16_encode(tag).c_str());
                dbs.println(" > plaintext");
                dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
                dbs.println(" > ciphertext");
                dump_memory(ciphertext, &dbs, 16, 3, 0x0, dump_notrunc);
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::decrypt_aead(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext,
                                      protection_space_t space, decrypt_alert_policy_t alert_policy) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t aadlen = get_header_size();
        uint8 tagsize = get_tag_size(session, dir);
        // Validate the complete header and authentication tag before
        // calculating size - tagsize; truncated records must not underflow.
        if ((size < pos) || (size - pos < aadlen) || (0 == tagsize) || (size - pos - aadlen < tagsize)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        binary_t aad;
        binary_append(aad, stream + pos, aadlen);
        pos += aadlen;

        // aad(aadlen) encdata tag(tagsize)
        //             \\_ pos
        binary_t tag;
        binary_append(tag, stream + size - tagsize, tagsize);

        ret = decrypt_aead(session, dir, stream, size - tagsize, pos, plaintext, aad, tag, space, alert_policy);
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::decrypt_aead(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t pos, binary_t& plaintext, const binary_t& aad,
                                      const binary_t& tag, protection_space_t space, decrypt_alert_policy_t alert_policy) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size < pos) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
        // An empty TLS 1.3 encrypted fragment can still carry a valid AEAD tag.
        // Authenticate it first; the record layer rejects the resulting empty
        // TLSInnerPlaintext because it has no inner content type.

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        uint16 cs = 0;
        switch (space) {
            case protection_space_t::initial:
                // AEAD_AES_128_GCM, SHA256
                cs = 0x1301;
                break;
            default:
                cs = get_cipher_suite(session, dir);
                break;
        }
        auto hint_cipher = tlsadvisor->hintof_cipher(cs);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto mode = typeof_mode(hint_cipher);

        // TLS 1.2 AES-GCM and AES-CCM records carry an 8-byte explicit nonce
        // before the encrypted fragment. Validate it before consuming a record number.
        if (is_kindof_tls1_2() && (crypt_mode_t::gcm == mode || crypt_mode_t::ccm == mode) && (size - pos < 8)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        encrypt_option_t options[] = {{crypt_ctrl_t::nsize, hint_cipher->nsize}, {crypt_ctrl_t::tsize, hint_cipher->tsize}, {}};

        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_iv;
        get_aead_key(session, dir, space, secret_key, secret_iv);

        uint64 record_no = 0;
        ret = advance_recordno(session, dir, record_no, space);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        const binary_t& key = get_secrets().get(secret_key);
        const binary_t& iv = get_secrets().get(secret_iv);
        binary_t tls12_aad;
        binary_t nonce;
        auto alg = typeof_alg(hint_cipher);

        if (is_kindof_tls1_2()) {
            uint8 size_nonce_explicit = 8;

            if (crypt_mode_t::poly1305 == mode) {
                /**
                 * RFC 7905 2.  ChaCha20 Cipher Suites
                 *   AEAD_CHACHA20_POLY1305 requires a 96-bit nonce, which is formed as
                 *   follows:
                 *
                 *   1.  The 64-bit record sequence number is serialized as an 8-byte,
                 *       big-endian value and padded on the left with four 0x00 bytes.
                 *
                 *   2.  The padded sequence number is XORed with the client_write_IV
                 *       (when the client is sending) or server_write_IV (when the server
                 *       is sending).
                 */

                size_nonce_explicit = 0;

                if (is_kindof_dtls()) {
                    // in case of DTLS 1.2 chacha20-poly1305, true == is_kindof_dtls()
                    // in case of CBC-HMAC, session_type_t::dtls == session->get_type
                    auto& kv = session->get_session_info(dir).get_keyvalue();
                    uint16 epoch = t_narrow_cast(kv.get(session_dtls_epoch));
                    uint64 seq = kv.get(session_dtls_seq);
                    record_no = session->get_dtls_record_arrange().make_epoch_seq(epoch, seq);
                }

                build_iv(session, nonce, iv, record_no);
            } else if (crypt_mode_t::ccm == mode || crypt_mode_t::gcm == mode) {
                /**
                 * RFC 5246 6.2.3.3.  AEAD Ciphers
                 *   struct {
                 *      opaque nonce_explicit[SecurityParameters.record_iv_length];
                 *      aead-ciphered struct {
                 *          opaque content[TLSCompressed.length];
                 *      };
                 *   } GenericAEADCipher;
                 * RFC 5288
                 *   struct {
                 *      opaque salt[4];
                 *      opaque nonce_explicit[8];
                 *   } GCMNonce;
                 */

                size_nonce_explicit = 8;

                binary_append(nonce, iv);
                binary_append(nonce, stream + pos, size_nonce_explicit);

                pos += size_nonce_explicit;
            }

            build_tls1_2_aad_from_record(session, dir, tls12_aad, aad, record_no, size_nonce_explicit);

            ret = crypt.decrypt(alg, mode, key, nonce, stream + pos, size - pos, plaintext, tls12_aad, tag, options);
        } else {
            build_iv(session, nonce, iv, record_no);
            ret = crypt.decrypt(alg, mode, key, nonce, stream + pos, size - pos, plaintext, aad, tag, options);
        }

        if ((errorcode_t::success != ret) && ((decrypt_alert_policy_t::report == alert_policy) || (errorcode_t::verification_failure != ret))) {
            // Suppress only authentication failures during rejected-0-RTT
            // trial decryption. Internal/setup failures must remain visible.
            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::bad_record_mac);
        }

#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
                dbs.println("> decrypt");
                dbs.println(" > key[%08x] %s (%s)", secret_key, base16_encode(key).c_str(), tlsadvisor->nameof_secret(secret_key).c_str());
                dbs.println(" > iv [%08x] %s (%s)", secret_iv, base16_encode(iv).c_str(), tlsadvisor->nameof_secret(secret_iv).c_str());
                dbs.println(" > record no %i (space %s)", record_no, tlsadvisor->nameof_protection_space(space).c_str());
                dbs.println(" > nonce %s", base16_encode(nonce).c_str());
                if (is_kindof_tls1_2()) {
                    dbs.println(" > aad %s", base16_encode(tls12_aad).c_str());
                } else {
                    dbs.println(" > aad %s", base16_encode(aad).c_str());
                }
                dbs.println(" > tag %s", base16_encode(tag).c_str());
                dbs.println(" > ciphertext");
                dump_memory(stream + pos, size - pos, &dbs, 16, 3, 0x0, dump_notrunc);
                dbs.println(" > plaintext");
                dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
