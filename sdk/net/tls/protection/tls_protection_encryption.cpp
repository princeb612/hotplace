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
#include <sdk/crypto/basic/cipher_encrypt.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_cbc_hmac.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/asn.1/types.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/dtls_record_arrange.hpp>
#include <sdk/net/tls/dtls_record_publisher.hpp>
#include <sdk/net/tls/quic_stream_tracer.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "record content type";
constexpr char constexpr_record_version[] = "record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_tls[] = "tls";
constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_dtls_epoch[] = "epoch";
constexpr char constexpr_dtls_record_seq[] = "sequence number";

return_t tls_protection::build_tls12_aad_from_record(tls_session *session, binary_t &aad, const binary_t &record_header, uint64 record_no) {
    return_t ret = errorcode_t::success;

    tls_advisor *tlsadvisor = tls_advisor::get_instance();
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

        auto lambda_check_dtls = [&](payload *pl, payload_member *item) -> void {
            auto ver = pl->t_value_of<uint16>(item);
            pl->set_group(constexpr_group_dtls, tlsadvisor->is_kindof_dtls(ver));
        };
        pl.set_condition(constexpr_record_version, lambda_check_dtls);
        size_t apos = 0;
        pl.read(&record_header[0], record_header.size(), apos);

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

        len -= (8 + get_tag_size());

        payload pl;
        pl << new payload_member(uint64(record_no), true, constexpr_dtls_epoch, constexpr_group_tls)
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

return_t tls_protection::build_iv(tls_session *session, binary_t &nonce, const binary_t &iv, uint64 recordno) {
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
            nonce[12 - 1 - i] = v ^ n;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

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
                ret_value = dlen;
                break;
        }
    }
    return ret_value;
}

return_t tls_protection::get_aead_key(tls_session *session, tls_direction_t dir, tls_secret_t &secret_key, tls_secret_t &secret_iv, protection_level_t level) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session_type = session->get_type();
        auto hsstatus = session->get_session_info(dir).get_status();

        switch (session_type) {
            case session_type_tls:
            case session_type_dtls: {
                if (is_kindof_tls13()) {
                    // TLS 1.3
                    if (from_client == dir) {
                        // TLS, DTLS
                        auto flow = get_flow();
                        if (tls_flow_1rtt == flow || tls_flow_hello_retry_request == flow) {
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
                    } else if (from_server == dir) {
                        // from_server
                        if (tls_hs_finished == hsstatus) {
                            secret_key = tls_secret_application_server_key;
                            secret_iv = tls_secret_application_server_iv;
                        } else {
                            secret_key = tls_secret_handshake_server_key;
                            secret_iv = tls_secret_handshake_server_iv;
                        }
                    }
                } else {
                    // TLS 1.2
                    if (from_client == dir) {
                        secret_key = tls_secret_client_key;
                        secret_iv = tls_secret_client_iv;
                    } else if (from_server == dir) {
                        secret_key = tls_secret_server_key;
                        secret_iv = tls_secret_server_iv;
                    }
                }
            } break;
            case session_type_quic:
            case session_type_quic2: {
                // QUIC
                if (from_client == dir) {
                    if (protection_initial == level) {
                        secret_key = tls_secret_initial_quic_client_key;
                        secret_iv = tls_secret_initial_quic_client_iv;
                    } else if (protection_handshake == level) {
                        secret_key = tls_secret_handshake_quic_client_key;
                        secret_iv = tls_secret_handshake_quic_client_iv;
                    } else if (protection_application == level) {
                        secret_key = tls_secret_application_quic_client_key;
                        secret_iv = tls_secret_application_quic_client_iv;
                    } else {
                        ret = errorcode_t::invalid_parameter;
                    }
                } else if (from_server == dir) {
                    if (protection_initial == level) {
                        secret_key = tls_secret_initial_quic_server_key;
                        secret_iv = tls_secret_initial_quic_server_iv;
                    } else if (protection_handshake == level) {
                        secret_key = tls_secret_handshake_quic_server_key;
                        secret_iv = tls_secret_handshake_quic_server_iv;
                    } else if (protection_application == level) {
                        secret_key = tls_secret_application_quic_server_key;
                        secret_iv = tls_secret_application_quic_server_iv;
                    } else {
                        ret = errorcode_t::invalid_parameter;
                    }
                }
            } break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::get_cbc_hmac_key(tls_session *session, tls_direction_t dir, tls_secret_t &secret_key, tls_secret_t &secret_mac_key) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (from_client == dir) {
            secret_key = tls_secret_client_key;
            secret_mac_key = tls_secret_client_mac_key;
        } else if (from_server == dir) {
            secret_key = tls_secret_server_key;
            secret_mac_key = tls_secret_server_mac_key;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

// RFC 2246 6.2.3 Record payload protection
// length of TLSCiphertext.fragment may not exceed 2^14 + 2048
#define TLS_CIPHERTEXT_MAXSIZE ((2 << 14) + 2048)

return_t tls_protection::encrypt(tls_session *session, tls_direction_t dir, const binary_t &plaintext, binary_t &ciphertext, const binary_t &additional,
                                 binary_t &tag, protection_level_t level) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
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
            ret = encrypt_aead(session, dir, plaintext, ciphertext, additional, tag, level);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (ciphertext.size() > TLS_CIPHERTEXT_MAXSIZE) {
            ret = errorcode_t::exceed;
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::encrypt_aead(tls_session *session, tls_direction_t dir, const binary_t &plaintext, binary_t &ciphertext, const binary_t &aad,
                                      binary_t &tag, protection_level_t level) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto record_version = get_lagacy_version();
        size_t content_header_size = 0;
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        uint16 cs = 0;
        switch (level) {
            case protection_initial:
                // AEAD_AES_128_GCM, SHA256
                cs = 0x1301;
                break;
            default:
                cs = get_cipher_suite();
                break;
        }
        auto hint_cipher = tlsadvisor->hintof_cipher(cs);

        crypt_context_t *handle = nullptr;
        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_iv;
        get_aead_key(session, dir, secret_key, secret_iv, level);

        uint64 record_no = 0;
        record_no = session->get_recordno(dir, true, level);

        auto const &key = get_item(secret_key);
        auto const &iv = get_item(secret_iv);
        binary_t nonce;
        encrypt_option_t options[] = {{crypt_ctrl_nsize, hint_cipher->nsize}, {crypt_ctrl_tsize, hint_cipher->tsize}, {}};
        binary_t tls12_aad;

        auto alg = typeof_alg(hint_cipher);
        auto mode = typeof_mode(hint_cipher);
        if (is_kindof_tls12()) {
            const binary_t &nonce_explicit = get_item(tls_context_nonce_explicit);
            binary_append(nonce, iv);
            binary_append(nonce, nonce_explicit);
            ret = crypt.encrypt(alg, mode, key, nonce, plaintext, ciphertext, aad, tag, options);
            ciphertext.insert(ciphertext.begin(), nonce_explicit.begin(), nonce_explicit.end());
        } else {
            build_iv(session, nonce, iv, record_no);
            ret = crypt.encrypt(alg, mode, key, nonce, plaintext, ciphertext, aad, tag, options);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> encrypt");
            dbs.println(" > key[%08x] %s (%s)", secret_key, base16_encode(key).c_str(), tlsadvisor->nameof_secret(secret_key).c_str());
            dbs.println(" > iv [%08x] %s (%s)", secret_iv, base16_encode(iv).c_str(), tlsadvisor->nameof_secret(secret_iv).c_str());
            dbs.println(" > record no %i", record_no);
            dbs.println(" > nonce %s", base16_encode(nonce).c_str());
            dbs.println(" > aad %s", base16_encode(aad).c_str());
            dbs.println(" > tag %s", base16_encode(tag).c_str());
            dbs.println(" > plaintext");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.println(" > ciphertext");
            dump_memory(ciphertext, &dbs, 16, 3, 0x0, dump_notrunc);

            trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::encrypt_cbc_hmac(tls_session *session, tls_direction_t dir, const binary_t &plaintext, binary_t &ciphertext,
                                          const binary_t &additional, binary_t &maced) {
    return_t ret = errorcode_t::success;
    __try2 {
        ciphertext.clear();

        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        auto session_type = session->get_type();
        auto cs = get_cipher_suite();

        crypto_advisor *advisor = crypto_advisor::get_instance();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto hint_cipher = tlsadvisor->hintof_blockcipher(cs);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_mac_key;
        get_cbc_hmac_key(session, dir, secret_key, secret_mac_key);

        uint64 record_no = 0;

        const binary_t &enckey = get_item(secret_key);
        auto enc_alg = typeof_alg(hint_cipher);
        auto hmac_alg = hint->mac;  // do not promote insecure algorithm
        const binary_t &mackey = get_item(secret_mac_key);

        bool etm = session->get_keyvalue().get(session_encrypt_then_mac);
        uint16 flag = etm ? tls_encrypt_then_mac : tls_mac_then_encrypt;

        binary_t iv;
        if (etm) {
            if (from_client == dir) {
                iv = get_item(tls_secret_client_iv);
            } else if (from_server == dir) {
                iv = get_item(tls_secret_server_iv);
            }
        } else {
            auto ivsize = sizeof_iv(hint_cipher);
            openssl_prng prng;
            prng.random(iv, ivsize);
        }

        binary_t verifydata;
        binary_t aad;
        if (session_type_dtls == session_type) {
            auto &kv = session->get_session_info(dir).get_keyvalue();
            uint16 epoch = kv.get(session_dtls_epoch);
            uint64 seq = kv.get(session_dtls_seq);
            record_no = session->get_dtls_record_arrange().make_epoch_seq(epoch, seq);
        } else {
            // TLS, QUIC, QUIC2
            record_no = session->get_recordno(dir, true);
        }
        binary_append(aad, uint64(record_no), hton64);  // sequence
        binary_append(aad, &additional[0], 3);          // rechdr (content_type, version)
        size_t plainsize = 0;

        crypto_cbc_hmac cbchmac;
        cbchmac.set_enc(enc_alg).set_mac(hmac_alg).set_flag(flag);
        ret = cbchmac.encrypt(enckey, mackey, iv, aad, plaintext, ciphertext);

        if (etm) {
            // do nothing
        } else {
            ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> encrypt %s", advisor->nameof_authenticated_encryption(flag).c_str());
            dbs.println(" > aad %s", base16_encode(aad).c_str());
            dbs.println(" > enc %s", advisor->nameof_cipher(enc_alg, cbc));
            dbs.println(" > enckey[%08x] %s (%s)", secret_key, base16_encode(enckey).c_str(), tlsadvisor->nameof_secret(secret_key).c_str());
            dbs.println(" > iv %s", base16_encode(iv).c_str());
            dbs.println(" > mac %s", advisor->nameof_md(hmac_alg));
            dbs.println(" > mackey[%08x] %s (%s)", secret_mac_key, base16_encode(mackey).c_str(), tlsadvisor->nameof_secret(secret_mac_key).c_str());
            dbs.println(" > record no %i", record_no);
            dbs.println(" > plaintext");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.println(" > cbcmaced");
            dump_memory(ciphertext, &dbs, 16, 3, 0x0, dump_notrunc);

            trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext,
                                 protection_level_t level) {
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
            ret = decrypt_aead(session, dir, stream, size, pos, plaintext, level);
        }
        if (errorcode_t::success != ret) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_decryption_failed);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::decrypt(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext, binary_t &aad,
                                 protection_level_t level) {
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
                    ret = decrypt_aead(session, dir, stream, size - tagsize, pos + aadlen, plaintext, aad, tag, level);
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

return_t tls_protection::decrypt(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext,
                                 const binary_t &aad, const binary_t &tag, protection_level_t level) {
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
            ret = decrypt_aead(session, dir, stream, size, pos, plaintext, aad, tag, level);
            if (errorcode_t::success != ret) {
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_decryption_failed);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::decrypt_aead(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext,
                                      protection_level_t level) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t aadlen = get_header_size();

        binary_t aad;
        binary_append(aad, stream + pos, aadlen);
        pos += aadlen;

        // aad(aadlen) encdata tag(tagsize)
        //             \_ pos
        binary_t tag;
        uint8 tagsize = get_tag_size();
        binary_append(tag, stream + size - tagsize, tagsize);

        ret = decrypt_aead(session, dir, stream, size - tagsize, pos, plaintext, aad, tag, level);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt_aead(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext,
                                      const binary_t &aad, const binary_t &tag, protection_level_t level) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_advisor *tlsadvisor = tls_advisor::get_instance();
        auto session_type = session->get_type();
        auto record_version = get_lagacy_version();
        uint16 cs = 0;
        switch (level) {
            case protection_initial:
                // AEAD_AES_128_GCM, SHA256
                cs = 0x1301;
                break;
            default:
                cs = get_cipher_suite();
                break;
        }
        auto hint_cipher = tlsadvisor->hintof_cipher(cs);
        encrypt_option_t options[] = {{crypt_ctrl_nsize, hint_cipher->nsize}, {crypt_ctrl_tsize, hint_cipher->tsize}, {}};

        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_iv;
        get_aead_key(session, dir, secret_key, secret_iv, level);

        uint64 record_no = session->get_recordno(dir, true, level);

        const binary_t &key = get_item(secret_key);
        const binary_t &iv = get_item(secret_iv);
        binary_t tls12_aad;
        binary_t nonce;
        auto alg = typeof_alg(hint_cipher);
        auto mode = typeof_mode(hint_cipher);

        if (is_kindof_tls12()) {
            build_tls12_aad_from_record(session, tls12_aad, aad, record_no);

            if (mode_poly1305 == mode) {
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

                // TODO

                build_iv(session, nonce, iv, record_no);
            } else if (ccm == mode || gcm == mode) {
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
                size_t size_nonce_explicit = 8;
                binary_append(nonce, iv);
                binary_append(nonce, stream + pos, size_nonce_explicit);

                pos += size_nonce_explicit;
            }

            ret = crypt.decrypt(alg, mode, key, nonce, stream + pos, size - pos, plaintext, tls12_aad, tag, options);
        } else {
            build_iv(session, nonce, iv, record_no);
            ret = crypt.decrypt(alg, mode, key, nonce, stream + pos, size - pos, plaintext, aad, tag, options);
        }

        if (errorcode_t::success != ret) {
            session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_decryption_failed);
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> decrypt");
            dbs.println(" > key[%08x] %s (%s)", secret_key, base16_encode(key).c_str(), tlsadvisor->nameof_secret(secret_key).c_str());
            dbs.println(" > iv [%08x] %s (%s)", secret_iv, base16_encode(iv).c_str(), tlsadvisor->nameof_secret(secret_iv).c_str());
            dbs.println(" > record no %i", record_no);
            dbs.println(" > nonce %s", base16_encode(nonce).c_str());
            if (is_kindof_tls12()) {
                dbs.println(" > aad %s", base16_encode(tls12_aad).c_str());
            } else {
                dbs.println(" > aad %s", base16_encode(aad).c_str());
            }
            dbs.println(" > tag %s", base16_encode(tag).c_str());
            dbs.println(" > ciphertext");
            dump_memory(stream + pos, size - pos, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.println(" > plaintext");
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);

            trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt_cbc_hmac(tls_session *session, tls_direction_t dir, const byte_t *stream, size_t size, size_t pos, binary_t &plaintext) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session_type = session->get_type();
        auto cs = get_cipher_suite();

        // stream = unprotected(content header + iv) + protected(ciphertext)
        // ciphertext = enc(plaintext + tag)

        crypto_advisor *advisor = crypto_advisor::get_instance();
        tls_advisor *tlsadvisor = tls_advisor::get_instance();

        const tls_cipher_suite_t *hint = tlsadvisor->hintof_cipher_suite(cs);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto hint_cipher = tlsadvisor->hintof_blockcipher(cs);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        auto ivsize = sizeof_iv(hint_cipher);
        size_t content_header_size = get_header_size();

        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_mac_key;
        get_cbc_hmac_key(session, dir, secret_key, secret_mac_key);

        uint64 record_no = 0;

        const binary_t &enckey = get_item(secret_key);
        auto enc_alg = hint_cipher->algorithm;
        auto hmac_alg = hint->mac;  // do not promote insecure algorithm
        const binary_t &mackey = get_item(secret_mac_key);

        bool etm = session->get_keyvalue().get(session_encrypt_then_mac);
        uint16 flag = etm ? tls_encrypt_then_mac : tls_mac_then_encrypt;

        binary_t verifydata;
        binary_t aad;
        binary_t tag;
        if (session_type_dtls == session_type) {
            auto &kv = session->get_session_info(dir).get_keyvalue();
            uint16 epoch = kv.get(session_dtls_epoch);
            uint64 seq = kv.get(session_dtls_seq);
            record_no = session->get_dtls_record_arrange().make_epoch_seq(epoch, seq);
        } else {
            record_no = session->get_recordno(dir, true);
        }
        binary_append(aad, uint64(record_no), hton64);  // sequence
        binary_append(aad, stream + pos, 3);            // rechdr (content_type, version)
        size_t plainsize = 0;

        // MtE
        //   plaintext || tag
        //            \- plainsize
        // EtM
        //   ciphertext || tag
        binary_t iv;
        size_t bpos = 0;
        const byte_t *ciphertext = nullptr;
        size_t ciphersize = 0;
        if (etm) {
            bpos = content_header_size;
            ciphertext = stream + pos + bpos;
            ciphersize = size - pos - bpos;
            if (from_client == dir) {
                iv = get_item(tls_secret_client_iv);
            } else if (from_server == dir) {
                iv = get_item(tls_secret_server_iv);
            }
        } else {
            bpos = content_header_size + ivsize;
            ciphertext = stream + pos + bpos;
            ciphersize = size - pos - bpos;
            binary_append(iv, stream + pos + content_header_size, ivsize);
        }

        crypto_cbc_hmac cbchmac;
        cbchmac.set_enc(enc_alg).set_mac(hmac_alg).set_flag(flag);
        ret = cbchmac.decrypt(enckey, mackey, iv, aad, ciphertext, ciphersize, plaintext);
        switch (ret) {
            case errorcode_t::success:
                break;
            case errorcode_t::error_cipher:
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_decryption_failed);
                break;
            case errorcode_t::error_verify:
                session->push_alert(dir, tls_alertlevel_fatal, tls_alertdesc_bad_record_mac);
                break;
        }

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("> decrypt %s", advisor->nameof_authenticated_encryption(flag).c_str());
            dbs.println(" > aad %s", base16_encode(aad).c_str());
            dbs.println(" > enc %s", advisor->nameof_cipher(enc_alg, cbc));
            dbs.println(" > enckey[%08x] %s (%s)", secret_key, base16_encode(enckey).c_str(), tlsadvisor->nameof_secret(secret_key).c_str());
            dbs.println(" > iv %s", base16_encode(iv).c_str());
            dbs.println(" > mac %s", advisor->nameof_md(hmac_alg));
            dbs.println(" > mackey[%08x] %s (%s)", secret_mac_key, base16_encode(mackey).c_str(), tlsadvisor->nameof_secret(secret_mac_key).c_str());
            dbs.println(" > record no %i", record_no);
            dbs.println(" > ciphertext");
            dump_memory(ciphertext, ciphersize, &dbs, 16, 3, 0x0, dump_notrunc);
            dbs.println(" > plaintext 0x%x(%i)", plainsize, plainsize);
            dump_memory(plaintext, &dbs, 16, 3, 0x0, dump_notrunc);

            trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
