/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection_encryption_cbchmac.cpp
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

return_t tls_protection::get_cbc_hmac_key(tls_session *session, tls_direction_t dir, tls_secret_t &secret_key, tls_secret_t &secret_mac_key) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (is_clientinitiated(dir)) {
            secret_key = tls_secret_client_key;
            secret_mac_key = tls_secret_client_mac_key;
        } else if (is_serverinitiated(dir)) {
            secret_key = tls_secret_server_key;
            secret_mac_key = tls_secret_server_mac_key;
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_protection::encrypt_cbc_hmac(tls_session *session, tls_direction_t dir, const binary_t &plaintext, binary_t &ciphertext, const binary_t &additional,
                                          binary_t &maced) {
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

        const binary_t &enckey = get_secrets().get(secret_key);
        auto enc_alg = typeof_alg(hint_cipher);
        auto hmac_alg = hint->mac;  // do not promote insecure algorithm
        const binary_t &mackey = get_secrets().get(secret_mac_key);

        bool etm = session->get_keyvalue().get(session_encrypt_then_mac);
        uint16 flag = etm ? tls_encrypt_then_mac : tls_mac_then_encrypt;

        binary_t iv;
        if (etm) {
            if (is_clientinitiated(dir)) {
                iv = get_secrets().get(tls_secret_client_iv);
            } else if (is_serverinitiated(dir)) {
                iv = get_secrets().get(tls_secret_server_iv);
            }
        } else {
            auto ivsize = sizeof_iv(hint_cipher);
            openssl_prng prng;
            prng.random(iv, ivsize);
        }

        binary_t verifydata;
        binary_t aad;
        if (session_type_dtls == session_type) {
            // in case of DTLS 1.2 chacha20-poly1305, true == is_kindof_dtls()
            // in case of CBC-HMAC, session_type_dtls == session->get_type
            auto &kv = session->get_session_info(dir).get_keyvalue();
            uint16 epoch = t_narrow_cast(kv.get(session_dtls_epoch));
            uint64 seq = kv.get(session_dtls_seq);
            record_no = session->get_dtls_record_arrange().make_epoch_seq(epoch, seq);
        } else {
            // TLS, QUIC, QUIC2
            record_no = session->get_recordno(dir, true);
        }
        binary_append(aad, uint64(record_no), hton64);  // sequence
        binary_append(aad, additional.data(), 3);       // rechdr (content_type, version)
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
        if (istraceable(trace_category_net, loglevel_debug)) {
            trace_debug_event(trace_category_net, trace_event_tls_protection, [&](basic_stream &dbs) -> void {
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
            });
        }
#endif
    }
    __finally2 {}
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

        const binary_t &enckey = get_secrets().get(secret_key);
        auto enc_alg = hint_cipher->algorithm;
        auto hmac_alg = hint->mac;  // do not promote insecure algorithm
        const binary_t &mackey = get_secrets().get(secret_mac_key);

        bool etm = session->get_keyvalue().get(session_encrypt_then_mac);
        uint16 flag = etm ? tls_encrypt_then_mac : tls_mac_then_encrypt;

        binary_t verifydata;
        binary_t aad;
        binary_t tag;
        if (session_type_dtls == session_type) {
            // in case of DTLS 1.2 chacha20-poly1305, true == is_kindof_dtls()
            // in case of CBC-HMAC, session_type_dtls == session->get_type
            auto &kv = session->get_session_info(dir).get_keyvalue();
            uint16 epoch = t_narrow_cast(kv.get(session_dtls_epoch));
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
            if (is_clientinitiated(dir)) {
                iv = get_secrets().get(tls_secret_client_iv);
            } else if (is_serverinitiated(dir)) {
                iv = get_secrets().get(tls_secret_server_iv);
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
        if (istraceable(trace_category_net, loglevel_debug)) {
            trace_debug_event(trace_category_net, trace_event_tls_protection, [&](basic_stream &dbs) -> void {
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
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
