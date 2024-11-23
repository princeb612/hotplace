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
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/crypto_aead.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/crypto_sign.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/net/tlsspec/tlsspec.hpp>

//---
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {
namespace net {

tls_protection::tls_protection(uint8 mode) : _mode(mode) {}

crypto_key& tls_protection::get_key() { return _key; }

crypto_key& tls_protection::get_keyshare() { return _keyshare; }

return_t tls_protection::key_agreement(tls_session* session, binary_t& shared) {
    return_t ret = errorcode_t::success;
    __try2 {
        const EVP_PKEY* pkey_priv = get_key().any();
        const EVP_PKEY* pkey_pub = get_keyshare().any();
        if (nullptr == pkey_priv || nullptr == pkey_pub) {
            ret = errorcode_t::not_found;
            __leave2;
        }

        const EVP_PKEY* pubkey = get_peer_key(pkey_pub);
        ret = dh_key_agreement(pkey_priv, pkey_pub, shared);
        EVP_PKEY_free((EVP_PKEY*)pubkey);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::calc_hello_hash(tls_session* session, binary_t& hello_hash) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto alg = session->get_cipher_suite();

        tls_advisor* tls_advisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint = tls_advisor->hintof_tls_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        const binary_t& client_hello = session->get(session_item_t::item_client_hello);
        const binary_t& server_hello = session->get(session_item_t::item_server_hello);
        {
            basic_stream bs;
            dump_memory(client_hello, &bs, 16, 3);
            printf("client_hello\n%s\n", bs.c_str());
            bs.clear();
            dump_memory(server_hello, &bs, 16, 3);
            printf("server_hello\n%s\n", bs.c_str());
            bs.clear();
        }

        openssl_hash hash;
        hash_context_t* handle = nullptr;
        ret = hash.open(&handle, hint->mac);
        if (errorcode_t::success == ret) {
            hash.update(handle, client_hello);
            hash.update(handle, server_hello);
            hash.finalize(handle, hello_hash);
            hash.close(handle);
        }

        session->erase(session_item_t::item_client_hello);
        session->erase(session_item_t::item_server_hello);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::calc(uint16 alg, const binary_t& hello_hash, const binary_t& shared_secret) {
    return_t ret = errorcode_t::success;
    // RFC 8446 7.1.  Key Schedule
    __try2 {
        _kv.clear();

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint_tls_alg = tlsadvisor->hintof_tls_algorithm(alg);
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        const hint_blockcipher_t* hint_cipher = advisor->hintof_blockcipher(hint_tls_alg->cipher);
        if (nullptr == hint_cipher) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
        if (nullptr == hint_mac) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto keysize = hint_cipher->keysize;
        auto dlen = hint_mac->digest_size;
        auto hashalg = hint_mac->fetchname;

        openssl_kdf kdf;
        binary_t context;
        binary_t early_secret;
        binary_t ikm_empty;
        ikm_empty.resize(dlen);
        {
            binary_t salt;
            salt.resize(1);
            kdf.hmac_kdf_extract(early_secret, hashalg, salt, ikm_empty);
            _kv[tls_secret_early_secret] = early_secret;
        }
        binary_t empty_hash;
        {
            openssl_digest dgst;
            binary_t empty;
            dgst.digest(hashalg, empty, empty_hash);
            _kv[tls_secret_empty_hash] = empty_hash;
        }

        /**
         *             0
         *             |
         *             v
         *   PSK ->  HKDF-Extract = Early Secret
         *             |
         *             +-----> Derive-Secret(., "ext binder" | "res binder", "")
         *             |                     = binder_key
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

        binary_t handshake_derived_secret;
        {
            kdf.hkdf_expand_label(handshake_derived_secret, hashalg, dlen, early_secret, str2bin("derived"), empty_hash);
            _kv[tls_secret_handshake_derived] = handshake_derived_secret;
        }
        binary_t handshake_secret;
        {
            kdf.hmac_kdf_extract(handshake_secret, hashalg, handshake_derived_secret, shared_secret);
            _kv[tls_secret_handshake] = handshake_secret;
        }

        binary_t okm;
        if (tls_mode_client & get_mode()) {
            binary_t handshake_client_secret;
            {
                kdf.hkdf_expand_label(handshake_client_secret, hashalg, dlen, handshake_secret, str2bin("c hs traffic"), hello_hash);
                _kv[tls_secret_handshake_client] = handshake_client_secret;
            }

            if (tls_mode_tls & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, handshake_client_secret, str2bin("key"), context);
                _kv[tls_secret_handshake_client_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, handshake_client_secret, str2bin("iv"), context);
                _kv[tls_secret_handshake_client_iv] = okm;
            }
            if (tls_mode_quic & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, handshake_client_secret, str2bin("quic key"), context);
                _kv[tls_secret_handshake_quic_client_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, handshake_client_secret, str2bin("quic iv"), context);
                _kv[tls_secret_handshake_quic_client_iv] = okm;

                kdf.hkdf_expand_label(okm, hashalg, keysize, handshake_client_secret, str2bin("quic hp"), context);
                _kv[tls_secret_handshake_quic_client_hp] = okm;
            }
        }
        if (tls_mode_server & get_mode()) {
            binary_t handshake_server_secret;
            {
                kdf.hkdf_expand_label(handshake_server_secret, hashalg, dlen, handshake_secret, str2bin("s hs traffic"), hello_hash);
                _kv[tls_secret_handshake_server] = handshake_server_secret;
            }

            if (tls_mode_tls & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, handshake_server_secret, str2bin("key"), context);
                _kv[tls_secret_handshake_server_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, handshake_server_secret, str2bin("iv"), context);
                _kv[tls_secret_handshake_server_iv] = okm;
            }
            if (tls_mode_quic & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, handshake_server_secret, str2bin("quic key"), context);
                _kv[tls_secret_handshake_quic_server_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, handshake_server_secret, str2bin("quic iv"), context);
                _kv[tls_secret_handshake_quic_server_iv] = okm;

                kdf.hkdf_expand_label(okm, hashalg, keysize, handshake_server_secret, str2bin("quic hp"), context);
                _kv[tls_secret_handshake_quic_server_hp] = okm;
            }
        }
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
         *             |                     = exporter_master_secret
         *             |
         *             +-----> Derive-Secret(., "res master",
         *                                   ClientHello...client Finished)
         *                                   = resumption_master_secret
         */
        binary_t master_derived_secret;
        {
            kdf.hkdf_expand_label(master_derived_secret, hashalg, dlen, handshake_secret, str2bin("derived"), empty_hash);
            _kv[tls_secret_master_derived] = master_derived_secret;
        }
        binary_t master_secret;
        {
            kdf.hmac_kdf_extract(master_secret, hashalg, master_derived_secret, ikm_empty);
            _kv[tls_secret_master] = master_secret;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::build_iv(tls_session* session, tls_secret_t type, binary_t& iv) {
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

        auto seq = session->get_sequence();
        for (uint64 i = 0; i < 8; i++) {
            iv[12 - 1 - i] ^= ((seq >> (i * 8)) & 0xff);
        }

        session->inc_sequence();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt(tls_session* session, const byte_t* stream, size_t size, binary_t& decrypted, size_t aadlen, binary_t& tag,
                                 stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        tag.clear();

        uint16 alg = session->get_cipher_suite();

        tls_advisor* advisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint = advisor->hintof_tls_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto tagsize = hint->tagsize;

        binary_t aad;
        binary_append(aad, stream, aadlen);
        binary_append(tag, stream + aadlen + size - tagsize, tagsize);

        auto const& key = get_item(tls_secret_handshake_server_key);
        binary_t iv;  // XOR seq
        build_iv(session, tls_secret_handshake_server_iv, iv);

        crypt_context_t* handle = nullptr;
        openssl_crypt crypt;
        ret = crypt.open(&handle, hint->cipher, hint->mode, key, iv);
        if (errorcode_t::success == ret) {
            ret = crypt.decrypt2(handle, stream + aadlen, size - tagsize, decrypted, &aad, &tag);
            crypt.close(handle);
        }

        if (debugstream) {
            debugstream->printf(" > key %s\n", base16_encode(key).c_str());
            debugstream->printf(" > iv %s\n", base16_encode(iv).c_str());
            debugstream->printf(" > aad %s\n", base16_encode(aad).c_str());
            debugstream->printf(" > tag %s\n", base16_encode(tag).c_str());
            debugstream->printf(" > decrypted\n");
            dump_memory(decrypted, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf("\n");
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::verify(tls_session* session, uint16 scheme, const binary_t& data, const binary_t& signature) {
    return_t ret = errorcode_t::success;
    __try2 {
#if 0
        // RFC 8446 4.4.3.  Certificate Verify
        //  Transcript-Hash(Handshake Context, Certificate)
        //  "TLS 1.3, server CertificateVerify" / "TLS 1.3, client CertificateVerify"
        //  2020202020202020202020202020202020202020202020202020202020202020
        //  2020202020202020202020202020202020202020202020202020202020202020
        //  544c5320312e332c207365727665722043657274696669636174655665726966
        //  79
        //  00
        //  0101010101010101010101010101010101010101010101010101010101010101
        constexpr char constexpr_context[] = "TLS 1.3, server CertificateVerify";
        // RFC 8446 4.4.1
        // 
        crypto_sign_builder builder;
        crypto_sign* sign = nullptr;
        switch(scheme) {
            case 0x0401:  /* rsa_pkcs1_sha256 */ {
            } break;
            case 0x0501:  /* rsa_pkcs1_sha384 */ {
            } break;
            case 0x0601:  /* rsa_pkcs1_sha512 */ {
            } break;
            case 0x0403:  /* ecdsa_secp256r1_sha256 */ {
            } break;
            case 0x0503:  /* ecdsa_secp384r1_sha384 */ {
            } break;
            case 0x0603:  /* ecdsa_secp521r1_sha512 */ {
            } break;
            case 0x0804:  /* rsa_pss_rsae_sha256 */ {
                sign = builder.set_tls_scheme(scheme).set_digest(sha2_256).build();
            } break;
            case 0x0805:  /* rsa_pss_rsae_sha384 */ {
                sign = builder.set_tls_scheme(scheme).set_digest(sha2_384).build();
            } break;
            case 0x0806:  /* rsa_pss_rsae_sha512 */ {
                sign = builder.set_tls_scheme(scheme).set_digest(sha2_512).build();
            } break;
            case 0x0807:  /* ed25519 */
            case 0x0808:  /* ed448 */ {
                sign = builder.set_tls_scheme(scheme).build();
            } break;
            case 0x0809:  /* rsa_pss_pss_sha256 */ {
            } break;
            case 0x080a:  /* rsa_pss_pss_sha384 */ {
            } break;
            case 0x080b:  /* rsa_pss_pss_sha512 */ {
            } break;
            case 0x0201:  /* rsa_pkcs1_sha1 */ {
            } break;
            case 0x0203:  /* ecdsa_sha1 */ {
            } break;
        }
        if (nullptr == sign) {
            ret = errorcode_t::unknown;
            __leave2;
        }
#endif
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void tls_protection::get_item(tls_secret_t type, binary_t& item) { item = _kv[type]; }

const binary_t& tls_protection::get_item(tls_secret_t type) { return _kv[type]; }

uint8 tls_protection::get_mode() { return _mode; }

}  // namespace net
}  // namespace hotplace
