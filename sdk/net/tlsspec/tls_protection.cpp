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
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/basic/crypto_keychain.hpp>
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/crypto/crypto/crypto_aead.hpp>
#include <sdk/crypto/crypto/crypto_hash.hpp>
#include <sdk/crypto/crypto/crypto_mac.hpp>
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/net/tlsspec/tls.hpp>
#include <sdk/net/tlsspec/tls_advisor.hpp>
// debug
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {
namespace net {

tls_protection::tls_protection(uint8 mode) : _mode(mode), _alg(0), _version(0), _transcript_hash(nullptr) {}

tls_protection::~tls_protection() {
    if (_transcript_hash) {
        _transcript_hash->release();
    }
}

uint8 tls_protection::get_mode() { return _mode; }

uint16 tls_protection::get_cipher_suite() { return _alg; }

void tls_protection::set_cipher_suite(uint16 alg) { _alg = alg; }

uint16 tls_protection::get_tls_version() { return _version; }

void tls_protection::set_tls_version(uint16 version) { _version = version; }

transcript_hash* tls_protection::get_transcript_hash() {
    critical_section_guard guard(_lock);
    if (nullptr == _transcript_hash) {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        // hash_algorithm_t hashalg = tlsadvisor->hash_alg_of(get_cipher_suite()); // TLS 1.3
        const tls_alg_info_t* hint_tls_alg = tlsadvisor->hintof_tls_algorithm(get_cipher_suite());  // TLS 1.0~
        auto hashalg = algof_mac1(hint_tls_alg);
        transcript_hash_builder builder;
        _transcript_hash = builder.set(hashalg).build();
    }
    if (_transcript_hash) {
        _transcript_hash->addref();
    }
    return _transcript_hash;
}

crypto_key& tls_protection::get_cert() { return _cert; }

crypto_key& tls_protection::get_keyexchange() { return _keyexchange; }

return_t tls_protection::calc(tls_session* session, uint16 type) {
    return_t ret = errorcode_t::success;
    // RFC 8446 7.1.  Key Schedule
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint16 alg = get_cipher_suite();

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        const tls_alg_info_t* hint_tls_alg = tlsadvisor->hintof_tls_algorithm(alg);
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

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

        binary_t ikm_empty;
        binary_t empty_hash;

        {
            openssl_digest dgst;
            binary_t empty;
            dgst.digest(hashalg, empty, empty_hash);
            _kv[tls_secret_empty_hash] = empty_hash;
        }
        ikm_empty.resize(dlen);

        binary_t context_hash;
        auto tshash = get_transcript_hash();
        if (tshash) {
            tshash->digest(context_hash);
            tshash->release();
        }

        auto lambda_expand_label = [&](tls_secret_t sec, binary_t& okm, const char* alg, uint16 dlen, const binary_t& secret, const char* label,
                                       const binary_t& context) -> void {
            kdf.hkdf_expand_label(okm, alg, dlen, secret, str2bin(label), context);
            _kv[sec] = okm;
        };
        auto lambda_extract = [&](tls_secret_t sec, binary_t& prk, const char* alg, const binary_t& salt, const binary_t& ikm) -> void {
            kdf.hmac_kdf_extract(prk, alg, salt, ikm);
            _kv[sec] = prk;
        };

        // binary_t hello_hash;
        if (tls_context_server_hello == type) {
            // hello_hash = context_hash;
            _kv[tls_secret_hello_hash] = context_hash;

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

            // RFC 8446 4.2.9.  Pre-Shared Key Exchange Modes
            //  psk_ke      ... pre_shared_key
            //  psk_dhe_ke  ... key_share
            binary_t shared_secret;
            {
#if 1
                // in server ... priv("server") + pub("CH") <-- this case
                const EVP_PKEY* pkey_priv = get_keyexchange().find("server");
                const EVP_PKEY* pkey_pub = get_keyexchange().find("CH");  // client_hello
#else
                // in client ... priv("client") + pub("SH")
                const EVP_PKEY* pkey_priv = get_keyexchange().find("client");
                const EVP_PKEY* pkey_pub = get_keyexchange().find("SH");  // server_hello
#endif
                if (nullptr == pkey_priv || nullptr == pkey_pub) {
                    ret = errorcode_t::not_found;
                    __leave2;
                }

                ret = dh_key_agreement(pkey_priv, pkey_pub, shared_secret);

                _kv[tls_secret_shared_secret] = shared_secret;
            }

            binary_t early_secret;
            {
                binary_t salt;
                salt.resize(1);
                lambda_extract(tls_secret_early_secret, early_secret, hashalg, salt, ikm_empty);
            }

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
            lambda_expand_label(tls_secret_handshake_derived, handshake_derived_secret, hashalg, dlen, early_secret, "derived", empty_hash);
            binary_t handshake_secret;
            lambda_extract(tls_secret_handshake, handshake_secret, hashalg, handshake_derived_secret, shared_secret);

            binary_t okm;
            if (tls_mode_client & get_mode()) {
                binary_t handshake_client_secret;
                lambda_expand_label(tls_secret_handshake_client, handshake_client_secret, hashalg, dlen, handshake_secret, "c hs traffic", context_hash);

                if (tls_mode_tls & get_mode()) {
                    lambda_expand_label(tls_secret_handshake_client_key, okm, hashalg, keysize, handshake_client_secret, "key", context);
                    lambda_expand_label(tls_secret_handshake_client_iv, okm, hashalg, 12, handshake_client_secret, "iv", context);
                }
                if (tls_mode_quic & get_mode()) {
                    lambda_expand_label(tls_secret_handshake_quic_client_key, okm, hashalg, keysize, handshake_client_secret, "quic key", context);
                    lambda_expand_label(tls_secret_handshake_quic_client_iv, okm, hashalg, 12, handshake_client_secret, "quic iv", context);
                    lambda_expand_label(tls_secret_handshake_quic_client_hp, okm, hashalg, keysize, handshake_client_secret, "quic hp", context);
                }
            }
            if (tls_mode_server & get_mode()) {
                binary_t handshake_server_secret;
                lambda_expand_label(tls_secret_handshake_server, handshake_server_secret, hashalg, dlen, handshake_secret, "s hs traffic", context_hash);

                if (tls_mode_tls & get_mode()) {
                    lambda_expand_label(tls_secret_handshake_server_key, okm, hashalg, keysize, handshake_server_secret, "key", context);
                    lambda_expand_label(tls_secret_handshake_server_iv, okm, hashalg, 12, handshake_server_secret, "iv", context);
                }
                if (tls_mode_quic & get_mode()) {
                    lambda_expand_label(tls_secret_handshake_quic_server_key, okm, hashalg, keysize, handshake_server_secret, "quic key", context);
                    lambda_expand_label(tls_secret_handshake_quic_server_iv, okm, hashalg, 12, handshake_server_secret, "quic iv", context);
                    lambda_expand_label(tls_secret_handshake_quic_server_hp, okm, hashalg, keysize, handshake_server_secret, "quic hp", context);
                }
            }
        } else if (tls_context_server_finished == type) {
            _kv[tls_context_server_finished] = context_hash;
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
            const binary_t& handshake_secret = _kv[tls_secret_handshake];

            binary_t application_derived_secret;
            lambda_expand_label(tls_secret_application_derived, application_derived_secret, hashalg, dlen, handshake_secret, "derived", empty_hash);
            binary_t application_secret;
            lambda_extract(tls_secret_application, application_secret, hashalg, application_derived_secret, ikm_empty);

            binary_t okm;
            if (tls_mode_client & get_mode()) {
                binary_t application_client_secret;
                lambda_expand_label(tls_secret_application_client, application_client_secret, hashalg, dlen, application_secret, "c ap traffic", context_hash);

                if (tls_mode_tls & get_mode()) {
                    lambda_expand_label(tls_secret_application_client_key, okm, hashalg, keysize, application_client_secret, "key", context);
                    lambda_expand_label(tls_secret_application_client_iv, okm, hashalg, 12, application_client_secret, "iv", context);
                }
                if (tls_mode_quic & get_mode()) {
                    lambda_expand_label(tls_secret_application_quic_client_key, okm, hashalg, keysize, application_client_secret, "quic key", context);
                    lambda_expand_label(tls_secret_application_quic_client_iv, okm, hashalg, 12, application_client_secret, "quic iv", context);
                    lambda_expand_label(tls_secret_application_quic_client_hp, okm, hashalg, keysize, application_client_secret, "quic hp", context);
                }
            }
            if (tls_mode_server & get_mode()) {
                binary_t application_server_secret;
                lambda_expand_label(tls_secret_application_server, application_server_secret, hashalg, dlen, application_secret, "s ap traffic", context_hash);

                if (tls_mode_tls & get_mode()) {
                    lambda_expand_label(tls_secret_application_server_key, okm, hashalg, keysize, application_server_secret, "key", context);
                    lambda_expand_label(tls_secret_application_server_iv, okm, hashalg, 12, application_server_secret, "iv", context);
                }
                if (tls_mode_quic & get_mode()) {
                    lambda_expand_label(tls_secret_application_quic_server_key, okm, hashalg, keysize, application_server_secret, "quic key", context);
                    lambda_expand_label(tls_secret_application_quic_server_iv, okm, hashalg, 12, application_server_secret, "quic iv", context);
                    lambda_expand_label(tls_secret_application_quic_server_hp, okm, hashalg, keysize, application_server_secret, "quic hp", context);
                }
            }

            binary_t exporter_master_secret;
            lambda_expand_label(tls_secret_exporter_master, exporter_master_secret, hashalg, dlen, application_secret, "exp master", context_hash);
        } else if (tls_context_client_finished == type) {
            binary_t resumption_master_secret;
            const binary_t& application_secret = get_item(tls_secret_application);
            lambda_expand_label(tls_secret_resumption_master, resumption_master_secret, hashalg, dlen, application_secret, "res master", context_hash);
            binary_t resumption_secret;
            binary_t reshash;
            reshash.resize(2);
            lambda_expand_label(tls_secret_resumption, resumption_secret, hashalg, dlen, resumption_master_secret, "resumption", reshash);

            // RFC 8448 4.  Resumed 0-RTT Handshake
            binary_t resumption_early_secret;
            lambda_extract(tls_secret_resumption_early, resumption_early_secret, hashalg, ikm_empty, resumption_secret);
        } else if (tls_context_client_key_exchange == type) {
            /**
             * RFC 5246 8.1.  Computing the Master Secret
             * master_secret = PRF(pre_master_secret, "master secret",
             *                     ClientHello.random + ServerHello.random)
             *                     [0..47];
             */

            hash_algorithm_t hmac_alg = algof_mac1(hint_tls_alg);

            binary_t pre_master_secret;
            binary_t master_secret;
            const binary_t& client_hello_random = get_item(tls_context_client_hello_random);
            const binary_t& server_hello_random = get_item(tls_context_server_hello_random);

            {
#if 1
                const EVP_PKEY* pkey_priv = get_keyexchange().find("server");
                const EVP_PKEY* pkey_pub = get_keyexchange().find("CKE");
#else
                const EVP_PKEY* pkey_priv = get_keyexchange().find("client");
                const EVP_PKEY* pkey_pub = get_keyexchange().find("SKE");
#endif
                if (nullptr == pkey_priv || nullptr == pkey_pub) {
                    ret = errorcode_t::not_found;
                    __leave2;
                }
                ret = dh_key_agreement(pkey_priv, pkey_pub, pre_master_secret);
                if (errorcode_t::success != ret) {
                    __leave2;
                }

                set_item(tls_secret_pre_master, pre_master_secret);
            }

            crypto_hmac_builder builder;
            auto hmac_master = builder.set(hmac_alg).set(pre_master_secret).build();
            if (hmac_master) {
                /**
                 * master secret
                 * RFC 2246 5. HMAC and the pseudorandom function
                 * RFC 2246 8.1. Computing the master secret
                 * master_secret = PRF(pre_master_secret, "master secret",
                 *                     ClientHello.random + ServerHello.random)
                 *                     [0..47];
                 */
                binary_t seed;
                hash_context_t* hmac_handle = nullptr;
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

void tls_protection::get_item(tls_secret_t type, binary_t& item) { item = _kv[type]; }

const binary_t& tls_protection::get_item(tls_secret_t type) { return _kv[type]; }

void tls_protection::set_item(tls_secret_t type, const binary_t& item) { _kv[type] = item; }

void tls_protection::set_item(tls_secret_t type, const byte_t* stream, size_t size) {
    if (stream) {
        binary_t bin;
        bin.insert(bin.end(), stream, stream + size);
        _kv[type] = std::move(bin);
    }
}

return_t tls_protection::build_iv(tls_session* session, tls_secret_t type, binary_t& iv, uint64 recordno) {
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

return_t tls_protection::decrypt_tls13(tls_session* session, tls_role_t role, const byte_t* stream, size_t size, binary_t& plaintext, size_t aadlen,
                                       binary_t& tag, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        tag.clear();

        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint = tlsadvisor->hintof_tls_algorithm(get_cipher_suite());
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
        }

        auto tagsize = hint->tagsize;

        binary_t aad;
        binary_append(aad, stream, aadlen);
        binary_append(tag, stream + aadlen + size - tagsize, tagsize);

        crypt_context_t* handle = nullptr;
        openssl_crypt crypt;

        tls_secret_t secret_key;
        tls_secret_t secret_iv;
        uint64 record_no = 0;
        auto& ri = session->get_roleinfo(role);
        auto hsstatus = ri.get_status();
        record_no = ri.get_recordno(true);
        if (role_client == role) {
            if (tls_handshake_finished == hsstatus) {
                secret_key = tls_secret_application_client_key;
                secret_iv = tls_secret_application_client_iv;
            } else {
                secret_key = tls_secret_handshake_client_key;
                secret_iv = tls_secret_handshake_client_iv;
            }
        } else {
            if (tls_handshake_finished == hsstatus) {
                secret_key = tls_secret_application_server_key;
                secret_iv = tls_secret_application_server_iv;
            } else {
                secret_key = tls_secret_handshake_server_key;
                secret_iv = tls_secret_handshake_server_iv;
            }
        }

        auto const& key = get_item(secret_key);
        auto const& iv = get_item(secret_iv);
        binary_t nonce = iv;
        build_iv(session, secret_iv, nonce, record_no);
        ret = crypt.open(&handle, hint->cipher, hint->mode, key, nonce);
        if (errorcode_t::success == ret) {
            ret = crypt.decrypt2(handle, stream + aadlen, size - tagsize, plaintext, &aad, &tag);
            crypt.close(handle);
        }

        if (debugstream) {
            debugstream->autoindent(3);
            debugstream->printf(" > key %s\n", base16_encode(key).c_str());
            debugstream->printf(" > iv %s\n", base16_encode(iv).c_str());
            debugstream->printf(" > record no %i\n", record_no);
            debugstream->printf(" > nonce %s\n", base16_encode(nonce).c_str());
            debugstream->printf(" > aad %s\n", base16_encode(aad).c_str());
            debugstream->printf(" > tag %s\n", base16_encode(tag).c_str());
            debugstream->printf(" > plaintext\n");
            dump_memory(plaintext, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->autoindent(0);
            debugstream->printf("\n");
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_protection::decrypt_tls1(tls_session* session, tls_role_t role, const byte_t* stream, size_t size, binary_t& plaintext, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto ciphersuite = get_cipher_suite();
        const tls_alg_info_t* hint_tls_alg = tlsadvisor->hintof_tls_algorithm(ciphersuite);
        if (nullptr == hint_tls_alg) {
            ret = errorcode_t::not_supported;
            __leave2;
        }
        const tls_alg_info_t* hint = tlsadvisor->hintof_tls_algorithm(ciphersuite);
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

        crypt_context_t* handle = nullptr;
        openssl_crypt crypt;

        tls_secret_t secret_mac_key;
        tls_secret_t secret_key;
        uint64 record_no = 0;
        auto& ri = session->get_roleinfo(role);
        auto hsstatus = ri.get_status();
        record_no = ri.get_recordno(true);
        if (role_client == role) {
            secret_mac_key = tls_secret_server_mac_key;
            secret_key = tls_secret_server_key;
        } else {
            secret_mac_key = tls_secret_client_mac_key;
            secret_key = tls_secret_client_key;
        }

        const binary_t& key = get_item(secret_key);
        binary_t iv;
        binary_append(iv, stream + sizeof(tls_content_t), ivsize);
        size_t bpos = sizeof(tls_content_t) + ivsize;

        ret = crypt.open(&handle, hint->cipher, hint->mode, key, iv);
        if (errorcode_t::success == ret) {
            crypt.set(handle, crypt_ctrl_padding, 0);
            ret = crypt.decrypt(handle, stream + bpos, size - bpos, plaintext);
            crypt.close(handle);
        }
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // MAC
        binary_t content;
        binary_t verifydata;
        binary_t maced;
        const binary_t& mackey = get_item(secret_mac_key);
        {
            auto hmac_alg = algof_mac(hint_tls_alg);
            auto hint_digest = advisor->hintof_digest(hmac_alg);
            auto dlen = sizeof_digest(hint_digest);
            /**
             * sequence='0000000000000000'
             * rechdr='16 03 03' ; content_type version
             * datalen='00 10'
             * data='00 01 ... 0f'
             * > data.data = &protectedtext[0]
             * > data.size = protectedtext.size() - 32
             * verifydata
             * > verifydata.data = &protectedtext[datasize]
             * > verifydata.size = 32
             */
            size_t size_mackey = (dlen + 31) & ~31;  // sha1 20 -> 32
            size_t datalen = plaintext.size() - size_mackey;
            binary_append(content, uint64(record_no), hton64);            // sequence
            binary_append(content, stream, 3);                            // rechdr (content_type, version)
            binary_append(content, uint16(datalen), hton16);              // datalen
            binary_append(content, &plaintext[0], datalen);               // data
            binary_append(verifydata, &plaintext[datalen], size_mackey);  // verifydata

            // plaintext.resize(datalen);

            uint8 pad = *verifydata.rbegin();
            size_t verifydatasize = verifydata.size() - pad - 1;
            verifydata.resize(verifydatasize);

            crypto_hmac_builder builder;
            auto hmac = builder.set(hint_tls_alg->mac).set(mackey).build();
            if (hmac) {
                hmac->update(content).finalize(maced);
                hmac->release();
            }
            if (maced != verifydata) {
                ret = errorcode_t::mismatch;
            }
        }

        if (debugstream) {
            debugstream->autoindent(3);
            debugstream->printf(" > key %s\n", base16_encode(key).c_str());
            debugstream->printf(" > iv %s\n", base16_encode(iv).c_str());
            debugstream->printf(" > record no %i\n", record_no);
            debugstream->printf(" > ciphertext\n");
            dump_memory(stream + bpos, size - bpos, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf("\n");
            debugstream->printf(" > plaintext\n");
            dump_memory(plaintext, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf("\n");
            debugstream->printf(" > verifydata\n");
            dump_memory(verifydata, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf("\n");
            debugstream->printf(" > content\n");
            dump_memory(content, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf("\n");
            debugstream->printf(" > mackey\n");
            dump_memory(mackey, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->printf("\n");
            debugstream->printf(" > maced\n");
            dump_memory(maced, debugstream, 16, 3, 0x0, dump_notrunc);
            debugstream->autoindent(0);
            debugstream->printf("\n");
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

crypto_sign* tls_protection::get_crypto_sign(uint16 scheme) {
    crypto_sign_builder builder;
    crypto_sign* sign = nullptr;
    switch (scheme) {
        case 0x0401: /* rsa_pkcs1_sha256 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_256).build();
        } break;
        case 0x0501: /* rsa_pkcs1_sha384 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_384).build();
        } break;
        case 0x0601: /* rsa_pkcs1_sha512 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_512).build();
        } break;
        case 0x0403: /* ecdsa_secp256r1_sha256 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_256).build();
        } break;
        case 0x0503: /* ecdsa_secp384r1_sha384 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_384).build();
        } break;
        case 0x0603: /* ecdsa_secp521r1_sha512 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_512).build();
        } break;
        case 0x0804: /* rsa_pss_rsae_sha256 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_256).build();
        } break;
        case 0x0805: /* rsa_pss_rsae_sha384 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_384).build();
        } break;
        case 0x0806: /* rsa_pss_rsae_sha512 */ {
            sign = builder.tls_sign_scheme(scheme).set_digest(sha2_512).build();
        } break;
        case 0x0807: /* ed25519 */
        case 0x0808: /* ed448 */ {
            sign = builder.tls_sign_scheme(scheme).build();
        } break;
        case 0x0809: /* rsa_pss_pss_sha256 */ {
        } break;
        case 0x080a: /* rsa_pss_pss_sha384 */ {
        } break;
        case 0x080b: /* rsa_pss_pss_sha512 */ {
        } break;
        case 0x0201: /* rsa_pkcs1_sha1 */ {
        } break;
        case 0x0203: /* ecdsa_sha1 */ {
        } break;
    }
    return sign;
}

}  // namespace net
}  // namespace hotplace
