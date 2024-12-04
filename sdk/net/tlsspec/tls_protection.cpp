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
#include <sdk/crypto/crypto/crypto_sign.hpp>
#include <sdk/net/tlsspec/tlsspec.hpp>
// debug
#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {
namespace net {

tls_protection::tls_protection(uint8 mode) : _mode(mode), _alg(0), _transcript_hash(nullptr) {}

tls_protection::~tls_protection() {
    if (_transcript_hash) {
        _transcript_hash->release();
    }
}

uint8 tls_protection::get_mode() { return _mode; }

uint16 tls_protection::get_cipher_suite() { return _alg; }

void tls_protection::set_cipher_suite(uint16 alg) { _alg = alg; }

transcript_hash* tls_protection::get_transcript_hash() {
    critical_section_guard guard(_lock);
    if (nullptr == _transcript_hash) {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        hash_algorithm_t hashalg = tlsadvisor->hash_alg_of(get_cipher_suite());
        transcript_hash_builder builder;
        _transcript_hash = builder.set(hashalg).build();
    }
    if (_transcript_hash) {
        _transcript_hash->addref();
    }
    return _transcript_hash;
}

crypto_key& tls_protection::get_cert() { return _cert; }

crypto_key& tls_protection::get_key() { return _key; }

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
                const EVP_PKEY* pkey_priv = get_key().any();
                const EVP_PKEY* pkey_pub = get_keyexchange().any();
                if (nullptr == pkey_priv || nullptr == pkey_pub) {
                    ret = errorcode_t::not_found;
                    __leave2;
                }

                const EVP_PKEY* pubkey = get_peer_key(pkey_pub);
                ret = dh_key_agreement(pkey_priv, pkey_pub, shared_secret);
                EVP_PKEY_free((EVP_PKEY*)pubkey);

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

return_t tls_protection::decrypt(tls_session* session, tls_role_t role, const byte_t* stream, size_t size, binary_t& plaintext, size_t aadlen, binary_t& tag,
                                 stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        tag.clear();

        tls_advisor* advisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint = advisor->hintof_tls_algorithm(get_cipher_suite());
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

crypto_sign* tls_protection::get_crypto_sign(uint16 scheme) {
    crypto_sign_builder builder;
    crypto_sign* sign = nullptr;
    switch (scheme) {
        case 0x0401: /* rsa_pkcs1_sha256 */ {
        } break;
        case 0x0501: /* rsa_pkcs1_sha384 */ {
        } break;
        case 0x0601: /* rsa_pkcs1_sha512 */ {
        } break;
        case 0x0403: /* ecdsa_secp256r1_sha256 */ {
        } break;
        case 0x0503: /* ecdsa_secp384r1_sha384 */ {
        } break;
        case 0x0603: /* ecdsa_secp521r1_sha512 */ {
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
