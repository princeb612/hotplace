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
#include <sdk/crypto/basic/openssl_ecdh.hpp>
#include <sdk/crypto/basic/openssl_hash.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/net/tls/tlsspec.hpp>

namespace hotplace {
namespace net {

tls_handshake_key::tls_handshake_key(uint8 mode) : _mode(mode) {}

crypto_key& tls_handshake_key::get_key() { return _key; }

return_t tls_handshake_key::key_agreement(const std::string& priv_key, const std::string& pub_key, binary_t& shared) {
    return_t ret = errorcode_t::success;
    __try2 {
        const EVP_PKEY* pkey_priv = _key.find(priv_key.c_str());
        const EVP_PKEY* pkey_pub = _key.find(pub_key.c_str());
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

return_t tls_handshake_key::calc_hello_hash(uint16 alg, binary_t& hello_hash, const binary_t& client_hello, const binary_t& server_hello) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_advisor* tls_advisor = tls_advisor::get_instance();
        const tls_alg_info_t* hint = tls_advisor->hintof_tls_algorithm(alg);
        if (nullptr == hint) {
            ret = errorcode_t::not_supported;
            __leave2;
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
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_handshake_key::calc(uint16 alg, const binary_t& hello_hash, const binary_t& shared_secret) {
    return_t ret = errorcode_t::success;

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
        {
            binary_t salt;
            binary_t ikm;
            salt.resize(1);
            ikm.resize(dlen);
            kdf.hmac_kdf_extract(early_secret, hashalg, salt, ikm);
            _kv[tls_secret_early_secret] = early_secret;
        }
        binary_t empty_hash;
        {
            openssl_digest dgst;
            binary_t empty;
            dgst.digest(hashalg, empty, empty_hash);
            _kv[tls_secret_empty_hash] = empty_hash;
        }
        binary_t derived_secret;
        {
            kdf.hkdf_expand_label(derived_secret, hashalg, dlen, early_secret, str2bin("derived"), empty_hash);
            _kv[tls_secret_derived_secret] = derived_secret;
        }
        binary_t handshake_secret;
        {
            kdf.hmac_kdf_extract(handshake_secret, hashalg, derived_secret, shared_secret);
            _kv[tls_secret_handshake_secret] = handshake_secret;
        }

        binary_t okm;
        if (tls_mode_client & get_mode()) {
            binary_t client_secret;
            {
                kdf.hkdf_expand_label(client_secret, hashalg, dlen, handshake_secret, str2bin("c hs traffic"), hello_hash);
                _kv[tls_secret_client_secret] = client_secret;
            }

            if (tls_mode_tls & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, client_secret, str2bin("key"), context);
                _kv[tls_secret_client_handshake_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, client_secret, str2bin("iv"), context);
                _kv[tls_secret_client_handshake_iv] = okm;
            }
            if (tls_mode_quic & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, client_secret, str2bin("quic key"), context);
                _kv[tls_secret_client_handshake_quic_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, client_secret, str2bin("quic iv"), context);
                _kv[tls_secret_client_handshake_quic_iv] = okm;

                kdf.hkdf_expand_label(okm, hashalg, keysize, client_secret, str2bin("quic hp"), context);
                _kv[tls_secret_client_handshake_quic_hp] = okm;
            }
        }
        if (tls_mode_server & get_mode()) {
            binary_t server_secret;
            {
                kdf.hkdf_expand_label(server_secret, hashalg, dlen, handshake_secret, str2bin("s hs traffic"), hello_hash);
                _kv[tls_secret_server_secret] = server_secret;
            }

            if (tls_mode_tls & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, server_secret, str2bin("key"), context);
                _kv[tls_secret_server_handshake_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, server_secret, str2bin("iv"), context);
                _kv[tls_secret_server_handshake_iv] = okm;
            }
            if (tls_mode_quic & get_mode()) {
                kdf.hkdf_expand_label(okm, hashalg, keysize, server_secret, str2bin("quic key"), context);
                _kv[tls_secret_server_handshake_quic_key] = okm;

                kdf.hkdf_expand_label(okm, hashalg, 12, server_secret, str2bin("quic iv"), context);
                _kv[tls_secret_server_handshake_quic_iv] = okm;

                kdf.hkdf_expand_label(okm, hashalg, keysize, server_secret, str2bin("quic hp"), context);
                _kv[tls_secret_server_handshake_quic_hp] = okm;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void tls_handshake_key::get_item(tls_secret_t mode, binary_t& item) { item = _kv[mode]; }

const binary_t& tls_handshake_key::get_item(tls_secret_t mode) { return _kv[mode]; }

uint8 tls_handshake_key::get_mode() { return _mode; }

}  // namespace net
}  // namespace hotplace
