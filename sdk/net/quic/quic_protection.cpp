/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <math.h>

#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/openssl_kdf.hpp>
#include <sdk/net/quic/quic.hpp>
#include <sdk/net/tls1/types.hpp>

namespace hotplace {
namespace net {

quic_protection::quic_protection(const binary_t& salt, uint32 mode) {
    _shared.make_share(this);
    _kv[quic_original_dcid] = salt;
    calc(salt, binary_t(), mode);
}

quic_protection::quic_protection(const binary_t& salt, const binary_t& context, uint32 mode) {
    _shared.make_share(this);
    _kv[quic_original_dcid] = salt;
    calc(salt, context, mode);
}

const binary_t& quic_protection::get_item(quic_initial_keys_t mode) { return _kv[mode]; }

void quic_protection::get_item(quic_initial_keys_t mode, binary_t& item) { item = _kv[mode]; }

return_t quic_protection::calc(const binary_t& salt, const binary_t& context, uint32 mode) {
    return_t ret = errorcode_t::success;

    openssl_kdf kdf;
    const char* initial_salt = "0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a";
    binary_t bin_initial_salt = base16_decode_rfc(initial_salt);
    binary_t bin;
    binary_t bin_initial_secret;
    binary_t bin_client_initial_secret;
    binary_t bin_server_initial_secret;
    constexpr char alg[] = "sha256";

    /**
     * RFC 5869
     * RFC 8446 7.1.  Key Schedule
     * RFC 9001 5.2.  Initial Secrets
     * RFC 9001 A.1.  Keys
     * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
     * RFC 9001 A.5.  ChaCha20-Poly1305 Short Header Packet
     */

    ret = kdf.hmac_kdf_extract(bin_initial_secret, alg, bin_initial_salt, salt);
    _kv[quic_initial_secret] = bin_initial_secret;

    if (tls_mode_client & mode) {
        kdf.hkdf_expand_tls13_label(bin_client_initial_secret, alg, 32, bin_initial_secret, str2bin("client in"), context);
        _kv[quic_client_secret] = bin_client_initial_secret;

        kdf.hkdf_expand_tls13_label(bin, alg, 16, bin_client_initial_secret, str2bin("quic key"), context);
        _kv[quic_client_key] = bin;

        kdf.hkdf_expand_tls13_label(bin, alg, 12, bin_client_initial_secret, str2bin("quic iv"), context);
        _kv[quic_client_iv] = bin;

        kdf.hkdf_expand_tls13_label(bin, alg, 16, bin_client_initial_secret, str2bin("quic hp"), context);
        _kv[quic_client_hp] = bin;
    }

    if (tls_mode_server & mode) {
        kdf.hkdf_expand_tls13_label(bin_server_initial_secret, alg, 32, bin_initial_secret, str2bin("server in"), context);
        _kv[quic_server_secret] = bin_server_initial_secret;

        kdf.hkdf_expand_tls13_label(bin, alg, 16, bin_server_initial_secret, str2bin("quic key"), context);
        _kv[quic_server_key] = bin;

        kdf.hkdf_expand_tls13_label(bin, alg, 12, bin_server_initial_secret, str2bin("quic iv"), context);
        _kv[quic_server_iv] = bin;

        kdf.hkdf_expand_tls13_label(bin, alg, 16, bin_server_initial_secret, str2bin("quic hp"), context);
        _kv[quic_server_hp] = bin;
    }

    return ret;
}

return_t quic_protection::hpmask(uint32 mode, const byte_t* sample, size_t size_sample, binary_t& mask) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == sample) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        /**
         * RFC 9001 5.4.3.  AES-Based Header Protection
         *
         *  header_protection(hp_key, sample):
         *    mask = AES-ECB(hp_key, sample)
         *
         * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
         *
         *  header_protection(hp_key, sample):
         *    counter = sample[0..3]
         *    nonce = sample[4..15]
         *    mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
         *
         * RFC 9001 A.2.
         *  sample = d1b1c98dd7689fb8ec11d242b123dc9b
         *  mask = AES-ECB(hp, sample)[0..4]
         *       = 437b9aec36
         *
         * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
         *  header_protection(hp_key, sample):
         *    counter = sample[0..3]
         *    nonce = sample[4..15]
         *    mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
         */

        crypt_context_t* handle = nullptr;

        // mask = AES-ECB(hp_key, sample)
        {
            openssl_crypt crypt;
            quic_initial_keys_t kty = quic_initial_keys_t::quic_client_hp;
            if (tls_mode_t::tls_mode_server == mode) {
                kty = quic_initial_keys_t::quic_server_hp;
            }
            auto const& key = get_item(kty);
            auto const& iv = binary_t();
            ret = crypt.open(&handle, "aes-128-ecb", key, iv);
            if (errorcode_t::success == ret) {
                ret = crypt.encrypt(handle, sample, size_sample, mask);
                crypt.close(handle);
            }
            if (errorcode_t::success != ret) {
                __leave2;
            }
            mask.resize(5);  // [0..4]
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_protection::hpencode(uint32 mode, const binary_t& mask, byte_t& ht, binary_t& bin_pn) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (bin_pn.size() < 4) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        /**
         * RFC 9001 5.4.1.  Header Protection Application
         *
         *  mask = header_protection(hp_key, sample)
         *
         *  pn_length = (packet[0] & 0x03) + 1
         *  if (packet[0] & 0x80) == 0x80:
         *     # Long header: 4 bits masked
         *     packet[0] ^= mask[0] & 0x0f
         *  else:
         *     # Short header: 5 bits masked
         *     packet[0] ^= mask[0] & 0x1f
         *
         *  # pn_offset is the start of the Packet Number field.
         *  packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
         *
         *                  Figure 6: Header Protection Pseudocode
         *
         * RFC 9001 A.2.
         *  header[0] ^= mask[0] & 0x0f
         *          = c0
         *  header[18..21] ^= mask[1..4]
         *          = 7b9aec34
         *  header = c000000001088394c8f03e5157080000449e7b9aec34
         *
         * RFC 9001 A.3 The final protected packet
         *  unprotected header = c1000000010008f067a5502a4262b50040750001
         *  packet number = 1
         *  packet number length = 2
         *  protected header = cf000000010008f067a5502a4262b5004075c0d9
         *           [5a 48]
         *  sample = 2cd0991cd25b0aac406a5816b6394100
         *
         *  The final protected packet
         *      00000000 : CF 00 00 00 01 00 08 F0 67 A5 50 2A 42 62 B5 00 | ........g.P*Bb..
         *      00000010 : 40 75 C0 D9 5A 48 2C D0 99 1C D2 5B 0A AC 40 6A | @u..ZH,....[..@j
         *
         *  5.4.2.  Header Protection Sample
         *  in sampling packet ciphertext for header protection, the Packet Number field is
         *  assumed to be 4 bytes long (its maximum possible encoded length).
         */
        {
            if (quic_packet_field_hf & ht) {
                ht ^= mask[0] & 0x0f;
            } else {
                ht ^= mask[0] & 0x1f;
            }

            for (auto i = 0; i < 4; i++) {
                bin_pn[i] ^= mask[1 + i];
            }
        }
    }
    __finally2 {
        // do noting
    }
    return ret;
}

return_t quic_protection::encrypt(uint32 mode, uint64 pn, const binary_t& payload, binary_t& encrypted, const binary_t& aad, binary_t& tag) {
    return_t ret = errorcode_t::success;
    // TODO
    // - ChaCha20-Poly1305
    __try2 {
        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        quic_initial_keys_t kty_key = quic_initial_keys_t::quic_client_key;
        quic_initial_keys_t kty_iv = quic_initial_keys_t::quic_client_iv;
        if (tls_mode_t::tls_mode_server == mode) {
            kty_key = quic_initial_keys_t::quic_server_key;
            kty_iv = quic_initial_keys_t::quic_server_iv;
        }
        const binary_t& bin_key = get_item(kty_key);
        binary_t bin_nonce = get_item(kty_iv);

        binary_t bin_pn8;
        binary_load(bin_pn8, 8, (uint64)pn, hton64);
        for (int i = 0; i < 8; i++) {
            bin_nonce[i + 12 - 8] ^= bin_pn8[i];
        }

        ret = crypt.encrypt("aes-128-gcm", bin_key, bin_nonce, payload, encrypted, aad, tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_protection::decrypt(uint32 mode, uint64 pn, const binary_t& payload, binary_t& decrypted, const binary_t& aad, const binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        // aes-128-gcm
        // chacha20-poly1305
        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        quic_initial_keys_t kty_key = quic_initial_keys_t::quic_client_key;
        quic_initial_keys_t kty_iv = quic_initial_keys_t::quic_client_iv;
        if (tls_mode_t::tls_mode_server == mode) {
            kty_key = quic_initial_keys_t::quic_server_key;
            kty_iv = quic_initial_keys_t::quic_server_iv;
        }
        const binary_t& bin_key = get_item(kty_key);
        binary_t bin_nonce = get_item(kty_iv);

        binary_t bin_pn8;
        binary_load(bin_pn8, 8, (uint64)pn, hton64);
        for (int i = 0; i < 8; i++) {
            bin_nonce[i + 12 - 8] ^= bin_pn8[i];
        }

        ret = crypt.decrypt("aes-128-gcm", bin_key, bin_nonce, payload, decrypted, aad, tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_protection::retry_integrity_tag(const quic_packet_retry& retry_packet, binary_t& tag) {
    return_t ret = errorcode_t::success;
    __try2 {
        // RFC 9001 5.8.  Retry Packet Integrity
        // RFC 9001 Figure 8: Retry Pseudo-Packet
        const char* key = "0xbe0c690b9f66575a1d766b54e368c84e";
        const char* nonce = "0x461599d35d632bf2239825bb";

        quic_packet_retry retry(retry_packet);

        binary_t bin_retry_pseudo_packet;
        binary_t bin_key = base16_decode_rfc(key);
        binary_t bin_nonce = base16_decode_rfc(nonce);
        binary_t bin_plaintext;
        binary_t bin_encrypted;
        const binary_t& bin_dcid = get_item(quic_original_dcid);

        // ODCID Length (8)
        binary_append(bin_retry_pseudo_packet, (uint8)bin_dcid.size());
        // Original Destination Connection ID (0..160)
        binary_append(bin_retry_pseudo_packet, bin_dcid);

        // Header Form (1) ~ Retry Token (..)
        retry.write(bin_retry_pseudo_packet);

        // Retry Integrity Tag
        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        crypt.open(&handle, "aes-128-gcm", bin_key, bin_nonce);
        ret = crypt.encrypt2(handle, bin_plaintext, bin_encrypted, &bin_retry_pseudo_packet, &tag);
        crypt.close(handle);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void quic_protection::addref() { _shared.addref(); }

void quic_protection::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
