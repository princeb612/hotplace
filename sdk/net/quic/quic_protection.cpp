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

namespace hotplace {
namespace net {

quic_protection::quic_protection(const binary_t& salt, uint32 flags) {
    _shared.make_share(this);
    _kv[quic_original_dcid] = salt;
    compute(salt, binary_t(), flags);
}

quic_protection::quic_protection(const binary_t& salt, const binary_t& context, uint32 flags) {
    _shared.make_share(this);
    _kv[quic_original_dcid] = salt;
    compute(salt, context, flags);
}

const binary_t& quic_protection::get_item(quic_initial_keys_t mode) { return _kv[mode]; }

void quic_protection::get_item(quic_initial_keys_t mode, binary_t& item) { item = _kv[mode]; }

return_t quic_protection::compute(const binary_t& salt, const binary_t& context, uint32 flags) {
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
     *   HKDF-Extract(salt, IKM) -> PRK
     *   HKDF-Expand(PRK, info, L) -> OKM
     *
     * RFC 8446 7.1.  Key Schedule
     *   HKDF-Expand-Label(Secret, Label, Context, Length) =
     *        HKDF-Expand(Secret, HkdfLabel, Length)
     *
     *   Where HkdfLabel is specified as:
     *
     *   struct {
     *       uint16 length = Length;
     *       opaque label<7..255> = "tls13 " + Label;
     *       opaque context<0..255> = Context;
     *   } HkdfLabel;
     *
     *   Derive-Secret(Secret, Label, Messages) =
     *        HKDF-Expand-Label(Secret, Label,
     *                          Transcript-Hash(Messages), Hash.length)
     *
     * RFC 9001 5.2.  Initial Secrets
     *   initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
     *   quic_initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
     *   client_initial_secret = HKDF-Expand-Label(quic_initial_secret, "client in", "", Hash.length)
     *   server_initial_secret = HKDF-Expand-Label(quic_initial_secret, "server in", "", Hash.length)
     *
     * RFC 9001 A.1.  Keys
     *   client in:  00200f746c73313320636c69656e7420696e00
     *   server in:  00200f746c7331332073657276657220696e00
     *   quic key:  00100e746c7331332071756963206b657900
     *   quic iv:  000c0d746c733133207175696320697600
     *   quic hp:  00100d746c733133207175696320687000
     *
     *   The initial secret is common:
     *   quic_initial_secret = HKDF-Extract(initial_salt, cid)
     *       = 7db5df06e7a69e432496adedb0085192
     *         3595221596ae2ae9fb8115c1e9ed0a44
     *
     *   The secrets for protecting client packets are:
     *   client_initial_secret
     *       = HKDF-Expand-Label(quic_initial_secret, "client in", "", 32)
     *       = c00cf151ca5be075ed0ebfb5c80323c4
     *         2d6b7db67881289af4008f1f6c357aea
     *
     *    key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16)
     *        = 1f369613dd76d5467730efcbe3b1a22d
     *
     *    iv  = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12)
     *        = fa044b2f42a3fd3b46fb255c
     *
     *    hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16)
     *        = 9f50449e04a0e810283a1e9933adedd2
     *
     *    The secrets for protecting server packets are:
     *    server_initial_secret
     *        = HKDF-Expand-Label(quic_initial_secret, "server in", "", 32)
     *        = 3c199828fd139efd216c155ad844cc81
     *          fb82fa8d7446fa7d78be803acdda951b
     *    key = HKDF-Expand-Label(server_initial_secret, "quic key", "", 16)
     *        = cf3a5331653c364c88f0f379b6067e37
     *    iv  = HKDF-Expand-Label(server_initial_secret, "quic iv", "", 12)
     *        = 0ac1493ca1905853b0bba03e
     *    hp  = HKDF-Expand-Label(server_initial_secret, "quic hp", "", 16)
     *        = c206b8d9b9f0f37644430b490eeaa314
     *
     * RFC 9001 5.4.4.  ChaCha20-Based Header Protection
     *    header_protection(hp_key, sample):
     *      counter = sample[0..3]
     *      nonce = sample[4..15]
     *      mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
     *
     * RFC 9001 A.5.  ChaCha20-Poly1305 Short Header Packet
     *
     *    secret
     *        = 9ac312a7f877468ebe69422748ad00a1
     *          5443f18203a07d6060f688f30f21632b
     *    key = HKDF-Expand-Label(secret, "quic key", "", 32)
     *        = c6d98ff3441c3fe1b2182094f69caa2e
     *          d4b716b65488960a7a984979fb23e1c8
     *    iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)
     *        = e0459b3474bdd0e44a41c144
     *    hp  = HKDF-Expand-Label(secret, "quic hp", "", 32)
     *        = 25a282b9e82f06f21f488917a4fc8f1b
     *          73573685608597d0efcb076b0ab7a7a4
     *    ku  = HKDF-Expand-Label(secret, "quic ku", "", 32)
     *        = 1223504755036d556342ee9361d25342
     *          1a826c9ecdf3c7148684b36b714881f9
     */

    ret = kdf.hmac_kdf_extract(bin_initial_secret, alg, bin_initial_salt, salt);
    _kv[quic_initial_secret] = bin_initial_secret;

    if ((quic_client_secret | quic_client_key | quic_client_iv | quic_client_hp) & flags) {
        kdf.hkdf_expand_label(bin_client_initial_secret, alg, 32, bin_initial_secret, str2bin("client in"), context);
        _kv[quic_client_secret] = bin_client_initial_secret;

        if (quic_client_key & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_client_initial_secret, str2bin("quic key"), context);
            _kv[quic_client_key] = bin;
        }

        if (quic_client_iv & flags) {
            kdf.hkdf_expand_label(bin, alg, 12, bin_client_initial_secret, str2bin("quic iv"), context);
            _kv[quic_client_iv] = bin;
        }

        if (quic_client_hp & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_client_initial_secret, str2bin("quic hp"), context);
            _kv[quic_client_hp] = bin;
        }
    }

    if ((quic_server_secret | quic_server_key | quic_server_iv | quic_server_hp) & flags) {
        kdf.hkdf_expand_label(bin_server_initial_secret, alg, 32, bin_initial_secret, str2bin("server in"), context);
        _kv[quic_server_secret] = bin_server_initial_secret;

        if (quic_server_key & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_server_initial_secret, str2bin("quic key"), context);
            _kv[quic_server_key] = bin;
        }

        if (quic_server_iv & flags) {
            kdf.hkdf_expand_label(bin, alg, 12, bin_server_initial_secret, str2bin("quic iv"), context);
            _kv[quic_server_iv] = bin;
        }

        if (quic_server_hp & flags) {
            kdf.hkdf_expand_label(bin, alg, 16, bin_server_initial_secret, str2bin("quic hp"), context);
            _kv[quic_server_hp] = bin;
        }
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
         *
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
            if (quic_mode_t::quic_mode_server == mode) {
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
        if (quic_mode_t::quic_mode_server == mode) {
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

        crypt.open(&handle, "aes-128-gcm", bin_key, bin_nonce);
        ret = crypt.encrypt2(handle, payload, encrypted, &aad, &tag);
        crypt.close(handle);
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
        if (quic_mode_t::quic_mode_server == mode) {
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

        crypt.open(&handle, "aes-128-gcm", bin_key, bin_nonce);
        crypt.decrypt2(handle, payload, decrypted, &aad, &tag);
        crypt.close(handle);
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
