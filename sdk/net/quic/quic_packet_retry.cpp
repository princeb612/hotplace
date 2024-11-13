/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * RFC 9001 5.8.  Retry Packet Integrity
 *
 *   The Retry Integrity Tag is a 128-bit field that is computed as the
 *   output of AEAD_AES_128_GCM [AEAD] used with the following inputs:
 *   *  The secret key, K, is 128 bits equal to 0xbe0c690b9f66575a1d766b54e368c84e.
 *   *  The nonce, N, is 96 bits equal to 0x461599d35d632bf2239825bb.
 *   *  The plaintext, P, is empty.
 *   *  The associated data, A, is the contents of the Retry Pseudo-Packet, as illustrated in Figure 8:
 *
 *   The secret key and the nonce are values derived by calling HKDF-Expand-Label using
 *   0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e as the secret, with labels being "quic key" and "quic iv" (Section 5.1).
 *      Retry Pseudo-Packet {
 *        ODCID Length (8),
 *        Original Destination Connection ID (0..160),
 *        Header Form (1) = 1,
 *        Fixed Bit (1) = 1,
 *        Long Packet Type (2) = 3,
 *        Unused (4),
 *        Version (32),
 *        DCID Len (8),
 *        Destination Connection ID (0..160),
 *        SCID Len (8),
 *        Source Connection ID (0..160),
 *        Retry Token (..),
 *      }
 *      Figure 8: Retry Pseudo-Packet
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/quic/quic.hpp>

namespace hotplace {
namespace net {

quic_packet_retry::quic_packet_retry() : quic_packet(quic_packet_type_retry) {}

quic_packet_retry::quic_packet_retry(const quic_packet_retry& rhs) : quic_packet(rhs) {}

return_t quic_packet_retry::read(const byte_t* stream, size_t size, size_t& pos, uint32 mode) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = quic_packet::read(stream, size, pos, mode);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // size_t initial_offset = pos;

        payload pl;
        pl << new payload_member(binary_t(), "retry token") << new payload_member(binary_t(), "retry integrity tag");
        pl.select("retry integrity tag")->reserve(128 >> 3);
        pl.read(stream, size, pos);

        pl.select("retry token")->get_variant().to_binary(_retry_token);
        pl.select("retry integrity tag")->get_variant().to_binary(_retry_integrity_tag);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t quic_packet_retry::write(binary_t& packet, uint32 mode) {
    return_t ret = errorcode_t::success;
    ret = quic_packet::write(packet, mode);

    binary_t bin_retry_pseudo_packet;

    if (mode && get_keys()) {
        // RFC 9001 Figure 8: Retry Pseudo-Packet
        const char* key = "0xbe0c690b9f66575a1d766b54e368c84e";
        const char* nonce = "0x461599d35d632bf2239825bb";

        binary_t bin_key = base16_decode_rfc(key);
        binary_t bin_nonce = base16_decode_rfc(nonce);
        binary_t bin_plaintext;
        binary_t bin_encrypted;
        binary_t bin_tag;
        const binary_t& bin_dcid = get_keys()->get_item(quic_original_dcid);

        binary_append(bin_retry_pseudo_packet, (uint8)bin_dcid.size());
        binary_append(bin_retry_pseudo_packet, bin_dcid);

        quic_packet_retry retry;
        retry.attach(get_keys());
        retry.set_scid(get_scid());
        retry.set_retry_token(get_retry_token());
        retry.write(bin_retry_pseudo_packet);

        openssl_crypt crypt;
        crypt_context_t* handle = nullptr;
        crypt.open(&handle, "aes-128-gcm", bin_key, bin_nonce);
        ret = crypt.encrypt2(handle, bin_plaintext, bin_encrypted, &bin_retry_pseudo_packet, &bin_tag);
        if (errorcode_t::success == ret) {
            _retry_integrity_tag = std::move(bin_tag);
        }
        crypt.close(handle);
    }

    payload pl;
    pl << new payload_member(_retry_token, "retry token") << new payload_member(_retry_integrity_tag, "retry integrity tag");
    pl.write(packet);

    return ret;
}

void quic_packet_retry::dump(stream_t* s) {
    if (s) {
        quic_packet::dump(s);

        s->printf(" > retry token\n");
        dump_memory(_retry_token, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
        s->printf(" > retry integrity tag\n");
        dump_memory(_retry_integrity_tag, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
    }
}

quic_packet_retry& quic_packet_retry::set_retry_token(const binary_t& token) {
    _retry_token = token;
    return *this;
}

quic_packet_retry& quic_packet_retry::set_integrity_tag(const binary_t& tag) {
    _retry_integrity_tag = tag;
    return *this;
}

const binary_t& quic_packet_retry::get_retry_token() { return _retry_token; }

const binary_t& quic_packet_retry::get_integrity_tag() { return _retry_integrity_tag; }

}  // namespace net
}  // namespace hotplace
