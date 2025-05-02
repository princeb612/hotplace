/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "record content type";
constexpr char constexpr_legacy_version[] = "legacy record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_key_epoch[] = "key epoch";
constexpr char constexpr_dtls_record_seq[] = "dtls record sequence number";

tls_record_handshake::tls_record_handshake(tls_session* session) : tls_record(tls_content_type_handshake, session) {}

tls_handshakes& tls_record_handshake::get_handshakes() { return _handshakes; }

return_t tls_record_handshake::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_body_size();

        {
            auto session = get_session();
            size_t tpos = 0;
            size_t recpos = offsetof_header();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();

            if (session->get_session_info(dir).apply_protection()) {
                /**
                 * RFC 2246 6.2.3. Record payload protection
                 *     struct {
                 *         ContentType type;
                 *         ProtocolVersion version;
                 *         uint16 length;
                 *         select (CipherSpec.cipher_type) {
                 *             case stream: GenericStreamCipher;
                 *             case block: GenericBlockCipher;
                 *         } fragment;
                 *     } TLSCiphertext;
                 * RFC 2246 6.2.3.1. Null or standard stream cipher
                 *     stream-ciphered struct {
                 *         opaque content[TLSCompressed.length];
                 *         opaque MAC[CipherSpec.hash_size];
                 *     } GenericStreamCipher;
                 *     HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
                 *                   TLSCompressed.version + TLSCompressed.length +
                 *                   TLSCompressed.fragment));
                 * RFC 2246 6.2.3.2. CBC block cipher
                 *     block-ciphered struct {
                 *         opaque content[TLSCompressed.length];
                 *         opaque MAC[CipherSpec.hash_size];
                 *         uint8 padding[GenericBlockCipher.padding_length];
                 *         uint8 padding_length;
                 *     } GenericBlockCipher;
                 */
                tls_protection& protection = session->get_tls_protection();
                binary_t plaintext;

                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                auto cs = protection.get_cipher_suite();
                const tls_cipher_suite_t* hint = tlsadvisor->hintof_cipher_suite(cs);
                auto declen = (cbc == hint->mode) ? size : len;
                ret = protection.decrypt(session, dir, stream, declen, recpos, plaintext);
                if (errorcode_t::success == ret) {
                    tpos = 0;
                    auto handshake = tls_handshake::read(session, dir, &plaintext[0], plaintext.size(), tpos);
                    get_handshakes().add(handshake);
                }
            } else {
#if 0
                // record-handshake 1..1 (test vector, openssl)
                tpos = pos;
                auto handshake = tls_handshake::read(session, dir, stream, pos + len, tpos);
                get_handshakes().add(handshake);
#else
                // record-handshake 1..*
                get_handshakes().read(session, dir, stream, pos + len, pos);
#endif
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record_handshake::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        auto& handshakes = get_handshakes();
        handshakes.write(get_session(), dir, bin);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

bool tls_record_handshake::apply_protection() { return true; }

void tls_record_handshake::operator<<(tls_handshake* handshake) { get_handshakes().add(handshake); }

}  // namespace net
}  // namespace hotplace
