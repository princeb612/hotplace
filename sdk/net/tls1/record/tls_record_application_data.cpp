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
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/tls1/record/tls_record_alert.hpp>
#include <sdk/net/tls1/record/tls_record_application_data.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_protection.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "content type";
constexpr char constexpr_legacy_version[] = "legacy record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_key_epoch[] = "key epoch";
constexpr char constexpr_dtls_record_seq[] = "dtls record sequence number";

tls_record_application_data::tls_record_application_data(tls_session* session) : tls_record(tls_content_type_application_data, session) {}

tls_handshakes& tls_record_application_data::get_handshakes() { return _handshakes; }

return_t tls_record_application_data::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        binary_t aad;
        auto& protection = session->get_tls_protection();
        auto legacy_version = protection.get_record_version();
        auto tagsize = protection.get_tag_size();

        {
            payload pl;
            pl << new payload_member(uint8(get_type()), constexpr_content_type)                                         // tls, dtls
               << new payload_member(uint16(legacy_version), true, constexpr_legacy_version)                            // tls, dtls
               << new payload_member(uint16(get_key_epoch()), true, constexpr_key_epoch, constexpr_group_dtls)          // dtls
               << new payload_member(binary_t(get_dtls_record_seq()), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(body.size() + tagsize), true, constexpr_len);                               // tls, dtls

            pl.set_group(constexpr_group_dtls, is_kindof_dtls(_legacy_version));
            pl.write(aad);
        }

        binary_t ciphertext;
        binary_t tag;
        auto tlsversion = protection.get_tls_version();
        if (is_basedon_tls13(tlsversion)) {
            ret = protection.encrypt_tls13(session, dir, body, ciphertext, aad, tag, debugstream);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            binary_append(ciphertext, tag);
            tls_record::do_write_header(dir, bin, ciphertext, debugstream);

        } else {
            // ret = protection.decrypt_tls1(session, dir, stream, pos + len, recpos, plaintext, debugstream);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_record_application_data::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_body_size();

        auto session = get_session();
        size_t tpos = 0;
        size_t recpos = offsetof_header();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        tls_protection& protection = session->get_tls_protection();
        binary_t plaintext;
        binary_t tag;
        auto tlsversion = protection.get_tls_version();
        if (is_basedon_tls13(tlsversion)) {
            ret = protection.decrypt_tls13(session, dir, stream, len, recpos, plaintext, tag, debugstream);
        } else {
            ret = protection.decrypt_tls1(session, dir, stream, pos + len, recpos, plaintext, debugstream);
        }
        if (errorcode_t::success == ret) {
            auto plainsize = plaintext.size();
            if (plainsize) {
                auto tlsversion = protection.get_tls_version();
                uint8 last_byte = *plaintext.rbegin();
                if (is_basedon_tls13(tlsversion)) {
                    if (tls_content_type_alert == last_byte) {
                        tls_record_alert alert(session);
                        alert.read_plaintext(dir, &plaintext[0], plainsize - 1, tpos, debugstream);
                    } else if (tls_content_type_handshake == last_byte) {
                        ret = get_handshakes().read(session, dir, &plaintext[0], plainsize - 1, tpos, debugstream);
                    } else if (tls_content_type_application_data == last_byte) {
                        if (debugstream) {
                            debugstream->autoindent(3);
                            debugstream->printf("> %s\n", constexpr_application_data);
                            dump_memory(&plaintext[0], plainsize - 1, debugstream, 16, 3, 0x0, dump_notrunc);
                            debugstream->autoindent(0);
                        }
                    }
                } else {
                    crypto_advisor* advisor = crypto_advisor::get_instance();
                    const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
                    const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
                    auto dlen = hint_mac->digest_size;
                    size_t extra = last_byte + dlen + 1;
                    if (plaintext.size() > extra) {
                        if (debugstream) {
                            debugstream->autoindent(3);
                            debugstream->printf(" > %s\n", constexpr_application_data);  // data
                            dump_memory(&plaintext[0], plaintext.size() - extra, debugstream, 16, 3, 0x0, dump_notrunc);
                            debugstream->autoindent(0);
                        }
                    }
                }
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record_application_data::do_write_body(tls_direction_t dir, binary_t& bin, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    get_handshakes().write(get_session(), dir, bin, debugstream);
    binary_append(bin, uint8(tls_content_type_handshake));
    return ret;
}

}  // namespace net
}  // namespace hotplace
