/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_record.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_application_data[] = "application data";

tls_application_data::tls_application_data(tls_session* session) : tls_record(tls_content_type_application_data, session) {}

return_t tls_application_data::read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_length();

        {
            auto session = get_session();
            size_t tpos = 0;
            size_t recpos = get_header_range().begin;
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
                            // ret = tls_dump_alert(session, &plaintext[0], plainsize - 1, tpos, debugstream);
                            tls_alert alert(session);
                            alert.read_plaintext(dir, &plaintext[0], plainsize - 1, tpos, debugstream);
                        } else if (tls_content_type_handshake == last_byte) {
                            tpos = 0;
                            while (tpos < plainsize) {
                                auto test = tls_dump_handshake(session, &plaintext[0], plainsize - 1, tpos, debugstream, dir);
                                if (errorcode_t::success != test) {
                                    if (errorcode_t::no_more == test) {
                                        break;
                                    } else {
                                        ret = test;
                                    }
                                }
                            }
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
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_application_data::write(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
