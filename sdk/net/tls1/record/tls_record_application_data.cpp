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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/openssl_prng.hpp>
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

tls_record_application_data::tls_record_application_data(tls_session* session, const std::string& data)
    : tls_record(tls_content_type_application_data, session) {
    binary_append(_bin, data);
}

tls_record_application_data::tls_record_application_data(tls_session* session, const binary_t& data) : tls_record(tls_content_type_application_data, session) {
    _bin = data;
}

tls_handshakes& tls_record_application_data::get_handshakes() { return _handshakes; }

tls_records& tls_record_application_data::get_records() { return _records; }

void tls_record_application_data::set_binary(const binary_t bin) { _bin = bin; }

const binary_t& tls_record_application_data::get_binary() { return _bin; }

return_t tls_record_application_data::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_body_size();

        auto session = get_session();
        size_t tpos = 0;
        size_t recpos = offsetof_header();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();

        tls_protection& protection = session->get_tls_protection();
        binary_t plaintext;

        // tls_advisor *tlsadvisor = tls_advisor::get_instance();
        auto cs = protection.get_cipher_suite();
        const tls_cipher_suite_t* hint = tlsadvisor->hintof_cipher_suite(cs);
        auto declen = (cbc == hint->mode) ? pos + len : len;
        ret = protection.decrypt(session, dir, stream, declen, recpos, plaintext);
        if (errorcode_t::success == ret) {
            auto plainsize = plaintext.size();
            if (plainsize) {
                auto tlsversion = protection.get_tls_version();
                uint8 last_byte = *plaintext.rbegin();
                if (tls_content_type_alert == last_byte) {
                    tls_record_alert alert(session);
                    alert.read_plaintext(dir, &plaintext[0], plainsize - 1, tpos);
                } else if (tls_content_type_handshake == last_byte) {
                    ret = get_handshakes().read(session, dir, &plaintext[0], plainsize - 1, tpos);
                } else if (tls_content_type_application_data == last_byte) {
                    if (cbc == hint->mode) {
                        ret = get_application_data(plaintext, true);
                    } else {
                        ret = get_application_data(plaintext, false);
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

return_t tls_record_application_data::do_write_header(tls_direction_t dir, binary_t& bin, const binary_t& body) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        binary_t additional;
        binary_t ciphertext;
        binary_t tag;

        auto& protection = session->get_tls_protection();
        auto legacy_version = protection.get_record_version();
        auto tagsize = protection.get_tag_size();
        auto tlsversion = protection.get_tls_version();
        auto cs = protection.get_cipher_suite();
        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        const tls_cipher_suite_t* hint = tlsadvisor->hintof_cipher_suite(cs);
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
        uint16 len = (cbc == hint->mode) ? body.size() + tagsize + ivsize : body.size() + tagsize;

        {
            payload pl;
            pl << new payload_member(uint8(get_type()), constexpr_content_type)                                         // tls, dtls
               << new payload_member(uint16(legacy_version), true, constexpr_legacy_version)                            // tls, dtls
               << new payload_member(uint16(get_key_epoch()), true, constexpr_key_epoch, constexpr_group_dtls)          // dtls
               << new payload_member(binary_t(get_dtls_record_seq()), constexpr_dtls_record_seq, constexpr_group_dtls)  // dtls
               << new payload_member(uint16(len), true, constexpr_len);                                                 // tls, dtls

            pl.set_group(constexpr_group_dtls, is_kindof_dtls(_legacy_version));
            pl.write(additional);
        }

        if (cbc == hint->mode) {
            // additional = content header + iv
            binary_t iv;
            openssl_prng prng;
            prng.random(iv, ivsize);
            binary_append(additional, iv);

            binary_t encbody;
            ret = protection.encrypt(session, dir, body, encbody, additional, tag);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            binary_append(ciphertext, iv);
            binary_append(ciphertext, encbody);
        } else {
            // additional = content header as AAD
            ret = protection.encrypt(session, dir, body, ciphertext, additional, tag);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            binary_append(ciphertext, tag);
        }

        // content header + ciphertext
        tls_record::do_write_header(dir, bin, ciphertext);
    }
    __finally2 {}
    return ret;
}

return_t tls_record_application_data::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto& handshakes = get_handshakes();
    auto& records = get_records();
    if (handshakes.size()) {
        handshakes.write(get_session(), dir, bin);
        binary_append(bin, uint8(tls_content_type_handshake));
    } else if (records.size()) {
        auto lambda = [&](tls_record* record) -> void {
            record->do_write_body(dir, bin);
            binary_append(bin, uint8(record->get_type()));
        };
        records.for_each(lambda);
    } else if (get_binary().size()) {
        binary_append(bin, _bin);
        _bin.clear();
    }
    return ret;
}

return_t tls_record_application_data::get_application_data(binary_t& message, bool untag) {
    return_t ret = errorcode_t::success;
    auto& protection = get_session()->get_tls_protection();
    auto lambda = [&](const binary_t& msg, uint8 trail) -> void {
        if (msg.size() > trail) {
            if (istraceable()) {
                basic_stream dbs;
                dbs.autoindent(3);
                dbs.printf(" > %s\n", constexpr_application_data);  // data
                dump_memory(&msg[0], msg.size() - trail, &dbs, 16, 3, 0x0, dump_notrunc);
                dbs.autoindent(0);

                trace_debug_event(category_tls1, tls_event_read, &dbs);
            }
        }
    };

    if (untag) {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        const tls_cipher_suite_t* hint_tls_alg = tlsadvisor->hintof_cipher_suite(protection.get_cipher_suite());
        const hint_digest_t* hint_mac = advisor->hintof_digest(hint_tls_alg->mac);
        auto dlen = 0;  // hint_mac->digest_size;
        uint8 last_byte = *message.rbegin();
        size_t extra = last_byte + dlen + 1;
        lambda(message, extra);
    } else {
        lambda(message, 1);
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
