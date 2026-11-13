/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_record_application_data.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "content type";
constexpr char constexpr_legacy_version[] = "legacy record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_key_epoch[] = "key epoch";
constexpr char constexpr_dtls_record_seq[] = "dtls record sequence number";
constexpr size_t tls_handshake_header_size = 4;

static return_t validate_tls13_finished_message_order(const byte_t* stream, size_t size) {
    if (nullptr == stream) {
        return errorcode_t::invalid_parameter;
    }

    size_t cursor = 0;
    bool finished_seen = false;
    while (cursor < size) {
        if (size - cursor < tls_handshake_header_size) {
            return errorcode_t::bad_data;
        }

        auto type = (tls_handshake_type_t)stream[cursor];
        uint32 message_size = ((uint32)stream[cursor + 1] << 16) | ((uint32)stream[cursor + 2] << 8) | (uint32)stream[cursor + 3];
        if (message_size > size - cursor - tls_handshake_header_size) {
            return errorcode_t::bad_data;
        }
        if (finished_seen) {
            return errorcode_t::unexpected;
        }

        finished_seen = (tls_handshake_type_t::finished == type);
        cursor += tls_handshake_header_size + message_size;
    }

    return errorcode_t::success;
}

tls_record_application_data::tls_record_application_data(tls_session* session) : tls_record(tls_content_type_t::application_data, session) {}

tls_record_application_data::tls_record_application_data(tls_session* session, const std::string& data) : tls_record(tls_content_type_t::application_data, session) {
    binary_append(_bin, data);
}

tls_record_application_data::tls_record_application_data(tls_session* session, const binary_t& data) : tls_record(tls_content_type_t::application_data, session) {
    _bin = data;
}

tls_record_application_data::tls_record_application_data(tls_session* session, const byte_t* data, size_t size)
    : tls_record(tls_content_type_t::application_data, session) {
    binary_append(_bin, data, size);
}

tls_record_application_data::~tls_record_application_data() {}

tls_handshakes& tls_record_application_data::get_handshakes() { return _handshakes; }

tls_records& tls_record_application_data::get_records() { return _records; }

void tls_record_application_data::set_binary(const binary_t bin) { _bin = bin; }

void tls_record_application_data::set_binary(const byte_t* data, size_t size) {
    _bin.clear();
    binary_append(_bin, data, size);
}

const binary_t& tls_record_application_data::get_binary() const { return _bin; }

return_t tls_record_application_data::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto flow = protection.get_flow();
    auto session_status = session->get_session_status();
    uint32 session_status_prerequisite = 0;

    if (tls_flow_t::one_rtt == flow) {
        if (protection.is_kindof_tls13()) {
            session_status_prerequisite = session_status_server_hello;
        } else {
            session_status_prerequisite = session_status_server_finished;
        }
    } else if (tls_flow_t::zero_rtt == flow) {
        // RTF 8448 RFC 8448 4.  Resumed 0-RTT Handshake
        session_status_prerequisite = session_status_client_hello;
    }
    if (0 == (session_status_prerequisite & session_status)) {
        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
        session->reset_session_status();
        ret = errorcode_t::handshake_failure;
    }
    return ret;
}

return_t tls_record_application_data::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        tls_protection& protection = session->get_tls_protection();

        // uint16 len = get_body_size();
        size_t tpos = 0;
        size_t recpos = offsetof_header();
        binary_t plaintext;

        /**
         * RFC 8446 Application Data MUST NOT be sent prior to sending the Finished message
         *
         * understanding TLS 1.3
         *   server_hello
         *   change_cipher_spec (optional)
         *   application_data (handshake) // it's handshake (just encapsulated)
         *   finished
         *   application_data (application_data) // it's applicaton data
         *
         * encryption
         *   TLS 1.3
         *     handshake (server_hello)
         *       -> tls_secret_t::handshake_(client|server)_key
         *     application_data (handshake)
         *     handshake (finished)
         *       -> tls_secret_t::application_(client|server)_key
         *     application_data (application_data)
         *   TLS 1.2
         *     client_key_exchange
         *       -> tls_secret_t::(client|server)_key, tls_secret_t::(client|server)_mac_key
         *     handshake (finished)
         *     application_data (application_data)
         */

        auto limit = recpos + get_record_size();
        ret = protection.decrypt(session, dir, stream, limit, recpos, plaintext);
        if (errorcode_t::success == ret) {
            auto plainsize = plaintext.size();
            ret = validate_record_size_limit(dir, plainsize);
            if (errorcode_t::success != ret) {
                __leave2;
            }
            if (protection.is_kindof_tls13()) {
                // RFC 9846 5.2 / 5.4: TLSInnerPlaintext is content || type || zero padding.
                // The generic decrypt path has already enforced its 2^14+1 size limit.
                // Scan only the AEAD-decrypted plaintext and locate the last non-zero octet.
                size_t content_type_pos = plainsize;
                while (content_type_pos && (0 == plaintext[content_type_pos - 1])) {
                    --content_type_pos;
                }

                if (0 == content_type_pos) {
                    // An empty/all-zero TLSInnerPlaintext has no content type.
                    ret = errorcode_t::unexpected;
                    session->reset_session_status();
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                    __leave2;
                }

                uint8 type = plaintext[content_type_pos - 1];
                size_t content_size = content_type_pos - 1;
                t_enum_type<tls_content_type_t> ettype(type);
                if (tls_content_type_t::alert == ettype) {
                    // RFC 9846 5.1: an Alert record contains exactly one two-octet Alert message.
                    if (2 != content_size) {
                        ret = errorcode_t::unexpected;
                        session->reset_session_status();
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                        __leave2;
                    }
                    tls_record_alert alert(session);
                    ret = alert.read_plaintext(dir, plaintext.data(), content_size, tpos);
                } else if (tls_content_type_t::handshake == ettype) {
                    // Empty Handshake fragments are forbidden, even when padded.
                    if (0 == content_size) {
                        ret = errorcode_t::unexpected;
                        session->reset_session_status();
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                        __leave2;
                    }
                    ret = validate_tls13_finished_message_order(plaintext.data(), content_size);
                    if (errorcode_t::unexpected == ret) {
                        session->reset_session_status();
                        session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                        __leave2;
                    }
                    if (errorcode_t::success != ret) {
                        __leave2;
                    }
                    ret = get_handshakes().read(session, dir, plaintext.data(), content_size, tpos);
                } else if (tls_content_type_t::application_data == ettype) {
                    auto flow = protection.get_flow();
                    if (tls_flow_t::one_rtt == flow) {
                        // Each endpoint may send application data after its own Finished.
                        // The server does not need to wait for the client's Finished.
                        uint32 session_status_prerequisite = (from_server == dir) ? session_status_server_finished : session_status_client_finished;
                        auto session_status = session->get_session_status();
                        if (0 == (session_status_prerequisite & session_status)) {
                            ret = errorcode_t::unexpected;
                            session->reset_session_status();
                            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                            __leave2;
                        }
                    }

                    // Remove zero padding but retain the content type for get_application_data().
                    plaintext.resize(content_type_pos);
                    ret = get_application_data(plaintext, false);
                } else if (tls_content_type_t::change_cipher_spec == ettype) {
                    // ChangeCipherSpec is not a valid TLSInnerPlaintext content type.
                    ret = errorcode_t::unexpected;
                    session->reset_session_status();
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                    __leave2;
                } else {
                    // RFC 9846 Section 6.2: an invalid enum value is illegal_parameter.
                    ret = errorcode_t::unexpected;
                    session->reset_session_status();
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::illegal_parameter);
                    __leave2;
                }
            } else if (plainsize) {
                // The generic decrypt path enforces the TLS 1.2 2^14 plaintext limit.
                _bin = std::move(plaintext);
            }
#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_net)) {
                trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_record, [&](basic_stream& dbs) -> void {
                    dbs.autoindent(3);
                    dbs.println(" > %s", constexpr_application_data);  // data
                    dump_memory(_bin, &dbs, 16, 3, 0x0, dump_notrunc);
                    dbs.autoindent(0);
                });
            }
#endif
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_record_application_data::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto& handshakes = get_handshakes();
    auto& records = get_records();
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    auto is_tls13 = protection.is_kindof_tls13();
    if (handshakes.size()) {
        if (is_tls13) {
            bool finished_seen = false;
            for (size_t i = 0; i < handshakes.size(); ++i) {
                auto handshake = handshakes.getat(i);
                auto type = handshake ? handshake->get_type() : tls_handshake_type_t{};
                if (finished_seen) {
                    ret = errorcode_t::unexpected;
                    break;
                }
                finished_seen = (tls_handshake_type_t::finished == type);
            }
            if (errorcode_t::success != ret) {
                return ret;
            }
        }
        ret = handshakes.write(get_session(), dir, bin);
        if (errorcode_t::success == ret && is_tls13) {
            binary_append(bin, uint8(tls_content_type_t::handshake));
        }
    } else if (records.size()) {
        auto lambda = [&dir, &bin, &ret, &is_tls13](tls_record* record) -> return_t {
            ret = record->do_write_body(dir, bin);
            if ((errorcode_t::success == ret) && is_tls13) {
                binary_append(bin, uint8(record->get_type()));
            }
            return ret;
        };
        ret = records.for_each(lambda);
    } else if (get_binary().size()) {
        // RFC 8446 2.  Protocol Overview
        // Application Data MUST NOT be sent prior to sending the Finished message
        auto session = get_session();
        auto hsstatus = session->get_session_info(dir).get_status();
        if (tls_handshake_type_t::finished == hsstatus) {
            binary_append(bin, _bin);
            if (is_tls13) {
                // TLSInnerPlaintext carries the inner content type after application data.
                binary_append(bin, uint8(tls_content_type_t::application_data));
            }
            _bin.clear();
        }
    }
    return ret;
}

bool tls_record_application_data::apply_protection() const { return true; }

return_t tls_record_application_data::get_application_data(binary_t& message, bool untag) {
    return_t ret = errorcode_t::success;
    // auto& protection = get_session()->get_tls_protection();
    auto lambda = [this](const binary_t& msg, uint8 trail) -> void {
        _bin.clear();
        if (msg.size() > trail) {
            binary_append(_bin, msg.data(), msg.size() - trail);
        }
    };

    if (untag) {
        auto dlen = 0;  // hint_mac->digest_size;
        uint8 last_byte = *message.rbegin();
        size_t extra = last_byte + dlen + 1;
        lambda(message, t_narrow_cast(extra));
    } else {
        lambda(message, 1);
    }
    return ret;
}

void tls_record_application_data::operator<<(tls_record* record) { get_records().add(record); }

void tls_record_application_data::operator<<(tls_handshake* handshake) { get_handshakes().add(handshake); }

tls_record& tls_record_application_data::add(tls_content_type_t type, tls_session* session, std::function<return_t(tls_record*)> func, bool upref) {
    get_records().add(type, session, func, upref);
    return *this;
}

tls_record& tls_record_application_data::add(tls_handshake_type_t type, tls_session* session, std::function<return_t(tls_handshake*)> func, bool upref) {
    get_handshakes().add(type, session, func, upref);
    return *this;
}

}  // namespace net
}  // namespace hotplace
