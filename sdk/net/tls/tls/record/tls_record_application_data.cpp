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
            if ((from_client == dir) &&
                ((0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_offered_initial)) ||
                 (0 != session->get_session_info(from_server).get_keyvalue().get(session_early_data_offered))) &&
                (0 == session->get_session_info(from_server).get_keyvalue().get(session_early_data_accepted)) && (0 == (session_status_server_hello & session_status))) {
                // Rejected 0-RTT records can arrive before ServerHello. Allow
                // the trial-decryption path to discard them while no handshake
                // traffic keys are available yet.
                session_status_prerequisite = session_status_client_hello;
            }
        } else {
            session_status_prerequisite = session_status_server_finished;
        }
    } else if (tls_flow_t::zero_rtt == flow) {
        // RFC 8448 4.  Resumed 0-RTT Handshake
        session_status_prerequisite = session_status_client_hello;
    } else if ((tls_flow_t::hello_retry_request == flow) && (from_client == dir)) {
        const auto& early_state = session->get_session_info(from_server).get_keyvalue();
        if (((0 != early_state.get(session_early_data_offered_initial)) || (0 != early_state.get(session_early_data_offered))) &&
            (0 == early_state.get(session_early_data_accepted))) {
            // RFC 9846 4.3.10: after HRR the server skips any already-in-flight
            // 0-RTT records before processing ClientHello2.
            session_status_prerequisite = session_status_hello_retry_request;
        }
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

        auto& early_state = session->get_session_info(from_server).get_keyvalue();
        auto discard_rejected_early_data = [&]() -> return_t {
            constexpr uint64 max_tls13_ciphertext_record_size = (1u << 14) + 256;
            constexpr uint64 max_rejected_early_data_records = 64;
            constexpr uint64 max_rejected_early_data_ciphertext = max_tls13_ciphertext_record_size * max_rejected_early_data_records;
            uint64 discarded = early_state.get(session_early_data_discarded);
            uint64 discard_limit = early_state.get(session_early_data_discard_limit);
            uint64 discarded_records = early_state.get(session_early_data_discarded_records);
            // Count encrypted record fragments, not outer TLS headers. The
            // ticket's max_early_data_size is a plaintext limit, so rejected
            // ciphertext uses a separate byte budget plus record-count ceiling.
            uint64 ciphertext_size = get_body_size();
            if ((0 == discard_limit) || (discarded_records >= max_rejected_early_data_records) || (0 == ciphertext_size) ||
                (ciphertext_size > max_tls13_ciphertext_record_size) || (discarded > max_rejected_early_data_ciphertext) ||
                (ciphertext_size > max_rejected_early_data_ciphertext - discarded)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                session->reset_session_status();
                return errorcode_t::overflow;
            }
            discard_limit = (discard_limit > max_rejected_early_data_ciphertext) ? max_rejected_early_data_ciphertext : discard_limit;
            if ((discarded > discard_limit) || (ciphertext_size > discard_limit - discarded)) {
                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                session->reset_session_status();
                return errorcode_t::overflow;
            }
            early_state.set(session_early_data_discarded, discarded + ciphertext_size);
            early_state.set(session_early_data_discarded_records, discarded_records + 1);
            _bin.clear();
            return errorcode_t::success;
        };

        bool trial_decrypt_rejected_early_data = false;
        if (protection.is_kindof_tls13() && (from_client == dir) &&
            ((0 != early_state.get(session_early_data_offered_initial)) || (0 != early_state.get(session_early_data_offered))) &&
            (0 == early_state.get(session_early_data_accepted))) {
            auto flow = protection.get_flow();
            uint16 selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
            uint64 early_data_limit = early_state.get(session_early_data_limit);
            uint32 session_status = session->get_session_status();
            bool client_finished = (0 != (session_status_client_finished & session_status));

            if (tls_flow_t::hello_retry_request == flow) {
                // RFC 9846 4.3.10: HRR rejects 0-RTT; skip in-flight records
                // with an external application_data content type.
                ret = discard_rejected_early_data();
                if (errorcode_t::success == ret) {
                    __leave2;
                }
                __leave2_trace(ret);
            }
            if ((tls_flow_t::zero_rtt == flow) && ((0 != selected_identity) || (0 == early_data_limit))) {
                // The server did not select identity zero or the ticket did
                // not permit early data. These records cannot be authenticated
                // with the selected PSK's early traffic secret.
                ret = discard_rejected_early_data();
                if (errorcode_t::success == ret) {
                    __leave2;
                }
                __leave2_trace(ret);
            }
            if ((tls_flow_t::one_rtt == flow) && (false == client_finished)) {
                // RFC 9846 4.3.10: after rejecting 0-RTT, trial-decrypt with
                // handshake traffic keys. Failed records are discarded; the
                // first successful record begins the client's second flight.
                trial_decrypt_rejected_early_data = true;
            }
        }

        auto limit = recpos + get_record_size();
        if (trial_decrypt_rejected_early_data) {
            uint64 record_no = session->get_session_info(dir).get_recordno(false);
            ret = protection.decrypt_aead(session, dir, stream, limit, recpos, plaintext, protection_space_t::tls, decrypt_alert_policy_t::suppress);
            if (errorcode_t::verification_failure == ret) {
                // Only an authentication failure identifies a late 0-RTT
                // record. Restore the sequence number before discarding it.
                session->get_session_info(dir).set_recordno(record_no);
                ret = discard_rejected_early_data();
                if (errorcode_t::success == ret) {
                    __leave2;
                }
                __leave2_trace(ret);
            }
            if ((errorcode_t::success != ret) && (errorcode_t::overflow != ret)) {
                // Do not disguise malformed input or local crypto failures as
                // rejected early data.
                session->get_session_info(dir).set_recordno(record_no);
                __leave2_trace(ret);
            }
        } else {
            ret = protection.decrypt(session, dir, stream, limit, recpos, plaintext);
        }
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
                    if ((tls_flow_t::zero_rtt == flow) && (from_client == dir)) {
                        auto& early_state = session->get_session_info(from_server).get_keyvalue();
                        if (0 == early_state.get(session_early_data_finished)) {
                            // Before EndOfEarlyData, client application_data
                            // records remain 0-RTT and are subject to the ticket limit.
                            auto selected_identity = t_narrow_cast(session->get_keyvalue().get(session_server_psk_selected_identity));
                            uint64 early_data_limit = early_state.get(session_early_data_limit);
                            bool early_data_accepted = (0 != early_state.get(session_early_data_offered)) && (0 != early_state.get(session_early_data_accepted)) &&
                                                       (0 == static_cast<uint16>(selected_identity)) && (0 != early_data_limit);
                            if ((false == early_data_accepted)) {
                                ret = discard_rejected_early_data();
                                if (errorcode_t::success == ret) {
                                    __leave2;
                                }
                                __leave2_trace(ret);
                            }

                            uint64 early_data_received = early_state.get(session_early_data_received);
                            if ((early_data_received > early_data_limit) || (content_size > early_data_limit - early_data_received)) {
                                ret = errorcode_t::overflow;
                                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                                session->reset_session_status();
                                __leave2;
                            }
                            early_state.set(session_early_data_received, early_data_received + content_size);
                        } else {
                            // After the client early-data phase, only 1-RTT
                            // application data is legal, and only after the
                            // client's Finished has been processed.
                            uint32 session_status = session->get_session_status();
                            if (0 == (session_status_client_finished & session_status)) {
                                ret = errorcode_t::unexpected;
                                session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                                session->reset_session_status();
                                __leave2;
                            }
                        }
                    } else if ((tls_flow_t::zero_rtt == flow) && (from_server == dir)) {
                        // The server cannot send 0-RTT data, but it may send 1-RTT
                        // application data after its own Finished while the client
                        // is still completing the resumed handshake.
                        uint32 session_status = session->get_session_status();
                        if (0 == (session_status_server_finished & session_status)) {
                            ret = errorcode_t::unexpected;
                            session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                            session->reset_session_status();
                            __leave2;
                        }
                    }
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
        auto session = get_session();
        auto hsstatus = session->get_session_info(dir).get_status();
        auto flow = protection.get_flow();
        if (is_tls13 && (from_client == dir) && (tls_flow_t::zero_rtt == flow)) {
            // Client 0-RTT application data is protected with the early traffic
            // secret and is bounded by identity zero's NewSessionTicket limit.
            auto& early_state = session->get_session_info(from_server).get_keyvalue();
            uint64 early_data_limit = early_state.get(session_early_data_limit);
            uint64 early_data_sent = early_state.get(session_early_data_sent);
            bool can_send_early_data = (0 != early_state.get(session_early_data_offered)) && (0 != early_data_limit) && (tls_handshake_type_t::client_hello == hsstatus);
            if ((false == can_send_early_data)) {
                ret = errorcode_t::bad_request;
            } else if ((early_data_sent > early_data_limit) || (_bin.size() > early_data_limit - early_data_sent)) {
                ret = errorcode_t::overflow;
            } else {
                binary_append(bin, _bin);
                binary_append(bin, uint8(tls_content_type_t::application_data));
                early_state.set(session_early_data_sent, early_data_sent + _bin.size());
                _bin.clear();
            }
        } else if (tls_handshake_type_t::finished == hsstatus) {
            // Ordinary application data is not sent until this endpoint has
            // sent Finished.
            binary_append(bin, _bin);
            if (is_tls13) {
                // TLSInnerPlaintext carries the inner content type after application data.
                binary_append(bin, uint8(tls_content_type_t::application_data));
            }
            _bin.clear();
        } else if (is_tls13) {
            // Do not silently consume application data when 0-RTT was
            // rejected or the endpoint has not sent Finished yet.
            ret = errorcode_t::bad_request;
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
