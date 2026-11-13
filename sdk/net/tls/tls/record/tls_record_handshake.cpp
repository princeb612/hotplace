/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_record_handshake.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_content_type[] = "record content type";
constexpr char constexpr_legacy_version[] = "legacy record version";
constexpr char constexpr_len[] = "len";
constexpr char constexpr_application_data[] = "application data";

constexpr char constexpr_group_dtls[] = "dtls";
constexpr char constexpr_key_epoch[] = "key epoch";
constexpr char constexpr_dtls_record_seq[] = "dtls record sequence number";
constexpr size_t tls_handshake_header_size = 4;

static bool tls13_plaintext_handshake_type_allowed(tls_handshake_type_t type) {
    return (tls_handshake_type_t::client_hello == type) || (tls_handshake_type_t::server_hello == type);
}

static bool tls13_plaintext_handshake_phase_allowed(tls_session* session, tls_direction_t dir, tls_handshake_type_t type) {
    if (nullptr == session) {
        return false;
    }

    auto& protection = session->get_tls_protection();
    auto session_status = session->get_session_status();
    auto client_status = session->get_session_info(from_client).get_status();
    auto server_status = session->get_session_info(from_server).get_status();

    if ((tls_handshake_type_t::client_hello == type) && (from_client == dir)) {
        bool initial_client_hello = (0 == (session_status & session_status_client_hello)) && (tls_handshake_type_t::client_hello == client_status) &&
                                    (tls_handshake_type_t::client_hello == server_status);
        bool resumed_client_hello = (session_status_server_finished & session_status) && (session_status_client_finished & session_status);
        bool retry_client_hello = (tls_flow_t::hello_retry_request == protection.get_flow()) && (0 == (session_status & session_status_client_hello)) &&
                                  (tls_handshake_type_t::server_hello == client_status) && (tls_handshake_type_t::server_hello == server_status);

        return initial_client_hello || resumed_client_hello || retry_client_hello;
    }

    if ((tls_handshake_type_t::server_hello == type) && (from_server == dir)) {
        return (0 != (session_status & session_status_client_hello)) && (tls_handshake_type_t::client_hello == client_status);
    }

    return false;
}

tls_record_handshake::tls_record_handshake(tls_session* session) : tls_record(tls_content_type_t::handshake, session) {}

tls_record_handshake::~tls_record_handshake() {}

tls_handshakes& tls_record_handshake::get_handshakes() { return _handshakes; }

return_t tls_record_handshake::do_preprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    auto session = get_session();
    auto& protection = session->get_tls_protection();
    // TLS 1.3 plaintext Handshake records are phase-checked in the body read/write
    // paths, once their message types are available. Keep directional protection
    // active until the actual message type is known.
    if (protection.is_kindof_tls13() && (session_type_t::tls != session->get_type())) {
        session->get_session_info(dir).reset_protection();
    }
    return ret;
}

return_t tls_record_handshake::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_body_size();

        auto session = get_session();
        size_t tpos = 0;
        size_t recpos = offsetof_header();
        // tls_advisor* tlsadvisor = tls_advisor::get_instance();

        auto& protection_state = session->get_session_info(dir);
        auto& protection = session->get_tls_protection();
        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls13()) {
            // TLS 1.3 permits only ClientHello and ServerHello in plaintext Handshake
            // records. Protected Handshake records are decrypted by the regular
            // record-protection path below.
            if ((len < tls_handshake_header_size) || (pos > size) || (size - pos < len)) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            size_t cursor = pos;
            size_t end = pos + len;
            bool has_handshake = false;
            while (cursor < end) {
                if (end - cursor < tls_handshake_header_size) {
                    ret = errorcode_t::bad_data;
                    break;
                }
                auto type = (tls_handshake_type_t)stream[cursor];
                uint32 message_size = ((uint32)stream[cursor + 1] << 16) | ((uint32)stream[cursor + 2] << 8) | (uint32)stream[cursor + 3];
                auto type_allowed = tls13_plaintext_handshake_type_allowed(type);
                auto phase_allowed = tls13_plaintext_handshake_phase_allowed(session, dir, type);
                if ((false == type_allowed) || (message_size > end - cursor - tls_handshake_header_size) || (false == phase_allowed)) {
                    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::unexpected_message);
                    session->reset_session_status();
                    ret = errorcode_t::unexpected;
                    break;
                }
                cursor += tls_handshake_header_size + message_size;
                has_handshake = true;
            }
            if (errorcode_t::success != ret) {
                __leave2;
            }
            if (false == has_handshake) {
                ret = errorcode_t::bad_data;
                __leave2;
            }

            // Clear protection only while parsing permitted plaintext messages.
            // Restore it if the existing handshake state machine rejects one.
            bool was_protected = protection_state.apply_protection();
            protection_state.reset_protection();
            ret = get_handshakes().read(session, dir, stream, end, pos);
            if ((errorcode_t::success != ret) && was_protected) {
                protection_state.begin_protection();
            }
        } else if (protection_state.apply_protection()) {
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

            auto limit = recpos + get_record_size();
            ret = protection.decrypt(session, dir, stream, limit, recpos, plaintext);
            if (errorcode_t::success == ret) {
                ret = validate_record_size_limit(dir, plaintext.size());
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                tpos = 0;
                auto handshake = tls_handshake::read(session, dir, plaintext.data(), plaintext.size(), tpos);
                get_handshakes().add(handshake);
            }
        } else {
            // record-handshake 1..*
            ret = get_handshakes().read(session, dir, stream, pos + len, pos);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_record_handshake::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        auto& handshakes = get_handshakes();
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto& protection_state = session->get_session_info(dir);
        if ((session_type_t::tls == session->get_type()) && protection.is_kindof_tls13()) {
            if (false == protection_state.apply_protection()) {
                // Validate the permitted plaintext message types and their connection
                // phase before serializing.
                for (size_t i = 0; i < handshakes.size(); ++i) {
                    auto handshake = handshakes.getat(i);
                    auto type = handshake ? handshake->get_type() : tls_handshake_type_t{};
                    if ((false == tls13_plaintext_handshake_type_allowed(type)) || (false == tls13_plaintext_handshake_phase_allowed(session, dir, type))) {
                        ret = errorcode_t::unexpected;
                        break;
                    }
                }
                if (errorcode_t::success != ret) {
                    __leave2;
                }
                if (handshakes.size()) {
                    // Serialize first while preserving the current protection state.
                    // Only a successfully serialized ClientHello/ServerHello may switch
                    // the enclosing record to the permitted plaintext form.
                    ret = handshakes.write(session, dir, bin);
                    if (errorcode_t::success == ret) {
                        protection_state.reset_protection();
                    }
                    __leave2;
                }
            } else {
                // ClientHello and ServerHello are plaintext-only TLS 1.3 messages;
                // they must not be emitted inside a protected Handshake record.
                for (size_t i = 0; i < handshakes.size(); ++i) {
                    auto handshake = handshakes.getat(i);
                    auto type = handshake ? handshake->get_type() : tls_handshake_type_t{};
                    if (tls13_plaintext_handshake_type_allowed(type)) {
                        ret = errorcode_t::unexpected;
                        break;
                    }
                }
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            }
        }
        ret = handshakes.write(session, dir, bin);
    }
    __finally2 {}
    return ret;
}

bool tls_record_handshake::apply_protection() const { return true; }

void tls_record_handshake::operator<<(tls_handshake* handshake) { get_handshakes().add(handshake); }

tls_record& tls_record_handshake::add(tls_handshake* handshake) {
    get_handshakes().add(handshake);
    return *this;
}

tls_record& tls_record_handshake::add(tls_handshake_type_t type, tls_session* session, std::function<return_t(tls_handshake*)> func, bool upref) {
    get_handshakes().add(type, session, func, upref);
    return *this;
}

}  // namespace net
}  // namespace hotplace
