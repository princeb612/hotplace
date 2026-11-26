/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_protection.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/binary.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/transcript_hash.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_protection::tls_protection()
    : _session(nullptr), _flow(tls_flow_t::one_rtt), _ciphersuite(0), _version(tls1_0), _transcript_hash(nullptr), _use_pre_master_secret(false) {}

tls_protection::~tls_protection() {
    if (_transcript_hash) {
        _transcript_hash->release();
    }
}

tls_flow_t tls_protection::get_flow() { return _flow.load(std::memory_order_acquire); }

void tls_protection::set_flow(tls_flow_t flow) { _flow.store(flow, std::memory_order_release); }

uint16 tls_protection::get_cipher_suite() { return _ciphersuite; }

bool tls_protection::is_kindof_tls1_3_early_data(tls_session* session) {
    if ((nullptr == session) || (session_type_t::tls != session->get_type()) || (tls_flow_t::zero_rtt != get_flow())) {
        return false;
    }

    const tls_resumption_ticket ticket = session->get_early_data_ticket();
    if (ticket.identity.empty() || (ticket.version != static_cast<uint16>(tls1_3)) || (0 == ticket.cipher_suite) || (0 == ticket.max_early_data_size)) {
        return false;
    }

    const auto& early_state = session->get_session_info(from_server).get_keyvalue();
    return (0 != early_state.get(session_early_data_offered_initial)) || (0 != early_state.get(session_early_data_offered));
}

uint16 tls_protection::get_cipher_suite(tls_session* session, tls_direction_t dir) {
    if (is_kindof_tls1_3_early_data(session)) {
        return session->get_early_data_ticket().cipher_suite;
    }
    if (session && is_kindof_tls1_2() && ((session_type_t::tls == session->get_type()) || (session_type_t::dtls == session->get_type()))) {
        uint16 active = session->get_session_info(dir).get_active_cipher_suite();
        if (0 != active) {
            return active;
        }
    }
    return get_cipher_suite();
}

void tls_protection::set_cipher_suite(uint16 ciphersuite) {
    if (_ciphersuite != ciphersuite) {
        // The transcript hash algorithm is selected by the negotiated cipher
        // suite. A provisional PSK suite may be replaced by the HRR-selected
        // suite before the handshake transcript is committed; discard any
        // lazily-created hash state so the next use adopts the new algorithm.
        if (_transcript_hash) {
            _transcript_hash->release();
            _transcript_hash = nullptr;
        }
        _ciphersuite = ciphersuite;
    }
    get_protection_context().set_cipher_suite(ciphersuite);
}

tls_version_t tls_protection::get_lagacy_version() {
    auto type = _session->get_type();
    tls_version_t version = tls_version_t::tls1_2;
    switch (type) {
        case session_type_t::tls:
        case session_type_t::quic:
        case session_type_t::quic2:
            version = tls_version_t::tls1_2;
            break;
        case session_type_t::dtls:
            version = tls_version_t::dtls1_2;
            break;
    }
    return version;
}

bool tls_protection::is_kindof_tls() { return (false == tls_advisor::get_instance()->is_kindof_dtls(get_lagacy_version())); }

bool tls_protection::is_kindof_dtls() { return tls_advisor::get_instance()->is_kindof_dtls(get_lagacy_version()); }

bool tls_protection::is_kindof_tls1_2() { return tls_advisor::get_instance()->is_kindof_tls1_2(_version); }

return_t tls_protection::advance_recordno(tls_session* session, tls_direction_t dir, uint64& record_no, protection_space_t space) {
    if (nullptr == session) {
        return errorcode_t::invalid_parameter;
    }

    record_no = session->get_recordno(dir, space);
    const bool tls12_stream = (session_type_t::tls == session->get_type()) && is_kindof_tls1_2() && (protection_space_t::tls == space);
    if (tls12_stream && (~static_cast<uint64>(0) == record_no)) {
        // Do not increment UINT64_MAX: TLS 1.2 sequence numbers must never wrap.
        // There is no TLS 1.2 KeyUpdate; the caller must terminate this connection.
        auto& session_info = session->get_session_info(dir);
        if (false == session_info.has_alert(tls_alertlevel_t::fatal)) {
            session_info.push_alert(tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
        }
        return errorcode_t::exceed;
    }

    session->inc_recordno(dir, space);
    return errorcode_t::success;
}

bool tls_protection::is_kindof_tls1_3() { return tls_advisor::get_instance()->is_kindof_tls1_3(_version); }

tls_version_t tls_protection::get_tls_version() { return _version; }

void tls_protection::set_tls_version(tls_version_t version) { _version = version; }

crypto_key& tls_protection::get_key() { return _key; }

crypto_keyexchange& tls_protection::get_keyexchange() { return _keyexchange; }

void tls_protection::use_pre_master_secret(bool use) { _use_pre_master_secret = use; }

bool tls_protection::use_pre_master_secret() { return _use_pre_master_secret; }

t_binaries<tls_secret_t>& tls_protection::get_secrets() { return _secrets; }

size_t tls_protection::get_header_size() {
    size_t ret_value = 0;
    size_t content_header_size = 0;
    if (is_kindof_dtls()) {
        content_header_size = RTL_FIELD_SIZE(tls_content_t, dtls);
    } else {
        content_header_size = RTL_FIELD_SIZE(tls_content_t, tls);
    }
    ret_value = content_header_size;
    return ret_value;
}

protection_context& tls_protection::get_protection_context() { return _handshake_context; }

return_t tls_protection::negotiate(tls_session* session, uint16& ciphersuite, tls_version_t& tlsversion) {
    return session->get_tls_protection().get_protection_context().negotiate(session, tls_version_t::tls1_0, tls_version_t::tls1_3, ciphersuite, tlsversion);
}

return_t tls_protection::negotiate(tls_session* session, tls_version_t minspec, tls_version_t maxspec, uint16& ciphersuite, tls_version_t& tlsversion) {
    return session->get_tls_protection().get_protection_context().negotiate(session, minspec, maxspec, ciphersuite, tlsversion);
}

void tls_protection::set_session(tls_session* session) {
    if (session) {
        _session = session;
    }
}

}  // namespace net
}  // namespace hotplace
