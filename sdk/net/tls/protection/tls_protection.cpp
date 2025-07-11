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
#include <sdk/base/unittest/trace.hpp>
#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/crypto/basic/transcript_hash.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

// comments
//
// {
//     crypto_advisor::get_instance();
//     \-- linux crash
// }

tls_protection::tls_protection()
    : _session(nullptr), _flow(tls_flow_1rtt), _ciphersuite(0), _version(tls_10), _transcript_hash(nullptr), _use_pre_master_secret(false) {}

tls_protection::~tls_protection() {
    if (_transcript_hash) {
        _transcript_hash->release();
    }
}

tls_flow_t tls_protection::get_flow() { return _flow; }

void tls_protection::set_flow(tls_flow_t flow) { _flow = flow; }

uint16 tls_protection::get_cipher_suite() { return _ciphersuite; }

void tls_protection::set_cipher_suite(uint16 ciphersuite) {
    _ciphersuite = ciphersuite;
    get_protection_context().set_cipher_suite(ciphersuite);
}

uint16 tls_protection::get_lagacy_version() {
    auto type = _session->get_type();
    uint16 version = tls_12;
    switch (type) {
        case session_type_tls:
        case session_type_quic:
        case session_type_quic2:
            version = tls_12;
            break;
        case session_type_dtls:
            version = dtls_12;
            break;
    }
    return version;
}

bool tls_protection::is_kindof_tls() { return (false == tls_advisor::get_instance()->is_kindof_dtls(get_lagacy_version())); }

bool tls_protection::is_kindof_dtls() { return tls_advisor::get_instance()->is_kindof_dtls(get_lagacy_version()); }

bool tls_protection::is_kindof_tls12() { return tls_advisor::get_instance()->is_kindof_tls12(_version); }

bool tls_protection::is_kindof_tls13() { return tls_advisor::get_instance()->is_kindof_tls13(_version); }

uint16 tls_protection::get_tls_version() { return _version; }

void tls_protection::set_tls_version(uint16 version) { _version = version; }

crypto_key &tls_protection::get_keyexchange() { return _keyexchange; }

void tls_protection::use_pre_master_secret(bool use) { _use_pre_master_secret = use; }

bool tls_protection::use_pre_master_secret() { return _use_pre_master_secret; }

t_binary_data<tls_secret_t> &tls_protection::get_secrets() { return _secrets; }

size_t tls_protection::get_header_size() {
    size_t ret_value = 0;
    auto record_version = get_lagacy_version();
    size_t content_header_size = 0;
    tls_advisor *tlsadvisor = tls_advisor::get_instance();
    if (is_kindof_dtls()) {
        content_header_size = RTL_FIELD_SIZE(tls_content_t, dtls);
    } else {
        content_header_size = RTL_FIELD_SIZE(tls_content_t, tls);
    }
    ret_value = content_header_size;
    return ret_value;
}

protection_context &tls_protection::get_protection_context() { return _handshake_context; }

return_t tls_protection::negotiate(tls_session *client_session, tls_session *server_session, uint16 &ciphersuite, uint16 &tlsversion) {
    return_t ret = errorcode_t::success;
    __try2 {
        ciphersuite = 0;
        tlsversion = 0;

        if (nullptr == client_session || nullptr == server_session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto &client_handshake_context = client_session->get_tls_protection().get_protection_context();
        auto &server_handshake_context = server_session->get_tls_protection().get_protection_context();
        server_handshake_context.select_from(client_handshake_context, server_session);
        ciphersuite = server_handshake_context.get0_cipher_suite();
        tlsversion = server_handshake_context.get0_supported_version();
    }
    __finally2 {}
    return ret;
}

void tls_protection::set_session(tls_session *session) {
    if (session) {
        _session = session;
    }
}

}  // namespace net
}  // namespace hotplace
