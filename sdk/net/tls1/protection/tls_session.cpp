/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/handshake/tls_handshake.hpp>
#include <sdk/net/tls1/tls_protection.hpp>
#include <sdk/net/tls1/tls_session.hpp>

namespace hotplace {
namespace net {

tls_session::tls_session() { _shared.make_share(this); }

tls_protection& tls_session::get_tls_protection() { return _tls_protection; }

tls_session::session_info& tls_session::get_session_info(tls_direction_t dir) { return _direction[dir]; }

uint64 tls_session::get_recordno(tls_direction_t dir, bool inc) { return get_session_info(dir).get_recordno(inc); }

void tls_session::reset_recordno(tls_direction_t dir) {
    auto ver = get_tls_protection().get_tls_version();
    if ((tls_13 == ver) || (dtls_13 == ver)) {
        get_session_info(dir).reset_recordno();
    }
}

void tls_session::addref() { _shared.addref(); }

void tls_session::release() { _shared.delref(); }

tls_session::session_info::session_info() : hstype(tls_hs_client_hello), apply_cipher_spec(false), record_no(0) {}

void tls_session::session_info::set_status(tls_hs_type_t type) { hstype = type; }

tls_hs_type_t tls_session::session_info::get_status() { return hstype; }

void tls_session::session_info::change_cipher_spec() { apply_cipher_spec = true; }

bool tls_session::session_info::doprotect() { return apply_cipher_spec; }

uint64 tls_session::session_info::get_recordno(bool inc) { return inc ? record_no++ : record_no; }

void tls_session::session_info::inc_recordno() { ++record_no; }

void tls_session::session_info::reset_recordno() { record_no = 0; }

void tls_session::schedule(tls_handshake* handshake) {
    if (handshake) {
        critical_section_guard guard(_lock);
        handshake->addref();
        _que.push(handshake);
    }
}

void tls_session::carryout_schedule(tls_direction_t dir) {
    critical_section_guard guard(_lock);
    while (false == _que.empty()) {
        auto handshake = _que.front();
        handshake->carryout_schedule(dir);
        handshake->release();
        _que.pop();
    }
}

}  // namespace net
}  // namespace hotplace
