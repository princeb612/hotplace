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

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_session::tls_session() : _type(session_tls), _status(0) { _shared.make_share(this); }

tls_session::tls_session(session_type_t type) : _type(type), _status(0) { _shared.make_share(this); }

tls_protection& tls_session::get_tls_protection() { return _tls_protection; }

void tls_session::set_type(session_type_t type) { _type = type; }

session_type_t tls_session::get_type() { return _type; }

void tls_session::update_session_status(session_status_t status) {
    _status |= status;
    _sem.signal();
    if (_change_status_hook) {
        _change_status_hook(status);
    }
#if defined DEBUG
    if (istraceable()) {
        basic_stream dbs;
        auto tlsadvisor = tls_advisor::get_instance();
        dbs.println("\e[1;34msession status %08x (update %08x)\e[0m", _status, status);
        dbs.println("> update status 0x%08x", status);
        tlsadvisor->enum_session_status_string(status, [&](const char* desc) -> void { dbs.println("  %s", desc); });
        dbs.println("> session status 0x%08x", _status);
        tlsadvisor->enum_session_status_string(_status, [&](const char* desc) -> void { dbs.println("  %s", desc); });
        trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
    }
#endif
}

void tls_session::clear_session_status(session_status_t status) {
    _status &= ~status;
    _sem.signal();
}

uint32 tls_session::get_session_status() { return _status; }

return_t tls_session::wait_change_session_status(uint32 status, unsigned msec, bool waitall) {
    return_t ret = errorcode_t::mismatch;

    while (1) {
        ret = _sem.wait(msec);

#if defined DEBUG
        if (istraceable()) {
            basic_stream dbs;
            dbs.println("\e[1;34msession status %08x (wait%s %08x) %s\e[0m", _status, waitall ? "all" : "", status,
                        status == (_status & status) ? "true" : "false");
            trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
        }
#endif

        if (0 == _status) {
            break;
        }

        auto test = _status & status;
        if (waitall) {
            if (status == test) {
                ret = errorcode_t::success;
                break;
            }
        } else {
            if (test) {
                ret = errorcode_t::success;
                break;
            }
        }

        if (errorcode_t::timeout == ret) {
            break;
        }
    }
    return ret;
}

void tls_session::set_hook_change_session_status(std::function<void(uint32 status)> func) { _change_status_hook = func; }

t_key_value<uint16, uint16>& tls_session::get_conf() { return _kv; }

tls_session::session_info& tls_session::get_session_info(tls_direction_t dir) { return _direction[dir]; }

uint64 tls_session::get_recordno(tls_direction_t dir, bool inc, protection_level_t level) { return get_session_info(dir).get_recordno(inc, level); }

void tls_session::reset_recordno(tls_direction_t dir, protection_level_t level) {
    auto ver = get_tls_protection().get_tls_version();
    if ((tls_13 == ver) || (dtls_13 == ver)) {
        get_session_info(dir).reset_recordno(level);
    }
}

void tls_session::set_recordno(tls_direction_t dir, uint64 recno, protection_level_t level) { get_session_info(dir).set_recordno(recno, level); }

void tls_session::addref() { _shared.addref(); }

void tls_session::release() { _shared.delref(); }

tls_session::session_info::session_info() : _hstype(tls_hs_client_hello), _protection(false) {}

void tls_session::session_info::set_status(tls_hs_type_t type) { _hstype = type; }

tls_hs_type_t tls_session::session_info::get_status() { return _hstype; }

void tls_session::session_info::begin_protection() { _protection = true; }

bool tls_session::session_info::apply_protection() { return _protection; }

uint64 tls_session::session_info::get_recordno(bool inc, protection_level_t level) {
    auto& recordno = _recordno_spaces[level];
    return inc ? recordno++ : recordno;
}

void tls_session::session_info::inc_recordno(protection_level_t level) { ++_recordno_spaces[level]; }

void tls_session::session_info::reset_recordno(protection_level_t level) { _recordno_spaces[level] = 0; }

void tls_session::session_info::set_recordno(uint64 recordno, protection_level_t level) { _recordno_spaces[level] = recordno; }

void tls_session::session_info::push_alert(uint8 level, uint8 desc) {
    critical_section_guard guard(_alerts_lock);
    _alerts.push_back(alert(level, desc));
}

void tls_session::session_info::get_alert(std::function<void(uint8, uint8)> func) {
    critical_section_guard guard(_alerts_lock);
    for (auto iter = _alerts.begin(); iter != _alerts.end(); iter++) {
        const auto& item = *iter;
        func(item.level, item.desc);
    }
    _alerts.clear();
}

void tls_session::schedule(tls_handshake* handshake) {
    if (handshake) {
        critical_section_guard guard(_lock);
        handshake->addref();
        _que.push(handshake);
    }
}

void tls_session::run_scheduled(tls_direction_t dir) {
    critical_section_guard guard(_lock);
    while (false == _que.empty()) {
        auto handshake = _que.front();
        handshake->run_scheduled(dir);
        handshake->release();
        _que.pop();
    }
}

void tls_session::push_alert(tls_direction_t dir, uint8 level, uint8 desc) { get_session_info(dir).push_alert(level, desc); }

void tls_session::get_alert(tls_direction_t dir, std::function<void(uint8, uint8)> func) { get_session_info(dir).get_alert(func); }

}  // namespace net
}  // namespace hotplace
