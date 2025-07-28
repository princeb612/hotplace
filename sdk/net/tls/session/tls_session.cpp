/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/dtls_record_arrange.hpp>
#include <sdk/net/tls/dtls_record_publisher.hpp>
#include <sdk/net/tls/quic_session.hpp>
#include <sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

tls_session::tls_session()
    : _type(session_type_tls), _status(0), _hook_param(nullptr), _dtls_record_publisher(nullptr), _dtls_record_arrange(nullptr), _quic_session(nullptr) {
    _shared.make_share(this);
    _tls_protection.set_session(this);
}

tls_session::tls_session(session_type_t type)
    : _type(type), _status(0), _hook_param(nullptr), _dtls_record_publisher(nullptr), _dtls_record_arrange(nullptr), _quic_session(nullptr) {
    _shared.make_share(this);
    set_type(type);
}

tls_session::~tls_session() {
    if (_dtls_record_publisher) {
        delete _dtls_record_publisher;
    }
    if (_dtls_record_arrange) {
        delete _dtls_record_arrange;
    }
    if (_quic_session) {
        delete _quic_session;
    }
}

tls_protection& tls_session::get_tls_protection() { return _tls_protection; }

dtls_record_publisher& tls_session::get_dtls_record_publisher() {
    if (nullptr == _dtls_record_publisher) {
        critical_section_guard guard(_dtls_lock);
        if (nullptr == _dtls_record_publisher) {
            _dtls_record_publisher = new dtls_record_publisher;
            _dtls_record_publisher->set_session(this);
        }
    }
    return *_dtls_record_publisher;
}

dtls_record_arrange& tls_session::get_dtls_record_arrange() {
    if (nullptr == _dtls_record_arrange) {
        critical_section_guard guard(_dtls_lock);
        if (nullptr == _dtls_record_arrange) {
            _dtls_record_arrange = new dtls_record_arrange;
            _dtls_record_arrange->set_session(this);
        }
    }
    return *_dtls_record_arrange;
}

void tls_session::set_type(session_type_t type) {
    _type = type;
    _tls_protection.set_session(this);
    if (session_type_quic == type || session_type_quic2 == type) {
        _tls_protection.set_cipher_suite(0x1301);
    }
}

session_type_t tls_session::get_type() { return _type; }

void tls_session::update_session_status(session_status_t status) {
    _status |= status;
    _sem.signal();
    if (_change_status_hook) {
        _change_status_hook(this, status);
    }
#if defined DEBUG
    if (istraceable(trace_category_net, loglevel_debug)) {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        basic_stream dbs;
        dbs.println("\e[1;34msession status %08x (update %08x)\e[0m", _status, status);
        dbs.println("> update status 0x%08x", status);
        tlsadvisor->enum_session_status_string(status, [&](const char* desc) -> void { dbs.println("  %s", desc); });
        dbs.println("> session status 0x%08x", _status);
        tlsadvisor->enum_session_status_string(_status, [&](const char* desc) -> void { dbs.println("  %s", desc); });
        trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
    }
#endif
}

void tls_session::clear_session_status(uint32 status) {
    _status &= ~status;
    _sem.signal();
}

void tls_session::reset_session_status() { _status = 0; }

uint32 tls_session::get_session_status() { return _status; }

return_t tls_session::wait_change_session_status(uint32 status, unsigned msec, bool waitall) {
    return_t ret = errorcode_t::mismatch;

    while (1) {
        ret = _sem.wait(msec);

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

#if defined DEBUG
    if (istraceable(trace_category_net, loglevel_debug)) {
        basic_stream dbs;
        dbs.println("\e[1;34msession status %08x (wait%s %08x) %s\e[0m", _status, waitall ? "all" : "", status,
                    status == (_status & status) ? "true" : "false");
        trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
    }
#endif

    return ret;
}

void tls_session::set_hook_change_session_status(std::function<void(tls_session*, uint32)> func) { _change_status_hook = func; }

void tls_session::set_hook_param(void* param) { _hook_param = param; }

void* tls_session::get_hook_param() { return _hook_param; }

t_key_value<uint16, uint16>& tls_session::get_keyvalue() { return _kv; }

tls_session::session_info& tls_session::get_session_info(tls_direction_t dir) {
    // critical_section_guard guard(_lock);
    return _direction[dir];
}

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

void tls_session::session_info::reset_protection() { _protection = false; }

uint64 tls_session::session_info::get_recordno(bool inc, protection_level_t level) {
    auto& recordno = _recordno_spaces[level];
    return inc ? recordno++ : recordno;
}

void tls_session::session_info::inc_recordno(protection_level_t level) { ++_recordno_spaces[level]; }

void tls_session::session_info::reset_recordno(protection_level_t level) { _recordno_spaces[level] = 0; }

void tls_session::session_info::set_recordno(uint64 recordno, protection_level_t level) { _recordno_spaces[level] = recordno; }

void tls_session::session_info::push_alert(uint8 level, uint8 desc) {
    critical_section_guard guard(_info_lock);
    _alerts.push_back(alert(level, desc));
#if defined DEBUG
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    if (istraceable(trace_category_net)) {
        basic_stream dbs;
        dbs.println("\e[1;31malert level:%s desc:%s\e[0m", tlsadvisor->alert_level_string(level).c_str(), tlsadvisor->alert_desc_string(desc).c_str());
        trace_debug_event(trace_category_net, trace_event_tls_protection, &dbs);
    }
#endif
}

void tls_session::session_info::get_alert(std::function<void(uint8, uint8)> func, uint8 flags) {
    critical_section_guard guard(_info_lock);
    for (auto iter = _alerts.begin(); iter != _alerts.end(); iter++) {
        const auto& item = *iter;
        func(item.level, item.desc);
    }
    if (0 == (session_alert_peek & flags)) {
        _alerts.clear();
    }
}

bool tls_session::session_info::has_alert(uint8 level) {
    bool ret = false;
    critical_section_guard guard(_info_lock);
    for (auto iter = _alerts.begin(); iter != _alerts.end(); iter++) {
        const auto& item = *iter;
        if (item.level == level) {
            ret = true;
            break;
        }
    }
    return ret;
}

secure_prosumer* tls_session::get_secure_prosumer() { return &_prosumer; }

t_key_value<uint8, uint64>& tls_session::session_info::get_keyvalue() { return _kv; }

void tls_session::schedule(tls_handshake* handshake) {
    if (handshake) {
        critical_section_guard guard(_lock);
        handshake->addref();
        _handshake_que.push(handshake);
    }
}

void tls_session::run_scheduled(tls_direction_t dir) {
    critical_section_guard guard(_lock);
    while (false == _handshake_que.empty()) {
        auto handshake = _handshake_que.front();
        handshake->run_scheduled(dir);
        handshake->release();
        _handshake_que.pop();
    }
}

void tls_session::schedule_extension(tls_extension* extension) {
    if (extension) {
        critical_section_guard guard(_lock);
        extension->addref();
        _extension_list.push_back(extension);
    }
}

void tls_session::select_into_scheduled_extension(tls_extensions* extensions) {
    if (extensions) {
        critical_section_guard guard(_lock);
        for (auto ext : _extension_list) {
            extensions->add(ext, true);
            ext->release();
        }
        _extension_list.clear();
    }
}

void tls_session::select_into_scheduled_extension(tls_extensions* extensions, tls_ext_type_t type) {
    if (extensions) {
        critical_section_guard guard(_lock);
        for (auto iter = _extension_list.begin(); iter != _extension_list.end(); iter++) {
            auto ext = *iter;
            if (ext->get_type() == type) {
                extensions->add(ext, true);
                ext->release();

                _extension_list.erase(iter);
                break;
            }
        }
    }
}

void tls_session::push_alert(tls_direction_t dir, uint8 level, uint8 desc) { get_session_info(dir).push_alert(level, desc); }

void tls_session::get_alert(tls_direction_t dir, std::function<void(uint8, uint8)> func, uint8 flags) { get_session_info(dir).get_alert(func, flags); }

bool tls_session::has_alert(tls_direction_t dir, uint8 level) { return get_session_info(dir).has_alert(level); }

quic_session& tls_session::get_quic_session() {
    if (nullptr == _quic_session) {
        critical_section_guard guard(_dtls_lock);
        if (nullptr == _quic_session) {
            _quic_session = new quic_session;
        }
    }
    return *_quic_session;
}

}  // namespace net
}  // namespace hotplace
