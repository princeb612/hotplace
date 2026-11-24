/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_session.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <algorithm>
#include <atomic>
#include <cctype>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/dtls_record_arrange.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_packet_publisher.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>
#include <hotplace/sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

tls_session::tls_session()
    : _type(session_type_t::tls),
      _status(0),
      _hook_param(nullptr),
      _composer(nullptr),
      _dtls_record_publisher(nullptr),
      _dtls_record_arrange(nullptr),
      _quic_session(nullptr) {
    _shared.make_share(this);
    _tls12_ticket_store = std::make_shared<tls12_resumption_ticket_store>();
    _tls_protection.set_session(this);
}

tls_session::tls_session(session_type_t type)
    : _type(type), _status(0), _hook_param(nullptr), _composer(nullptr), _dtls_record_publisher(nullptr), _dtls_record_arrange(nullptr), _quic_session(nullptr) {
    _shared.make_share(this);
    _tls12_ticket_store = std::make_shared<tls12_resumption_ticket_store>();
    set_type(type);
}

tls_session* tls_session::duplicate(tls_session_copy_t type) const {
    switch (type) {
        case tls_session_copy_t::resumption: {
            tls_session* duplicated = new tls_session(_type);
            duplicated->_resumption_tickets = get_resumption_tickets();
            return duplicated;
        }
        default: {
            return nullptr;
        }
    }
}

tls_session::~tls_session() {
    if (_composer) {
        delete _composer;
    }
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

tls_composer* tls_session::get_tls_composer() {
    if (nullptr == _composer) {
        critical_section_guard guard(_dtls_lock);
        if (nullptr == _composer) {
            _composer = new tls_composer(this);
        }
    }
    return _composer;
}

secure_prosumer* tls_session::get_secure_prosumer() { return &_prosumer; }

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

quic_session& tls_session::get_quic_session() {
    if (nullptr == _quic_session) {
        critical_section_guard guard(_dtls_lock);
        if (nullptr == _quic_session) {
            _quic_session = new quic_session;
        }
    }
    return *_quic_session;
}

quic_packet_publisher& tls_session::get_quic_packet_publisher() { return get_quic_session().get_quic_packet_publisher(); }

void tls_session::set_type(session_type_t type) {
    _type = type;
    _tls_protection.set_session(this);
    if (session_type_t::quic == type || session_type_t::quic2 == type) {
        _tls_protection.set_cipher_suite(0x1301);
    }
}

session_type_t tls_session::get_type() const { return _type; }

void tls_session::store_resumption_ticket(const tls_resumption_ticket& ticket) {
    critical_section_guard guard(_lock);
    for (auto it = _resumption_tickets.begin(); it != _resumption_tickets.end(); ++it) {
        if (it->identity == ticket.identity) {
            *it = ticket;
            return;
        }
    }
    _resumption_tickets.emplace_back(ticket);
}

std::vector<tls_resumption_ticket> tls_session::get_resumption_tickets() const {
    critical_section_guard guard(_lock);
    return _resumption_tickets;
}

bool tls_session::find_resumption_ticket(const binary_t& identity, tls_resumption_ticket& ticket) {
    critical_section_guard guard(_lock);
    for (const auto& entry : _resumption_tickets) {
        if (entry.identity == identity) {
            ticket = entry;
            return true;
        }
    }
    return false;
}

void tls_session::remove_resumption_ticket(const binary_t& identity) {
    critical_section_guard guard(_lock);
    for (auto it = _resumption_tickets.begin(); it != _resumption_tickets.end();) {
        if (it->identity == identity) {
            it = _resumption_tickets.erase(it);
        } else {
            ++it;
        }
    }
}

void tls12_resumption_ticket_store::store(const tls12_resumption_ticket& ticket) {
    critical_section_guard guard(_lock);
    for (auto& active : _tickets) {
        if (active.identity == ticket.identity) {
            active = ticket;
            return;
        }
    }
    _tickets.emplace_back(ticket);
}

std::vector<tls12_resumption_ticket> tls12_resumption_ticket_store::get() {
    critical_section_guard guard(_lock);
    return _tickets;
}

bool tls12_resumption_ticket_store::find(const binary_t& identity, tls12_resumption_ticket& ticket) {
    critical_section_guard guard(_lock);
    for (const auto& entry : _tickets) {
        if (entry.identity == identity) {
            ticket = entry;
            return true;
        }
    }
    return false;
}

void tls12_resumption_ticket_store::remove(const binary_t& identity) {
    critical_section_guard guard(_lock);
    for (auto it = _tickets.begin(); it != _tickets.end();) {
        if (it->identity == identity) {
            it = _tickets.erase(it);
        } else {
            ++it;
        }
    }
}

void tls_session::set_tls12_resumption_ticket_store(const std::shared_ptr<tls12_resumption_ticket_store>& store) {
    std::shared_ptr<tls12_resumption_ticket_store> selected = store;
    if (nullptr == selected) {
        selected = std::make_shared<tls12_resumption_ticket_store>();
    }
    critical_section_guard guard(_lock);
    _tls12_ticket_store = selected;
}

void tls_session::stage_tls12_resumption_ticket(const tls12_resumption_ticket& ticket) {
    critical_section_guard guard(_lock);
    for (auto& pending : _pending_tls12_resumption_tickets) {
        if (pending.identity == ticket.identity) {
            pending = ticket;
            return;
        }
    }
    _pending_tls12_resumption_tickets.emplace_back(ticket);
}

bool tls_session::confirm_tls12_resumption_ticket(const binary_t& identity) {
    tls12_resumption_ticket confirmed;
    std::shared_ptr<tls12_resumption_ticket_store> store;
    bool found = false;
    {
        critical_section_guard guard(_lock);
        for (auto it = _pending_tls12_resumption_tickets.begin(); it != _pending_tls12_resumption_tickets.end(); ++it) {
            if (it->identity == identity) {
                confirmed = *it;
                _pending_tls12_resumption_tickets.erase(it);
                store = _tls12_ticket_store;
                found = true;
                break;
            }
        }
    }
    if ((false == found) || (nullptr == store)) {
        return false;
    }
    store->store(confirmed);
    return true;
}

void tls_session::discard_tls12_pending_resumption_ticket(const binary_t& identity) {
    critical_section_guard guard(_lock);
    for (auto it = _pending_tls12_resumption_tickets.begin(); it != _pending_tls12_resumption_tickets.end();) {
        if (it->identity == identity) {
            it = _pending_tls12_resumption_tickets.erase(it);
        } else {
            ++it;
        }
    }
}

void tls_session::discard_all_pending_tls12_resumption_tickets() {
    critical_section_guard guard(_lock);
    _pending_tls12_resumption_tickets.clear();
}

std::vector<tls12_resumption_ticket> tls_session::get_tls12_resumption_tickets() {
    std::shared_ptr<tls12_resumption_ticket_store> store;
    {
        critical_section_guard guard(_lock);
        store = _tls12_ticket_store;
    }
    return store ? store->get() : std::vector<tls12_resumption_ticket>();
}

std::vector<tls12_resumption_ticket> tls_session::get_pending_tls12_resumption_tickets() {
    critical_section_guard guard(_lock);
    return _pending_tls12_resumption_tickets;
}

bool tls_session::find_tls12_resumption_ticket(const binary_t& identity, tls12_resumption_ticket& ticket) {
    std::shared_ptr<tls12_resumption_ticket_store> store;
    {
        critical_section_guard guard(_lock);
        store = _tls12_ticket_store;
    }
    return store ? store->find(identity, ticket) : false;
}

void tls_session::remove_tls12_resumption_ticket(const binary_t& identity) {
    std::shared_ptr<tls12_resumption_ticket_store> store;
    {
        critical_section_guard guard(_lock);
        store = _tls12_ticket_store;
    }
    if (store) {
        store->remove(identity);
    }
}

void tls_session::set_offered_resumption_tickets(const std::vector<tls_resumption_ticket>& tickets) {
    critical_section_guard guard(_lock);
    _offered_resumption_tickets = tickets;
}

std::vector<tls_resumption_ticket> tls_session::get_offered_resumption_tickets() {
    critical_section_guard guard(_lock);
    return _offered_resumption_tickets;
}

void tls_session::set_early_data_ticket(const tls_resumption_ticket& ticket) {
    critical_section_guard guard(_lock);
    _early_data_ticket = ticket;
}

tls_resumption_ticket tls_session::get_early_data_ticket() {
    critical_section_guard guard(_lock);
    return _early_data_ticket;
}

void tls_session::clear_early_data_ticket() {
    critical_section_guard guard(_lock);
    _early_data_ticket = tls_resumption_ticket();
}

void tls_session::set_early_data_discard_limit(uint64 limit) {
    critical_section_guard guard(_lock);
    _early_data_discard_limit = limit;
}

uint64 tls_session::get_early_data_discard_limit() const {
    critical_section_guard guard(_lock);
    return _early_data_discard_limit;
}

void tls_session::set_client_server_name(const binary_t& server_name) {
    binary_t normalized = server_name;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](byte_t value) { return static_cast<byte_t>(std::tolower(value)); });
    critical_section_guard guard(_lock);
    _client_server_name = std::move(normalized);
}

binary_t tls_session::get_client_server_name() {
    critical_section_guard guard(_lock);
    return _client_server_name;
}

return_t tls_session::generate_ticket_nonce(binary_t& nonce) {
    // RFC 8446 requires ticket_nonce to be unique for every ticket issued
    // by a server. The atomic suffix guarantees uniqueness among calls in
    // this process. The fresh random prefix makes collisions across processes
    // and restarts negligibly likely; it is not a shared global allocator.
    binary_t ticket_nonce_prefix;
    return_t ret = crypto::openssl_prng::random(ticket_nonce_prefix, 16);
    if (errorcode_t::success != ret) {
        return ret;
    }

    static std::atomic<uint64> ticket_nonce_counter{0};
    uint64 value = ticket_nonce_counter.load(std::memory_order_relaxed);
    for (;;) {
        if (static_cast<uint64>(-1) == value) {
            return errorcode_t::internal_error;
        }
        if (ticket_nonce_counter.compare_exchange_weak(value, value + 1, std::memory_order_relaxed, std::memory_order_relaxed)) {
            ++value;
            break;
        }
    }

    nonce = ticket_nonce_prefix;
    const size_t offset = nonce.size();
    nonce.resize(offset + sizeof(value));
    for (size_t i = 0; i < sizeof(value); ++i) {
        nonce[offset + i] = static_cast<byte_t>(value >> ((sizeof(value) - i - 1) * 8));
    }
    return errorcode_t::success;
}

void tls_session::update_session_status(session_status_t status) {
    _status |= status;
    _sem.signal();
    if (_change_status_hook) {
        _change_status_hook(this, status);
    }
#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            dbs.println(ANSI_ESCAPE "1;34msession status %08x (update %08x)" ANSI_ESCAPE "0m", _status, status);
            dbs.println("> update status 0x%08x", status);
            tlsadvisor->enum_session_status_string(status, [&](const char* desc) -> void { dbs.println("  %s", desc); });
            dbs.println("> session status 0x%08x", _status);
            tlsadvisor->enum_session_status_string(_status, [&](const char* desc) -> void { dbs.println("  %s", desc); });
        });
    }
#endif
}

void tls_session::clear_session_status(uint32 status) {
    _status &= ~status;
    _sem.signal();
}

void tls_session::reset_session_status() {
    _status = 0;
    _sem.signal();

    // A failed handshake must not carry an unauthenticated TLS 1.2 ticket
    // into a later connection. Keep an already activated ticket untouched.
    auto& secrets = _tls_protection.get_secrets();
    secrets.erase(tls_secret_t::new_session_ticket_pending);
    auto& ticket_state = get_session_info(from_server).get_keyvalue();
    ticket_state.set(session_ticket_pending, 0);
    ticket_state.set(session_ticket_pending_lifetime, 0);
    ticket_state.set(session_ticket_pending_timestamp, 0);

    // Discard only unconfirmed TLS 1.2 server-side ticket state. Previously
    // confirmed tickets and the independent TLS 1.3 PSK cache remain usable.
    discard_all_pending_tls12_resumption_tickets();

    // A fatal alert terminates the current connection. Reset the TLS flow as
    // well as the directional handshake cursors, so a replayed/new connection
    // cannot inherit the previous connection's HelloRetryRequest state.
    if (tls_flow_t::hello_retry_request == _tls_protection.get_flow()) {
        _tls_protection.set_flow(tls_flow_t::one_rtt);
    }
    get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    get_session_info(from_server).set_status(tls_handshake_type_t::client_hello);
}

uint32 tls_session::get_session_status() const { return _status; }

return_t tls_session::wait_change_session_status(uint32 status, unsigned msec, bool waitall) {
    return_t ret = errorcode_t::mismatch;

    while (1) {
        ret = _sem.wait(msec);

        if (0 == _status) {
            if (errorcode_t::success == ret) {
                ret = errorcode_t::mismatch;
            }
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

        if (errorcode_t::success != ret) {
            break;
        }
    }

#if defined DEBUG
    if (istraceable(trace_category_t::trace_category_net, loglevel_t::loglevel_debug)) {
        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
            dbs.println(ANSI_ESCAPE "1;34msession status %08x (wait%s %08x) %s" ANSI_ESCAPE "0m", _status, waitall ? "all" : "", status,
                        status == (_status & status) ? "true" : "false");
        });
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
    tls_direction_t d = dir;
    if (client_initiated_bidi == dir) {
        d = from_client;
    } else if (server_initiated_bidi == dir) {
        d = from_server;
    }
    return _direction[d];
}

uint64 tls_session::get_recordno(tls_direction_t dir, protection_space_t space) { return get_session_info(dir).get_recordno(space); }

void tls_session::inc_recordno(tls_direction_t dir, protection_space_t space) { get_session_info(dir).inc_recordno(space); }

void tls_session::reset_recordno(tls_direction_t dir, protection_space_t space) {
    auto ver = get_tls_protection().get_tls_version();
    if ((tls1_3 == ver) || (dtls1_3 == ver)) {
        get_session_info(dir).reset_recordno(space);
    }
}

void tls_session::set_recordno(tls_direction_t dir, uint64 recno, protection_space_t space) { get_session_info(dir).set_recordno(recno, space); }
bool tls_session::register_certificate_request_context(const binary_t& context) {
    critical_section_guard guard(_certificate_request_context_lock);
    for (const auto& registered : _certificate_request_contexts) {
        if (registered.size() == context.size()) {
            bool equal = true;
            for (size_t i = 0; i < context.size(); ++i) {
                if (registered[i] != context[i]) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                return false;
            }
        }
    }
    _certificate_request_contexts.push_back(context);
    return true;
}

void tls_session::reset_certificate_request_contexts() {
    critical_section_guard guard(_certificate_request_context_lock);
    _certificate_request_contexts.clear();
}

void tls_session::addref() { _shared.addref(); }

void tls_session::release() { _shared.delref(); }

tls_session::session_info::session_info() : _hstype(tls_handshake_type_t::client_hello), _protection(false), _active_cipher_suite(0) {}

void tls_session::session_info::set_status(tls_handshake_type_t type) { _hstype = type; }

tls_handshake_type_t tls_session::session_info::get_status() const { return _hstype; }

void tls_session::session_info::begin_protection() { _protection = true; }

bool tls_session::session_info::apply_protection() const { return _protection; }

void tls_session::session_info::reset_protection() { _protection = false; }

void tls_session::session_info::set_active_cipher_suite(uint16 ciphersuite) { _active_cipher_suite = ciphersuite; }

uint16 tls_session::session_info::get_active_cipher_suite() const { return _active_cipher_suite; }

uint64 tls_session::session_info::get_recordno(protection_space_t space) const {
    auto iter = _recordno_spaces.find(space);
    return (_recordno_spaces.end() != iter) ? iter->second : 0;
}

void tls_session::session_info::inc_recordno(protection_space_t space) { ++_recordno_spaces[space]; }

void tls_session::session_info::reset_recordno(protection_space_t space) {
    _recordno_spaces[space] = 0;
    if (protection_space_t::tls == space) {
        _kv.set(session_tls13_key_usage_bytes, 0);
    }
}

void tls_session::session_info::set_recordno(uint64 recordno, protection_space_t space) { _recordno_spaces[space] = recordno; }

void tls_session::session_info::push_alert(tls_alertlevel_t level, tls_alertdesc_t desc) {
    critical_section_guard guard(_info_lock);
    _alerts.push_back(alert(level, desc));
#if defined DEBUG
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    if (istraceable(trace_category_t::trace_category_net)) {
        trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_protection, [&](basic_stream& dbs) -> void {
            dbs.println(ANSI_ESCAPE "1;31malert level:%s desc:%s" ANSI_ESCAPE "0m", tlsadvisor->nameof_tls_alert_level(level).c_str(),
                        tlsadvisor->nameof_tls_alert_desc(desc).c_str());
        });
    }
#endif
}

void tls_session::session_info::get_alert(std::function<void(tls_alertlevel_t, tls_alertdesc_t)> func, uint8 flags) {
    critical_section_guard guard(_info_lock);
    for (auto iter = _alerts.begin(); iter != _alerts.end(); iter++) {
        const auto& item = *iter;
        func(item.level, item.desc);
    }
    if (0 == (session_alert_peek & flags)) {
        _alerts.clear();
    }
}

bool tls_session::session_info::has_alert(tls_alertlevel_t level) {
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
        for (const auto& ext : _extension_list) {
            extensions->add(ext, true);
            ext->release();
        }
        _extension_list.clear();
    }
}

void tls_session::select_into_scheduled_extension(tls_extensions* extensions, tls_extension_type_t type) {
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

void tls_session::clear_scheduled_extensions() {
    critical_section_guard guard(_lock);
    for (auto iter = _extension_list.begin(); iter != _extension_list.end(); iter++) {
        auto ext = *iter;
        ext->release();
    }
    _extension_list.clear();
}

void tls_session::push_alert(tls_direction_t dir, tls_alertlevel_t level, tls_alertdesc_t desc) { get_session_info(dir).push_alert(level, desc); }

void tls_session::get_alert(tls_direction_t dir, std::function<void(tls_alertlevel_t, tls_alertdesc_t)> func, uint8 flags) {
    get_session_info(dir).get_alert(func, flags);
}

bool tls_session::has_alert(tls_direction_t dir, tls_alertlevel_t level) { return get_session_info(dir).has_alert(level); }

}  // namespace net
}  // namespace hotplace
