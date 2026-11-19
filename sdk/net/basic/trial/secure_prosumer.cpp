/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   secure_prosumer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/enumclass.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/lowlevel/printf.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/net/basic/trial/secure_prosumer.hpp>
#include <hotplace/sdk/net/tls/dtls_record_arrange.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

static constexpr uint64 pending_tls_early_data_default_buffer_limit = 1024 * 1024;
static constexpr size_t pending_tls_early_data_record_limit = 64;
static constexpr uint64 pending_tls_early_data_record_wire_limit = 5 + 0xffff;
static constexpr uint64 pending_tls_early_data_record_buffer_limit = pending_tls_early_data_record_limit * pending_tls_early_data_record_wire_limit;

static bool pending_tls_early_data_decision(tls_session* session, tls_direction_t dir) {
    if ((nullptr == session) || (session_type_t::tls != session->get_type()) || (from_client != dir)) {
        return false;
    }

    const auto& early_state = session->get_session_info(from_server).get_keyvalue();
    uint32 session_status = session->get_session_status();
    // A failed PSK identity match can move the protection flow to one_rtt
    // while the ClientHello's early_data offer is still awaiting the server's
    // EncryptedExtensions decision. The offer/status pair, not the current
    // traffic-key flow, defines this buffering window.
    return (0 != early_state.get(session_early_data_offered)) && (0 != (session_status_client_hello & session_status)) &&
           (0 == (session_status_encrypted_extensions & session_status));
}

static size_t pending_tls_early_data_record_count(const byte_t* stream, size_t size) {
    size_t count = 0;
    size_t pos = 0;
    while (pos < size) {
        ++count;
        size_t remaining = size - pos;
        if (remaining < 5) {
            break;
        }
        size_t record_size = 5 + (static_cast<size_t>(stream[pos + 3]) << 8) + stream[pos + 4];
        if (remaining < record_size) {
            break;
        }
        pos += record_size;
    }
    return count;
}

static uint64 pending_tls_early_data_effective_buffer_limit(uint64 byte_limit) {
    if ((0 == byte_limit) || (byte_limit > pending_tls_early_data_record_buffer_limit)) {
        return pending_tls_early_data_record_buffer_limit;
    }
    return byte_limit;
}

static bool pending_tls_early_data_limit_exceeded(const byte_t* stream, size_t size, uint64 byte_limit) {
    return (size > pending_tls_early_data_effective_buffer_limit(byte_limit)) ||
           (pending_tls_early_data_record_count(stream, size) > pending_tls_early_data_record_limit);
}

static void abort_pending_tls_early_data(tls_session* session, tls_direction_t dir, basic_stream& buffer) {
    buffer.clear();
    session->push_alert(dir, tls_alertlevel_t::fatal, tls_alertdesc_t::internal_error);
    session->reset_session_status();
}

static bool pending_tls_early_data_byte_limit_exceeded(size_t buffered_size, size_t incoming_size, uint64 byte_limit) {
    const uint64 effective_limit = pending_tls_early_data_effective_buffer_limit(byte_limit);
    uint64 buffered = static_cast<uint64>(buffered_size);
    uint64 incoming = static_cast<uint64>(incoming_size);
    return (buffered > effective_limit) || (incoming > effective_limit - buffered);
}

class pending_tls_early_data_stream;

struct pending_tls_early_data_printf_context : printf_context_t {
    pending_tls_early_data_stream* stream;
    return_t result;

    explicit pending_tls_early_data_printf_context(pending_tls_early_data_stream* value) : stream(value), result(errorcode_t::success) {}
};

static int pending_tls_early_data_printf_callback(printf_context_t* context, const char* data, int size);
#if defined _WIN32 || defined _WIN64
static int pending_tls_early_data_wprintf_callback(printf_context_t* context, const wchar_t* data, int size);
#endif

class pending_tls_early_data_stream : public basic_stream {
   public:
    pending_tls_early_data_stream(const basic_stream& initial, uint64 byte_limit) : basic_stream(initial), _byte_limit(byte_limit), _overflowed(false) {}

    basic_stream& operator=(const basic_stream& other) override {
        if (pending_tls_early_data_byte_limit_exceeded(0, other.size(), _byte_limit)) {
            _overflowed = true;
            return *this;
        }
        basic_stream::operator=(other);
        return *this;
    }

    basic_stream& operator=(basic_stream&& other) noexcept override {
        if (pending_tls_early_data_byte_limit_exceeded(0, other.size(), _byte_limit)) {
            _overflowed = true;
            return *this;
        }
        basic_stream::operator=(std::move(other));
        return *this;
    }

    return_t write(const void* data, size_t size) override {
        if (pending_tls_early_data_byte_limit_exceeded(this->size(), size, _byte_limit)) {
            _overflowed = true;
            return errorcode_t::overflow;
        }
        return basic_stream::write(data, size);
    }

    return_t insert(size_t begin, const void* data, size_t size) override {
        if (pending_tls_early_data_byte_limit_exceeded(this->size(), size, _byte_limit)) {
            _overflowed = true;
            return errorcode_t::overflow;
        }
        return basic_stream::insert(begin, data, size);
    }

    return_t fill(size_t size, char value) override {
        if (pending_tls_early_data_byte_limit_exceeded(this->size(), size, _byte_limit)) {
            _overflowed = true;
            return errorcode_t::overflow;
        }
        return basic_stream::fill(size, value);
    }

    return_t vprintf(const char* format, va_list args) override {
        pending_tls_early_data_printf_context context(this);
        int result = vprintf_runtime(&context, pending_tls_early_data_printf_callback, format, args);
        if (errorcode_t::success != context.result) {
            return context.result;
        }
        return (result < 0) ? errorcode_t::internal_error : errorcode_t::success;
    }

#if defined _WIN32 || defined _WIN64
    return_t vwprintf(const wchar_t* format, va_list args) override {
        pending_tls_early_data_printf_context context(this);
        int result = vprintf_runtimew(&context, pending_tls_early_data_wprintf_callback, format, args);
        if (errorcode_t::success != context.result) {
            return context.result;
        }
        return (result < 0) ? errorcode_t::internal_error : errorcode_t::success;
    }
#endif

    void resize(size_t size) override {
        if (pending_tls_early_data_byte_limit_exceeded(this->size(), size > this->size() ? size - this->size() : 0, _byte_limit)) {
            _overflowed = true;
            return;
        }
        basic_stream::resize(size);
    }

    bool overflowed() const { return _overflowed; }

   private:
    uint64 _byte_limit;
    bool _overflowed;
};

static int pending_tls_early_data_printf_callback(printf_context_t* context, const char* data, int size) {
    auto* output = static_cast<pending_tls_early_data_printf_context*>(context);
    if ((nullptr == output) || (errorcode_t::success != output->result)) {
        return -1;
    }
    if (size <= 0) {
        return 0;
    }
    output->result = output->stream->write(data, static_cast<size_t>(size));
    return (errorcode_t::success == output->result) ? size : -1;
}

#if defined _WIN32 || defined _WIN64
static int pending_tls_early_data_wprintf_callback(printf_context_t* context, const wchar_t* data, int size) {
    auto* output = static_cast<pending_tls_early_data_printf_context*>(context);
    if ((nullptr == output) || (errorcode_t::success != output->result)) {
        return -1;
    }
    if (size <= 0) {
        return 0;
    }
    output->result = output->stream->write(data, static_cast<size_t>(size) * sizeof(wchar_t));
    return (errorcode_t::success == output->result) ? size : -1;
}
#endif

static return_t enforce_pending_tls_early_data_limit(tls_session* session, tls_direction_t dir, basic_stream& buffer, uint64 byte_limit) {
    if (pending_tls_early_data_decision(session, dir) && pending_tls_early_data_limit_exceeded(buffer.data(), buffer.size(), byte_limit)) {
        abort_pending_tls_early_data(session, dir, buffer);
        return errorcode_t::overflow;
    }
    return errorcode_t::success;
}

secure_prosumer::secure_prosumer()
    : _producing(false), _resume_pending(false), _transport_closed(false), _pending_early_data_buffer_limit(pending_tls_early_data_default_buffer_limit) {}

return_t secure_prosumer::notify_transport_closed() {
    bool notify = false;
    {
        critical_section_guard guard(_mlock);
        if (false == _transport_closed) {
            _transport_closed = true;
            notify = true;
        }
    }
    if (true == notify) {
        return _msem.signal();
    }
    return errorcode_t::success;
}

void secure_prosumer::set_pending_early_data_buffer_limit(uint64 limit) { _pending_early_data_buffer_limit = limit; }

uint64 secure_prosumer::get_pending_early_data_buffer_limit() const { return _pending_early_data_buffer_limit; }

return_t secure_prosumer::produce(tls_session* session, tls_direction_t dir, std::function<void(basic_stream&, sockaddr_storage_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (true == _producing) {
            ret = errorcode_t::unexpected;
            __leave2;
        }
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        sockaddr_storage_t addr;
        if (pending_tls_early_data_decision(session, dir)) {
            pending_tls_early_data_stream candidate(_mbs, _pending_early_data_buffer_limit);
            func(candidate, addr);
            if (candidate.overflowed()) {
                abort_pending_tls_early_data(session, dir, _mbs);
                ret = errorcode_t::overflow;
                __leave2;
            }
            _mbs = std::move(candidate);

            socklen_t addrlen = sizeof(addr);
            ret = do_produce(session, dir, (sockaddr*)&addr, &addrlen);
            if ((errorcode_t::success == ret) && pending_tls_early_data_decision(session, dir) &&
                pending_tls_early_data_limit_exceeded(_mbs.data(), _mbs.size(), _pending_early_data_buffer_limit)) {
                abort_pending_tls_early_data(session, dir, _mbs);
                ret = errorcode_t::overflow;
            }
        } else {
            func(_mbs, addr);
            socklen_t addrlen = sizeof(addr);
            ret = do_produce(session, dir, (sockaddr*)&addr, &addrlen);
            if (errorcode_t::success == ret) {
                ret = enforce_pending_tls_early_data_limit(session, dir, _mbs, _pending_early_data_buffer_limit);
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::produce(tls_session* session, tls_direction_t dir, const byte_t* ptr_data, size_t size_data, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (true == _producing) {
            ret = errorcode_t::unexpected;
            __leave2;
        }
        if (nullptr == ptr_data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (pending_tls_early_data_decision(session, dir)) {
            if (pending_tls_early_data_byte_limit_exceeded(_mbs.size(), size_data, _pending_early_data_buffer_limit)) {
                abort_pending_tls_early_data(session, dir, _mbs);
                ret = errorcode_t::overflow;
                __leave2;
            }
            basic_stream candidate(_mbs);
            ret = candidate.write(ptr_data, size_data);
            if (errorcode_t::success != ret) {
                __leave2_trace(ret);
            }
            _mbs = std::move(candidate);

            ret = do_produce(session, dir, addr, addrlen);
            if ((errorcode_t::success == ret) && pending_tls_early_data_decision(session, dir) &&
                pending_tls_early_data_limit_exceeded(_mbs.data(), _mbs.size(), _pending_early_data_buffer_limit)) {
                abort_pending_tls_early_data(session, dir, _mbs);
                ret = errorcode_t::overflow;
            }
            __leave2;
        }

        if ((session_type_t::tls == session->get_type()) && (from_client == dir)) {
            // Process TLS records one at a time until ClientHello establishes
            // whether following application_data records must be buffered as 0-RTT.
            // This prevents a coalesced ClientHello + large early-data flight from
            // being copied into _mbs before the pending-data ceiling is known.
            size_t input_pos = 0;
            while (true) {
                if (pending_tls_early_data_decision(session, dir)) {
                    size_t remaining = size_data - input_pos;
                    if (0 == remaining) {
                        break;
                    }
                    if (pending_tls_early_data_byte_limit_exceeded(_mbs.size(), remaining, _pending_early_data_buffer_limit)) {
                        abort_pending_tls_early_data(session, dir, _mbs);
                        ret = errorcode_t::overflow;
                        break;
                    }
                    ret = _mbs.write(ptr_data + input_pos, remaining);
                    if (errorcode_t::success != ret) {
                        break;
                    }
                    input_pos = size_data;
                    size_t pos = 0;
                    ret = do_produce(session, dir, _mbs.data(), _mbs.size(), pos, addr, addrlen);
                    _mbs.cut(0, pos);
                    if ((errorcode_t::success == ret) && pending_tls_early_data_decision(session, dir) &&
                        pending_tls_early_data_limit_exceeded(_mbs.data(), _mbs.size(), _pending_early_data_buffer_limit)) {
                        abort_pending_tls_early_data(session, dir, _mbs);
                        ret = errorcode_t::overflow;
                    }
                    break;
                }

                size_t target_size = 5;
                if (_mbs.size() >= 5) {
                    const byte_t* buffered = _mbs.data();
                    target_size += (static_cast<size_t>(buffered[3]) << 8) + buffered[4];
                }
                if (_mbs.size() >= target_size) {
                    size_t pos = 0;
                    ret = do_produce(session, dir, _mbs.data(), _mbs.size(), pos, addr, addrlen);
                    _mbs.cut(0, pos);
                    if (errorcode_t::success != ret) {
                        break;
                    }
                    if (0 == pos) {
                        ret = errorcode_t::unexpected;
                        break;
                    }
                    continue;
                }

                if (input_pos >= size_data) {
                    break;
                }
                size_t remaining = size_data - input_pos;
                size_t needed = target_size - _mbs.size();
                size_t chunk = (needed < remaining) ? needed : remaining;
                ret = _mbs.write(ptr_data + input_pos, chunk);
                if (errorcode_t::success != ret) {
                    break;
                }
                input_pos += chunk;
            }

            // Complete records are dispatched inside the loop. Any bytes left
            // in _mbs are an incomplete trailing record; keep them until the
            // next input fragment arrives instead of parsing a partial body.
            __leave2;
        }

        ret = _mbs.write(ptr_data, size_data);
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        ret = do_produce(session, dir, addr, addrlen);
        if (errorcode_t::success == ret) {
            ret = enforce_pending_tls_early_data_limit(session, dir, _mbs, _pending_early_data_buffer_limit);
        }
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::resume_pending_records(tls_session* session, tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    bool owns_producer = false;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true == _producing) {
            _resume_pending = true;
            __leave2;
        }
        _producing = true;
        owns_producer = true;
        size_t size = _mbs.size();
        if (0 != size) {
            const byte_t* stream = _mbs.data();
            size_t complete_size = 0;
            while (size - complete_size >= 5) {
                uint16 body_size = (static_cast<uint16>(stream[complete_size + 3]) << 8) | stream[complete_size + 4];
                size_t record_size = 5 + body_size;
                if (size - complete_size < record_size) {
                    break;
                }
                complete_size += record_size;
            }
            if (0 != complete_size) {
                size_t pos = 0;
                ret = do_produce(session, dir, stream, complete_size, pos);
                _mbs.cut(0, pos);
            }
        }
    }
    __finally2 {
        if (true == owns_producer) {
            _producing = false;
        }
    }
    if ((true == owns_producer) && (true == _resume_pending)) {
        _resume_pending = false;
        if (errorcode_t::success == ret) {
            ret = resume_pending_records(session, dir);
        }
    }
    return ret;
}

return_t secure_prosumer::do_produce(tls_session* session, tls_direction_t dir, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    bool owns_producer = false;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (true == _producing) {
            ret = errorcode_t::unexpected;
            __leave2;
        }
        _producing = true;
        owns_producer = true;

        tls_record_builder builder;

        auto session_type = session->get_type();
        size_t pos = 0;

        if (session_type_t::dtls == session_type) {
            // DTLS (built-in reorder feature)
            if (nullptr == addr || nullptr == addrlen) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }
            socklen_t socklen = *addrlen;

            auto& arrange = session->get_dtls_record_arrange();
            arrange.produce(addr, socklen, _mbs.data(), _mbs.size());
            _mbs.clear();

            while (1) {
                binary_t packet;
                auto test = arrange.consume(addr, socklen, packet);
                if (errorcode_t::success == test) {
                    pos = 0;
                    ret = do_produce(session, dir, packet.data(), packet.size(), pos, addr, addrlen);
                } else {
                    break;  // empty, not_ready
                }
            }
        } else {
            // TLS, QUIC
            const byte_t* stream = _mbs.data();
            size_t size = _mbs.size();
            ret = do_produce(session, dir, stream, size, pos, addr, addrlen);
            _mbs.cut(0, pos);
        }
    }
    __finally2 {
        if (true == owns_producer) {
            _producing = false;
        }
    }
    if ((true == owns_producer) && (true == _resume_pending)) {
        _resume_pending = false;
        if (errorcode_t::success == ret) {
            ret = resume_pending_records(session, dir);
        }
    }
    return ret;
}

return_t secure_prosumer::do_produce(tls_session* session, tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, struct sockaddr* addr,
                                     socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        bool transport_closed = false;
        {
            critical_section_guard guard(_mlock);
            transport_closed = _transport_closed;
        }
        if (true == transport_closed) {
            pos = size;
            ret = errorcode_t::disconnect;
            __leave2;
        }

        // A fatal alert terminates the TLS connection. Do not parse another
        // record from this input or accept records from later input calls.
        if (session->has_alert(dir, tls_alertlevel_t::fatal)) {
            pos = size;
            return_t notify_ret = notify_transport_closed();
            if (errorcode_t::success == notify_ret) {
                ret = errorcode_t::handshake_failure;
            } else {
                ret = notify_ret;
            }
            __leave2;
        }

        tls_record_builder builder;

        while ((errorcode_t::success == ret) && (pos < size)) {
            if (true == _resume_pending) {
                break;
            }
            auto type = stream[pos];
            const auto& early_state = session->get_session_info(from_server).get_keyvalue();
            uint32 session_status = session->get_session_status();
            bool early_data_decision_pending =
                (session_type_t::tls == session->get_type()) && (from_client == dir) && (tls_content_type_t::application_data == static_cast<tls_content_type_t>(type)) &&
                (0 != early_state.get(session_early_data_offered)) && (0 != (session_status_client_hello & session_status)) &&
                (0 == (session_status_encrypted_extensions & session_status)) && (tls_flow_t::hello_retry_request != session->get_tls_protection().get_flow());
            if (true == early_data_decision_pending) {
                // Client 0-RTT application_data may already be in flight when
                // the server builds EncryptedExtensions. This remains true if
                // PSK processing has already selected one_rtt after rejecting
                // the offered identity; keep the ciphertext buffered until the
                // server's acceptance/rejection decision is committed.
                break;
            }

            t_enum_type<tls_content_type_t> ettype(type);
            tls_content_type_t content_type = ettype;
            auto record = builder.set(session).set(content_type).build();
            if (record) {
                ret = record->read(dir, stream, size, pos);
                if ((errorcode_t::success == ret) && session->has_alert(dir, tls_alertlevel_t::fatal)) {
                    // A received fatal alert makes the transport terminal:
                    // wake application readers and discard coalesced records.
                    pos = size;
                    return_t notify_ret = notify_transport_closed();
                    if (errorcode_t::success == notify_ret) {
                        ret = errorcode_t::handshake_failure;
                    } else {
                        ret = notify_ret;
                    }
                }
                if (errorcode_t::success == ret) {
                    if (tls_content_type_t::application_data == content_type) {
                        tls_record_application_data* appdata = (tls_record_application_data*)record;
                        const auto& bin = appdata->get_binary();
                        if (false == bin.empty()) {
                            socket_buffer_t item;
                            item.buffer << bin;
                            if (addr && addrlen) {
                                memcpy(&item.addr, addr, *addrlen);
                            }

                            bool transport_closed = false;
                            {
                                critical_section_guard guard(_mlock);
                                if (true == _transport_closed) {
                                    transport_closed = true;
                                } else {
                                    _mq.push(std::move(item));
                                }
                            }
                            if (true == transport_closed) {
                                // A concurrent close may win after the entry
                                // check. Never enqueue plaintext after terminal
                                // state has been published.
                                pos = size;
                                ret = errorcode_t::disconnect;
                            } else {
                                _msem.signal();
                            }
                        }
                    }
                }
                record->release();
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t secure_prosumer::consume(int sock_type, uint32 wto, char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbread) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *cbread = 0;

        bool terminal = false;
        {
            critical_section_guard guard(_mlock);
            terminal = _mq.empty() && _transport_closed;
        }
        if (true == terminal) {
            ret = errorcode_t::disconnect;
            __leave2;
        }

        ret = _msem.wait(wto);
        if (errorcode_t::success != ret) {
            critical_section_guard guard(_mlock);
            if (_mq.empty() && _transport_closed) {
                ret = errorcode_t::disconnect;
            }
            __leave2;
        }

        critical_section_guard guard(_mlock);
        if (false == _mq.empty()) {
            auto& item = _mq.front();

            if (SOCK_DGRAM == sock_type) {
                if (addr && addrlen) {
                    memcpy(addr, &item.addr, *addrlen);
                }
            }

            auto datasize = item.buffer.size();
            if (datasize > size_data) {
                memcpy(ptr_data, item.buffer.data(), size_data);
                item.buffer.cut(0, size_data);

                *cbread = size_data;
                ret = _msem.signal();
                if (errorcode_t::success == ret) {
                    ret = errorcode_t::more_data;
                }
            } else {
                memcpy(ptr_data, item.buffer.data(), datasize);

                *cbread = datasize;

                _mq.pop();
            }
#if defined DEBUG
            if (*cbread) {
                if (istraceable(trace_category_t::trace_category_net)) {
                    trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_record, [&](basic_stream& dbs) -> void {
                        dbs.println("+ read");
                        dump_memory((byte_t*)ptr_data, *cbread, &dbs, 16, 3, 0x0, dump_notrunc);
                    });
                }
            }
#endif
            if ((errorcode_t::success == ret) && (false == _mq.empty())) {
                ret = errorcode_t::more_data;
            }
        } else if (true == _transport_closed) {
            ret = errorcode_t::disconnect;
        } else {
            ret = errorcode_t::empty;
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
