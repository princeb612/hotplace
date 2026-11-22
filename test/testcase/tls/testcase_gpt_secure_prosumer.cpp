/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_secure_prosumer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc   TLS secure-prosumer queueing and consumption tests.
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <utility>

#include "sample.hpp"

class client_close_test_fixture : public hotplace::net::client_socket_prosumer {
   public:
    client_close_test_fixture() : _stage(0) {}
    int stage() const { return _stage; }
    bool remote_closed() const { return is_remote_transport_closed(); }

   protected:
    hotplace::return_t do_transport_disconnect() override {
        _stage = (_stage == 0) ? 1 : -1;
        return hotplace::errorcode_t::success;
    }
    hotplace::return_t do_shutdown() override {
        _stage = (_stage == 1) ? 2 : -1;
        return hotplace::errorcode_t::success;
    }
    hotplace::return_t do_close() override {
        _stage = (_stage == 2) ? 3 : -1;
        return hotplace::errorcode_t::success;
    }

   private:
    int _stage;
};

class client_receive_error_test_fixture : public hotplace::net::client_socket_prosumer {
   public:
#if defined __linux__
    hotplace::return_t dispatch_invalid_read() {
        void* data[2] = {nullptr, reinterpret_cast<void*>(static_cast<hotplace::arch_t>(-1))};
        return do_consumer_routine(hotplace::io::mux_read, 2, data, nullptr, this);
    }
#endif
    int disconnect_count() const { return _disconnect_count; }
    bool remote_closed() const { return is_remote_transport_closed(); }
    hotplace::return_t dispatch_disconnect() { return do_consumer_routine(hotplace::io::mux_disconnect, 0, nullptr, nullptr, this); }

   protected:
    hotplace::return_t do_transport_disconnect() override {
        ++_disconnect_count;
        return hotplace::errorcode_t::success;
    }

   private:
    int _disconnect_count = 0;
};

#if defined _WIN32 || defined _WIN64
class iocp_read_rearm_test_fixture : public hotplace::net::secure_client_socket {
   public:
    iocp_read_rearm_test_fixture()
        : secure_client_socket(hotplace::net::tls_version_t::tls1_3), _secure_count(0), _processed_size(0), _secure_status(hotplace::errorcode_t::success) {}
    void set_secure_status(hotplace::return_t status) { _secure_status = status; }

    hotplace::return_t dispatch_read(const char* payload, size_t size) {
        _mplexer_key.buffer.init();
        memcpy(_mplexer_key.buffer.wsabuf.buf, payload, size);
        void* data[3] = {nullptr, reinterpret_cast<void*>(static_cast<hotplace::arch_t>(size)), &_mplexer_key};
        return do_consumer_routine(hotplace::io::mux_read, 3, data, nullptr, this);
    }

    size_t secure_count() const { return _secure_count; }
    size_t processed_size() const { return _processed_size; }
    const char* processed_data() const { return _processed; }
    bool remote_closed() const { return is_remote_transport_closed(); }

   protected:
    hotplace::return_t do_secure() override {
        ++_secure_count;
        hotplace::basic_stream stream;
        hotplace::io::sockaddr_storage_t addr = {};
        hotplace::return_t ret = do_consume(stream, addr);
        if ((hotplace::errorcode_t::success == ret) && (stream.size() <= sizeof(_processed))) {
            _processed_size = stream.size();
            if (0 != _processed_size) {
                memcpy(_processed, stream.data(), _processed_size);
            }
        }
        return (hotplace::errorcode_t::success == ret) ? _secure_status : ret;
    }

   private:
    size_t _secure_count;
    size_t _processed_size;
    hotplace::return_t _secure_status;
    char _processed[16] = {};
};
#endif

class secure_prosumer_test_fixture : public hotplace::net::secure_prosumer {
   public:
    hotplace::return_t enqueue(const char* data, size_t size) {
        hotplace::net::socket_buffer_t item;
        hotplace::return_t ret = item.buffer.write((hotplace::byte_t*)data, size);
        if (hotplace::errorcode_t::success != ret) {
            return ret;
        }

        hotplace::critical_section_guard guard(_mlock);
        _mq.push(std::move(item));
        return _msem.signal();
    }
};

class dtls_fragment_test_handshake : public hotplace::net::tls_handshake {
   public:
    dtls_fragment_test_handshake(hotplace::net::tls_handshake_type_t type, hotplace::net::tls_session* session, size_t size)
        : tls_handshake(type, session), _body(size, 0x5a) {}

   protected:
    hotplace::return_t do_write_body(hotplace::net::tls_direction_t, hotplace::binary_t& bin) override {
        bin.insert(bin.end(), _body.begin(), _body.end());
        return hotplace::errorcode_t::success;
    }

   private:
    hotplace::binary_t _body;
};

static void test_secure_prosumer_fatal_alert(const char* testcase_name) {
    // Scenario under test: secure_prosumer stops processing application data after a fatal TLS alert.
    // Action: deliver a fatal alert followed by application-data bytes through the prosumer.
    // Expected: surface the fatal alert and do not process data that follows it.
    hotplace::return_t ret = hotplace::errorcode_t::success;
    {
        hotplace::net::tls_session fatal_session(hotplace::net::session_type_t::tls);
        hotplace::net::secure_prosumer fatal_prosumer;
        const hotplace::byte_t fatal_then_application[] = {
            0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28,      // fatal handshake_failure alert
            0x17, 0x03, 0x03, 0x00, 0x03, 'b',  'a',  'd'  // must not be processed
        };
        ret = fatal_prosumer.produce(&fatal_session, hotplace::net::from_server, fatal_then_application, sizeof(fatal_then_application));
        _test_case.assert(
            (hotplace::errorcode_t::handshake_failure == ret) && fatal_session.has_alert(hotplace::net::from_server, hotplace::net::tls_alertlevel_t::fatal),
            testcase_name, "fatal TLS alert terminates record processing");

        char fatal_buffer[8] = {};
        size_t fatal_read = 0;
        ret = fatal_prosumer.consume(SOCK_STREAM, 1, fatal_buffer, sizeof(fatal_buffer), &fatal_read);
        _test_case.assert((hotplace::errorcode_t::disconnect == ret) && (0 == fatal_read), testcase_name,
                          "do not deliver application data coalesced after a fatal alert");

        const hotplace::byte_t later_application[] = {0x17, 0x03, 0x03, 0x00, 0x03, 'n', 'e', 'w'};
        hotplace::net::tls_session preexisting_fatal_session(hotplace::net::session_type_t::tls);
        hotplace::net::secure_prosumer preexisting_fatal_prosumer;
        preexisting_fatal_session.push_alert(hotplace::net::from_server, hotplace::net::tls_alertlevel_t::fatal, hotplace::net::tls_alertdesc_t::internal_error);
        ret = preexisting_fatal_prosumer.produce(&preexisting_fatal_session, hotplace::net::from_server, later_application, sizeof(later_application));
        _test_case.assert(hotplace::errorcode_t::handshake_failure == ret, testcase_name, "reject input when a fatal TLS alert is already pending");
        fatal_read = 0;
        ret = preexisting_fatal_prosumer.consume(SOCK_STREAM, 1, fatal_buffer, sizeof(fatal_buffer), &fatal_read);
        _test_case.assert((hotplace::errorcode_t::disconnect == ret) && (0 == fatal_read), testcase_name, "preexisting fatal alert marks the secure prosumer terminal");

        ret = fatal_prosumer.produce(&fatal_session, hotplace::net::from_server, later_application, sizeof(later_application));
        _test_case.assert(hotplace::errorcode_t::disconnect == ret, testcase_name, "reject subsequent TLS records after a fatal alert");
    }
}

static void test_secure_prosumer_queue_lifecycle(const char* testcase_name) {
    // Scenario under test: secure_prosumer application-data queue lifecycle.
    // Action: enqueue, partially dequeue, and drain application payloads.
    // Expected: preserve byte order and queue accounting across partial reads.
    hotplace::return_t ret = hotplace::errorcode_t::success;
    secure_prosumer_test_fixture prosumer;
    const char* payload = "abcdef";
    ret = prosumer.enqueue(payload, 6);
    _test_case.test(ret, testcase_name, "enqueue application data");

    char buffer[8] = {};
    size_t cbread = 0;
    ret = prosumer.consume(SOCK_STREAM, 100, buffer, 3, &cbread);
    _test_case.assert((hotplace::errorcode_t::more_data == ret) && (3 == cbread) && (0 == memcmp(buffer, "abc", 3)), testcase_name,
                      "partial read keeps the remaining bytes ready");

    memset(buffer, 0, sizeof(buffer));
    cbread = 0;
    ret = prosumer.consume(SOCK_STREAM, 100, buffer, 3, &cbread);
    _test_case.assert((hotplace::errorcode_t::success == ret) && (3 == cbread) && (0 == memcmp(buffer, "def", 3)), testcase_name,
                      "second read consumes the remaining bytes");

    ret = prosumer.enqueue("xyz", 3);
    _test_case.test(ret, testcase_name, "enqueue exact-size application data");

    memset(buffer, 0, sizeof(buffer));
    cbread = 0;
    ret = prosumer.consume(SOCK_STREAM, 100, buffer, 3, &cbread);
    _test_case.assert((hotplace::errorcode_t::success == ret) && (3 == cbread) && (0 == memcmp(buffer, "xyz", 3)), testcase_name,
                      "exact-size read removes the queue item");

    cbread = 0;
    ret = prosumer.consume(SOCK_STREAM, 1, buffer, 1, &cbread);
    _test_case.assert(hotplace::errorcode_t::timeout == ret, testcase_name, "empty queue waits for new application data");

    ret = prosumer.notify_transport_closed();
    _test_case.test(ret, testcase_name, "mark transport terminal");
    cbread = 0;
    ret = prosumer.consume(SOCK_STREAM, 1000, buffer, 1, &cbread);
    _test_case.assert((hotplace::errorcode_t::disconnect == ret) && (0 == cbread), testcase_name, "terminal state wakes and ends a waiting read");
    cbread = 0;
    ret = prosumer.consume(SOCK_STREAM, 1000, buffer, 1, &cbread);
    _test_case.assert((hotplace::errorcode_t::disconnect == ret) && (0 == cbread), testcase_name, "repeated reads return terminal state immediately");

    secure_prosumer_test_fixture waiting;
    std::atomic<bool> read_started(false);
    hotplace::return_t waiting_result = hotplace::errorcode_t::success;
    size_t waiting_read = 0;
    std::thread reader([&]() {
        char waiting_buffer[4] = {};
        read_started.store(true);
        waiting_result = waiting.consume(SOCK_STREAM, 5000, waiting_buffer, sizeof(waiting_buffer), &waiting_read);
    });
    while (false == read_started.load()) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ret = waiting.notify_transport_closed();
    reader.join();
    _test_case.assert((hotplace::errorcode_t::success == ret) && (hotplace::errorcode_t::disconnect == waiting_result) && (0 == waiting_read), testcase_name,
                      "disconnect wakes a read already waiting on the semaphore");

    secure_prosumer_test_fixture queued;
    ret = queued.enqueue("one", 3);
    _test_case.test(ret, testcase_name, "enqueue first item before disconnect");
    ret = queued.enqueue("two", 3);
    _test_case.test(ret, testcase_name, "enqueue second item before disconnect");
    ret = queued.notify_transport_closed();
    _test_case.test(ret, testcase_name, "disconnect with queued application data");

    memset(buffer, 0, sizeof(buffer));
    cbread = 0;
    ret = queued.consume(SOCK_STREAM, 100, buffer, 3, &cbread);
    _test_case.assert((hotplace::errorcode_t::more_data == ret) && (3 == cbread) && (0 == memcmp(buffer, "one", 3)), testcase_name,
                      "queued data is delivered before terminal status");
    memset(buffer, 0, sizeof(buffer));
    cbread = 0;
    ret = queued.consume(SOCK_STREAM, 100, buffer, 3, &cbread);
    _test_case.assert((hotplace::errorcode_t::success == ret) && (3 == cbread) && (0 == memcmp(buffer, "two", 3)), testcase_name,
                      "all queued data is drained after disconnect");
    cbread = 0;
    ret = queued.consume(SOCK_STREAM, 100, buffer, 1, &cbread);
    _test_case.assert((hotplace::errorcode_t::disconnect == ret) && (0 == cbread), testcase_name, "terminal status follows the last queued item");
}

static void test_secure_prosumer_transport_disconnect(const char* testcase_name) {
    // Scenario under test: secure_prosumer explicit transport disconnect and close ordering.
    // Action: close the client transport while readers and TLS shutdown are pending.
    // Expected: notify readers before TLS shutdown and socket cleanup, without reporting a remote close.
    hotplace::return_t ret = hotplace::errorcode_t::success;
    client_close_test_fixture client;
    ret = client.close();
    _test_case.assert((hotplace::errorcode_t::success == ret) && (3 == client.stage()) && (false == client.remote_closed()), testcase_name,
                      "explicit close notifies readers before TLS shutdown and socket cleanup");

#if defined __linux__
    client_receive_error_test_fixture receive_error;
    ret = receive_error.dispatch_invalid_read();
    _test_case.assert((hotplace::errorcode_t::success != ret) && (1 == receive_error.disconnect_count()) && receive_error.remote_closed(), testcase_name,
                      "fatal Linux socket read error marks the TLS transport terminal");
#endif

    client_receive_error_test_fixture remote_disconnect;
    ret = remote_disconnect.dispatch_disconnect();
    _test_case.assert((hotplace::errorcode_t::success == ret) && (1 == remote_disconnect.disconnect_count()) && remote_disconnect.remote_closed(), testcase_name,
                      "remote multiplexer disconnect is tracked separately from explicit local close");

#if defined _WIN32 || defined _WIN64
    iocp_read_rearm_test_fixture iocp_read;
    ret = iocp_read.dispatch_read("last", 4);
    _test_case.assert((hotplace::errorcode_t::success != ret) && (1 == iocp_read.secure_count()) && (4 == iocp_read.processed_size()) &&
                          (0 == memcmp(iocp_read.processed_data(), "last", 4)) && iocp_read.remote_closed(),
                      testcase_name, "completed IOCP read is processed even when the next asynchronous read cannot be queued");

    iocp_read_rearm_test_fixture iocp_read_error;
    iocp_read_error.set_secure_status(hotplace::errorcode_t::internal_error);
    ret = iocp_read_error.dispatch_read("fail", 4);
    _test_case.assert((hotplace::errorcode_t::internal_error == ret) && (1 == iocp_read_error.secure_count()) && (4 == iocp_read_error.processed_size()) &&
                          (0 == memcmp(iocp_read_error.processed_data(), "fail", 4)) && iocp_read_error.remote_closed(),
                      testcase_name, "TLS processing failure takes precedence over a subsequent IOCP read rearm failure");
#endif
}

static void test_secure_prosumer_send_and_dtls(const char* testcase_name) {
    // Scenario under test: secure_prosumer send callback failure and DTLS transport behavior.
    // Action: force a TLS record send callback failure and exercise DTLS send/receive paths.
    // Expected: propagate transport errors and preserve the correct datagram behavior.
    hotplace::return_t ret = hotplace::errorcode_t::success;
    hotplace::net::tls_session session(hotplace::net::session_type_t::tls);
    hotplace::net::tls_records records;
    bool send_callback_called = false;
    ret = records.write(&session, hotplace::net::from_client, [&](hotplace::net::tls_session*, hotplace::binary_t&) -> hotplace::return_t {
        send_callback_called = true;
        return hotplace::errorcode_t::internal_error;
    });
    _test_case.assert((hotplace::errorcode_t::internal_error == ret) && send_callback_called, testcase_name, "TLS record writer returns the send callback failure");

    hotplace::net::tls_session handshake_session(hotplace::net::session_type_t::tls);
    hotplace::net::tls_composer composer(&handshake_session);
    composer.set_minver(hotplace::net::tls_version_t::tls1_3);
    composer.set_maxver(hotplace::net::tls_version_t::tls1_3);
    size_t handshake_send_calls = 0;
    ret = composer.handshake(hotplace::net::from_client, 1, [&](hotplace::net::tls_session*, hotplace::binary_t&) -> hotplace::return_t {
        ++handshake_send_calls;
        return hotplace::errorcode_t::internal_error;
    });
    _test_case.assert((hotplace::errorcode_t::internal_error == ret) && (1 == handshake_send_calls), testcase_name,
                      "TLS client handshake stops at ClientHello send failure and propagates its status");

    hotplace::net::tls_session timeout_session(hotplace::net::session_type_t::tls);
    hotplace::net::tls_composer timeout_composer(&timeout_session);
    timeout_composer.set_minver(hotplace::net::tls_version_t::tls1_3);
    timeout_composer.set_maxver(hotplace::net::tls_version_t::tls1_3);
    size_t timeout_send_calls = 0;
    ret = timeout_composer.handshake(hotplace::net::from_client, 1, [&](hotplace::net::tls_session*, hotplace::binary_t&) -> hotplace::return_t {
        ++timeout_send_calls;
        return hotplace::errorcode_t::success;
    });
    _test_case.assert((hotplace::errorcode_t::timeout == ret) && (1 == timeout_send_calls), testcase_name,
                      "TLS client handshake propagates the ServerHello wait timeout");

    hotplace::net::tls_session partial_status_session(hotplace::net::session_type_t::tls);
    partial_status_session.update_session_status(hotplace::net::session_status_server_hello);
    ret = partial_status_session.wait_change_session_status(hotplace::net::session_status_server_hello | hotplace::net::session_status_server_cert, 1);
    _test_case.assert(hotplace::errorcode_t::timeout == ret, testcase_name, "session status wait does not accept a partial status mask");

    hotplace::net::tls_session dtls_session(hotplace::net::session_type_t::dtls);
    auto& publisher = dtls_session.get_dtls_record_publisher();
    publisher.set_fragment_size(128);
    auto dtls_record = new hotplace::net::tls_record_handshake(&dtls_session);
    dtls_record->get_handshakes().add(new dtls_fragment_test_handshake(hotplace::net::tls_handshake_type_t::client_hello, &dtls_session, 100));
    dtls_record->get_handshakes().add(new dtls_fragment_test_handshake(hotplace::net::tls_handshake_type_t::server_hello, &dtls_session, 100));
    dtls_record->get_handshakes().add(new dtls_fragment_test_handshake(hotplace::net::tls_handshake_type_t::encrypted_extensions, &dtls_session, 100));

    size_t successful_fragments = 0;
    ret = publisher.publish(dtls_record, hotplace::net::from_client, [&](hotplace::net::tls_session*, hotplace::binary_t&) -> hotplace::return_t {
        ++successful_fragments;
        return hotplace::errorcode_t::success;
    });
    _test_case.assert((hotplace::errorcode_t::success == ret) && (successful_fragments > 2), testcase_name, "DTLS handshake publisher emits multiple fragments");

    size_t failed_send_calls = 0;
    ret = publisher.publish(dtls_record, hotplace::net::from_client, [&](hotplace::net::tls_session*, hotplace::binary_t&) -> hotplace::return_t {
        ++failed_send_calls;
        return (2 == failed_send_calls) ? hotplace::errorcode_t::internal_error : hotplace::errorcode_t::success;
    });
    _test_case.assert((hotplace::errorcode_t::internal_error == ret) && (2 == failed_send_calls), testcase_name,
                      "DTLS publisher propagates a mid-stream send failure and skips remaining fragments");
    dtls_record->release();
}

void testcase_gpt_secure_prosumer() {
    // Scenario under test: TLS secure prosumer queue consumption.
    // Action: enqueue application data.
    // Expected: fatal TLS alert terminates record processing.
    _test_case.begin("TLS secure prosumer queue consumption");

    test_secure_prosumer_fatal_alert(__FUNCTION__);
    test_secure_prosumer_queue_lifecycle(__FUNCTION__);
    test_secure_prosumer_transport_disconnect(__FUNCTION__);
    test_secure_prosumer_send_and_dtls(__FUNCTION__);
}
