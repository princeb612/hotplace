/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_loopback_tcp.cpp
 * @author GPT
 * @desc   TLS loopback TCP integration tests.
 */

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>

#include "testcase_gpt_common.hpp"

static return_t test_configure_tls12_loopback_renegotiation_session(tls_session& session) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);
    protection.set_flow(tls_flow_t::renegotiation);
    session.get_keyvalue().set(session_tls_version, tls1_2);
    session.get_session_info(from_client).begin_protection();
    session.get_session_info(from_server).begin_protection();
    session.get_session_info(from_client).set_active_cipher_suite(0xc02f);
    session.get_session_info(from_server).set_active_cipher_suite(0xc02f);
    session.update_session_status(session_status_server_key_exchange);
    session.update_session_status(session_status_client_key_exchange);

    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::client_key, binary_t(16, 0x11));
    secrets.assign(tls_secret_t::client_iv, binary_t(4, 0x21));
    secrets.assign(tls_secret_t::server_key, binary_t(16, 0x12));
    secrets.assign(tls_secret_t::server_iv, binary_t(4, 0x22));

    // Exercise the production TLS 1.2 key-block derivation. The resulting
    // renegotiation keys must remain staged until each direction's CCS.
    const binary_t master_secret(48, 0x31);
    const binary_t client_random(32, 0x41);
    const binary_t server_random(32, 0x42);
    secrets.assign(tls_secret_t::master, master_secret);
    secrets.assign(tls_secret_t::client_hello_random, client_random);
    secrets.assign(tls_secret_t::server_hello_random, server_random);
    return protection.calc_keyblock(hash_algorithm_t::sha2_256, master_secret, client_random, server_random, 0xc02f);
}

static return_t test_configure_tls12_live_peer_session(tls_session& session) {
    session.set_type(session_type_t::tls);
    return_t ret = test_configure_tls12_loopback_renegotiation_session(session);
    if (errorcode_t::success != ret) {
        return ret;
    }

    auto& protection = session.get_tls_protection();
    protection.set_flow(tls_flow_t::one_rtt);
    session.reset_session_status();
    session.get_keyvalue().set(session_tls1_2_ticket_resumed, 1);
    session.update_session_status(session_status_client_finished);
    session.update_session_status(session_status_server_finished);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    session.get_session_info(from_client).set_active_cipher_suite(0xc02f);
    session.get_session_info(from_server).set_active_cipher_suite(0xc02f);
    session.get_keyvalue().set(session_tls_version, tls1_2);
    session.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
    session.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
    protection.get_secrets().assign(tls_secret_t::client_verifydata, binary_t(12, 0x31));
    protection.get_secrets().assign(tls_secret_t::server_verifydata, binary_t(12, 0x42));
    session.set_recordno(from_client, 0);
    session.set_recordno(from_server, 0);
    return errorcode_t::success;
}

struct test_tls12_network_server_retirement_state {
    semaphore connected;
    semaphore disconnected;
    semaphore accepted_context_closed;
    std::atomic<socket_context_t*> transport;
    std::atomic<tls_session*> session;
    std::atomic<socket_t> accepted_fd;
    std::atomic<uint16> listen_port;
    std::atomic<uint32> disconnect_count;
    std::atomic<uint32> accepted_context_close_count;

    test_tls12_network_server_retirement_state()
        : transport(nullptr), session(nullptr), accepted_fd(INVALID_SOCKET), listen_port(0), disconnect_count(0), accepted_context_close_count(0) {}
};

class test_tls12_network_server_socket : public trial_tls_server_socket {
   public:
    explicit test_tls12_network_server_socket(test_tls12_network_server_retirement_state* state) : _state(state) {}

    virtual return_t open(socket_context_t** handle, unsigned int family, uint16 port) override {
        return_t ret = trial_tls_server_socket::open(handle, family, port);
        if ((errorcode_t::success == ret) && (nullptr != handle) && (nullptr != *handle) && (nullptr != _state)) {
            sockaddr_in listen_address = {};
            socklen_t listen_address_size = sizeof(listen_address);
            if (0 == getsockname((*handle)->fd, (sockaddr*)&listen_address, &listen_address_size)) {
                _state->listen_port.store(ntohs(listen_address.sin_port), std::memory_order_release);
            }
        }
        return ret;
    }

    virtual return_t close(socket_context_t* handle) override {
        const bool accepted_context = (nullptr != handle) && (nullptr != _state) && (handle->fd == _state->accepted_fd.load(std::memory_order_acquire));
        return_t ret = trial_tls_server_socket::close(handle);
        if (true == accepted_context) {
            _state->accepted_context_close_count.fetch_add(1, std::memory_order_acq_rel);
            _state->accepted_context_closed.signal();
        }
        return ret;
    }

   private:
    test_tls12_network_server_retirement_state* _state;
};

static return_t test_tls12_network_server_retirement_callback(uint32 type, uint32 data_count, void* data_array[], CALLBACK_CONTROL* callback_control,
                                                              void* user_context) {
    auto state = static_cast<test_tls12_network_server_retirement_state*>(user_context);
    if ((nullptr == state) || (nullptr == data_array) || (0 == data_count)) {
        return errorcode_t::invalid_parameter;
    }

    if (multiplexer_event_type_t::mux_connect == type) {
        auto socket_info = static_cast<netsocket_t*>(data_array[0]);
        if ((nullptr != socket_info) && (nullptr != socket_info->event_handle) && (nullptr != socket_info->event_handle->handle.session)) {
            auto session = socket_info->event_handle->handle.session;
            // Keep the test's observation pointer alive independently of the
            // network_session/socket_context_t owner, which may be released
            // by the event-loop thread as soon as session_closed() runs.
            session->addref();
            state->accepted_fd.store(socket_info->event_handle->fd, std::memory_order_release);
            state->transport.store(socket_info->event_handle, std::memory_order_release);
            state->session.store(session, std::memory_order_release);
            state->connected.signal();
        }
    } else if (multiplexer_event_type_t::mux_disconnect == type) {
        state->disconnect_count.fetch_add(1, std::memory_order_acq_rel);
        state->disconnected.signal();
    }

    return errorcode_t::success;
}

class test_live_tls12_client_socket : public trial_tls_client_socket {
   public:
    test_live_tls12_client_socket() : trial_tls_client_socket(tls1_2) {}

    return_t wait_for_hello_request(unsigned wto = 3000) { return _hello_request_processed.wait(wto); }

   protected:
    virtual return_t do_handshake() override { return test_configure_tls12_live_peer_session(*get_session()); }

    virtual return_t do_secure() override {
        return_t ret = secure_client_socket::do_secure();
        if (tls_flow_t::renegotiation == get_session()->get_tls_protection().get_flow()) {
            _hello_request_processed.signal();
        }
        return ret;
    }

   private:
    semaphore _hello_request_processed;
};

static void test_tls12_socket_hello_request_loopback_tcp() {
    // Scenario: a client and peer have an established, securely renegotiable
    // TLS 1.2 session. The peer sends a protected HelloRequest over loopback TCP.
    // Action: the real socket consumer processes it; client send() initiates
    // renegotiation; the peer captures and parses the protected ClientHello,
    // then sends a protected no_renegotiation warning.
    // Expected: the ClientHello crosses the TCP connection before the refusal;
    // the client returns negotiation_failure and retires the connection.
    // This is a live TCP/record/handshake-message test, not a complete peer
    // handshake or interoperability test: the peer flight is deliberately
    // limited to HelloRequest and no_renegotiation.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 peer HelloRequest and client ClientHello traverse a loopback TCP connection");

    tls_session peer_session;
    return_t ret = test_configure_tls12_live_peer_session(peer_session);
    _test_case.test(ret, function_name, "prepare the loopback peer's established TLS 1.2 record state");
    if (errorcode_t::success != ret) {
        return;
    }

    binary_t hello_request_wire;
    {
        tls_record_builder builder;
        tls_record* record = builder.set(&peer_session).set(tls_content_type_t::handshake).set(from_server).construct().build();
        _test_case.assert(nullptr != record, function_name, "construct the protected server handshake record");
        if (nullptr == record) {
            return;
        }
        record->add(tls_handshake_type_t::hello_request, &peer_session);
        ret = record->write(from_server, hello_request_wire);
        record->release();
        _test_case.test(ret, function_name, "serialize the protected HelloRequest record");
        if (errorcode_t::success != ret) {
            return;
        }
    }

    binary_t refusal_wire;
    {
        tls_record_alert refusal(&peer_session, tls_alertlevel_t::warning, tls_alertdesc_t::no_renegotiation);
        ret = refusal.write(from_server, refusal_wire);
        _test_case.test(ret, function_name, "serialize the protected peer no_renegotiation warning");
        if (errorcode_t::success != ret) {
            return;
        }
    }

    naive_tcp_server_socket listener;
    socket_context_t* listen_context = nullptr;
    ret = listener.open(&listen_context, AF_INET, 0);
    _test_case.test(ret, function_name, "open an ephemeral loopback TCP listener");
    if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
        return;
    }

    sockaddr_in listen_address = {};
    socklen_t listen_address_size = sizeof(listen_address);
    int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
    _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
    if (0 != name_ret) {
        listener.close(listen_context);
        return;
    }
    const uint16 port = ntohs(listen_address.sin_port);

    test_live_tls12_client_socket client;
    client.set_wto(3000);
    ret = client.connect("127.0.0.1", port, 3);
    _test_case.test(ret, function_name, "connect the TLS client socket to the loopback peer");
    if (errorcode_t::success != ret) {
        listener.close(listen_context);
        return;
    }

    socket_t accepted_socket = INVALID_SOCKET;
    sockaddr_storage_t accepted_address = {};
    socklen_t accepted_address_size = sizeof(accepted_address);
    ret = listener.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
    _test_case.test(ret, function_name, "accept the actual client TCP connection");
    if (errorcode_t::success != ret) {
        client.close();
        listener.close(listen_context);
        return;
    }
    socket_context_t peer_transport(accepted_socket, closesocket_ondestroy);

    std::atomic<bool> peer_hello_sent(false);
    std::atomic<bool> peer_client_hello_parsed(false);
    std::atomic<bool> peer_refusal_sent(false);
    std::atomic<bool> client_send_finished(false);
    std::atomic<bool> refusal_status_hook_entered(false);
    std::atomic<bool> release_refusal_status_hook(false);
    constexpr uint32 completed_status = session_status_client_finished | session_status_server_finished;
    client.get_session()->set_hook_change_session_status([&](tls_session*, uint32 status) -> return_t {
        if (completed_status == status) {
            refusal_status_hook_entered.store(true, std::memory_order_release);
            while (false == release_refusal_status_hook.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        return errorcode_t::success;
    });
    binary_t captured_client_hello;

    std::thread peer([&]() {
        auto send_all = [&](const binary_t& wire) -> bool {
            size_t offset = 0;
            while (offset < wire.size()) {
                size_t sent = 0;
                return_t send_ret = listener.send(&peer_transport, (const char*)wire.data() + offset, wire.size() - offset, &sent);
                if ((errorcode_t::success != send_ret) || (0 == sent)) {
                    return false;
                }
                offset += sent;
            }
            return true;
        };

        auto read_exact = [&](char* output, size_t size) -> bool {
            size_t offset = 0;
            while (offset < size) {
                size_t received = 0;
                return_t read_ret = listener.read(&peer_transport, 0, output + offset, size - offset, &received);
                if ((errorcode_t::success != read_ret) || (0 == received)) {
                    return false;
                }
                offset += received;
            }
            return true;
        };

        if (false == send_all(hello_request_wire)) {
            return;
        }
        peer_hello_sent.store(true);

        char header[5] = {};
        if (false == read_exact(header, sizeof(header))) {
            return;
        }
        const size_t fragment_size = (static_cast<size_t>(static_cast<byte_t>(header[3])) << 8) | static_cast<size_t>(static_cast<byte_t>(header[4]));
        captured_client_hello.resize(sizeof(header) + fragment_size);
        memcpy(captured_client_hello.data(), header, sizeof(header));
        if ((0 == fragment_size) || (false == read_exact((char*)captured_client_hello.data() + sizeof(header), fragment_size))) {
            captured_client_hello.clear();
            return;
        }
        if ((0x16 != static_cast<byte_t>(header[0])) || (0x03 != static_cast<byte_t>(header[1])) || (0x03 != static_cast<byte_t>(header[2]))) {
            captured_client_hello.clear();
            return;
        }
        tls_record_builder parser;
        tls_record* client_record = parser.set(&peer_session).set(static_cast<tls_content_type_t>(captured_client_hello[0])).set(from_client).construct().build();
        if (nullptr == client_record) {
            captured_client_hello.clear();
            return;
        }
        size_t client_hello_pos = 0;
        return_t parse_ret = client_record->read(from_client, captured_client_hello.data(), captured_client_hello.size(), client_hello_pos);
        auto* handshake_record = static_cast<tls_record_handshake*>(client_record);
        tls_handshake* first_handshake = (nullptr != handshake_record) ? handshake_record->get_handshakes().getat(0) : nullptr;
        const bool parsed_client_hello = (nullptr != first_handshake) && (tls_handshake_type_t::client_hello == first_handshake->get_type());
        client_record->release();
        if ((errorcode_t::success != parse_ret) || (captured_client_hello.size() != client_hello_pos) || (false == parsed_client_hello)) {
            captured_client_hello.clear();
            return;
        }
        peer_client_hello_parsed.store(true);
        if (true == send_all(refusal_wire)) {
            peer_refusal_sent.store(true);
            const auto close_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while ((false == client_send_finished.load()) && (std::chrono::steady_clock::now() < close_deadline)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    });

    return_t hello_request_ret = client.wait_for_hello_request(5000);
    _test_case.test(hello_request_ret, function_name, "process the peer HelloRequest through the real socket consumer");

    const binary_t application_data{'l', 'i', 'v', 'e'};
    size_t sent = 99;
    return_t send_ret = errorcode_t::internal_error;
    std::thread sender([&]() {
        send_ret = client.send((const char*)application_data.data(), application_data.size(), &sent);
        client_send_finished.store(true);
    });

    const auto hook_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while ((false == refusal_status_hook_entered.load(std::memory_order_acquire)) && (std::chrono::steady_clock::now() < hook_deadline)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const bool hook_entered = refusal_status_hook_entered.load(std::memory_order_acquire);
    _test_case.assert(hook_entered, function_name, "reach the status hook after the refusal state has been published");
    if (hook_entered) {
        const uint32 status = client.get_session()->get_session_status();
        const tls_flow_t flow = client.get_session()->get_tls_protection().get_flow();
        const tls_handshake_type_t client_handshake = client.get_session()->get_session_info(from_client).get_status();
        const tls_handshake_type_t server_handshake = client.get_session()->get_session_info(from_server).get_status();
        _test_case.assert(completed_status == status, function_name, "publish only the completed Finished status before notifying the composer");
        _test_case.assert(tls_flow_t::one_rtt == flow, function_name, "restore the TLS flow before notifying the composer");
        _test_case.assert(tls_handshake_type_t::finished == client_handshake, function_name, "restore the client handshake cursor before notifying the composer");
        _test_case.assert(tls_handshake_type_t::finished == server_handshake, function_name, "restore the server handshake cursor before notifying the composer");
    }
    release_refusal_status_hook.store(true, std::memory_order_release);
    sender.join();

    _test_case.assert(errorcode_t::negotiation_failure == send_ret, function_name, "surface the peer refusal after the real ClientHello write (actual return 0x%08x)",
                      static_cast<uint32>(send_ret));
    _test_case.assert(0 == sent, function_name, "do not report application data sent after peer refusal");

    peer.join();

    _test_case.assert(peer_hello_sent.load(), function_name, "send HelloRequest through the accepted TCP connection");
    _test_case.assert(peer_client_hello_parsed.load(), function_name, "decrypt and parse the ClientHello received over TCP before refusing renegotiation");
    _test_case.assert(peer_refusal_sent.load(), function_name, "send the protected no_renegotiation warning after ClientHello");
    _test_case.assert(client.get_session()->is_terminal(), function_name, "retire the session after the peer refuses renegotiation");

    client.close();
    listener.close(listen_context);
}

static void test_tls12_server_concurrent_application_sends_loopback_tcp() {
    // Scenario: an established TLS 1.2 server sends application data to a
    // connected peer while two application threads call send() concurrently.
    // Action: serialize both protected records through trial_tls_server_socket,
    // receive the actual TCP byte stream, and decrypt both records in wire order.
    // Expected: both calls succeed exactly once, both plaintexts arrive intact,
    // and the sender/receiver directional record counters advance twice.
    // The established TLS state is seeded; this is a live TCP record-delivery
    // test, not a full TLS handshake or renegotiation interoperability test.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 concurrent server application sends deliver two protected records over loopback TCP");

    tls_session server_session;
    tls_session peer_session;
    return_t ret = test_configure_tls12_live_peer_session(server_session);
    _test_case.test(ret, function_name, "prepare the established TLS 1.2 server session");
    if (errorcode_t::success != ret) {
        return;
    }
    ret = test_configure_tls12_live_peer_session(peer_session);
    _test_case.test(ret, function_name, "prepare the matching TLS 1.2 peer read state");
    if (errorcode_t::success != ret) {
        return;
    }

    trial_tls_server_socket server_socket(tls1_2, tls1_2);
    socket_context_t* listen_context = nullptr;
    ret = server_socket.open(&listen_context, AF_INET, 0);
    _test_case.test(ret, function_name, "open an ephemeral loopback TCP listener");
    if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
        return;
    }

    sockaddr_in listen_address = {};
    socklen_t listen_address_size = sizeof(listen_address);
    int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
    _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
    if (0 != name_ret) {
        server_socket.close(listen_context);
        return;
    }

    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);
    ret = peer_transport.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
    _test_case.test(ret, function_name, "connect the raw TCP peer");
    if (errorcode_t::success != ret) {
        server_socket.close(listen_context);
        return;
    }

    socket_t accepted_socket = INVALID_SOCKET;
    sockaddr_storage_t accepted_address = {};
    socklen_t accepted_address_size = sizeof(accepted_address);
    ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
    _test_case.test(ret, function_name, "accept the peer TCP connection");
    if (errorcode_t::success != ret) {
        peer_transport.close();
        server_socket.close(listen_context);
        return;
    }

    socket_context_t server_transport(accepted_socket, closesocket_ondestroy);
    // socket_context_t releases its TLS session on destruction. Keep the
    // stack-owned session's initial self-reference alive across that release.
    server_session.addref();
    server_transport.handle.session = &server_session;

    const binary_t payload_a{'s', 'e', 'n', 'd', 'e', 'r', '-', 'a'};
    const binary_t payload_b{'s', 'e', 'n', 'd', 'e', 'r', '-', 'b'};
    return_t send_ret_a = errorcode_t::internal_error;
    return_t send_ret_b = errorcode_t::internal_error;
    size_t sent_a = 99;
    size_t sent_b = 99;
    std::atomic<unsigned> ready(0);
    std::atomic<bool> start(false);

    std::thread sender_a([&]() {
        ready.fetch_add(1, std::memory_order_release);
        while (false == start.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        send_ret_a = server_socket.send(&server_transport, (const char*)payload_a.data(), payload_a.size(), &sent_a);
    });
    std::thread sender_b([&]() {
        ready.fetch_add(1, std::memory_order_release);
        while (false == start.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        send_ret_b = server_socket.send(&server_transport, (const char*)payload_b.data(), payload_b.size(), &sent_b);
    });

    while (2 != ready.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    sender_a.join();
    sender_b.join();

    _test_case.assert(errorcode_t::success == send_ret_a, function_name, "complete concurrent sender A (actual return 0x%08x)", static_cast<uint32>(send_ret_a));
    _test_case.assert(errorcode_t::success == send_ret_b, function_name, "complete concurrent sender B (actual return 0x%08x)", static_cast<uint32>(send_ret_b));
    _test_case.assert(payload_a.size() == sent_a, function_name, "report the full sender A plaintext length");
    _test_case.assert(payload_b.size() == sent_b, function_name, "report the full sender B plaintext length");
    _test_case.assert(2 == server_session.get_recordno(from_server), function_name, "serialize exactly two server-direction application records");

    auto read_exact = [&](char* output, size_t size) -> bool {
        size_t offset = 0;
        while (offset < size) {
            size_t received = 0;
            return_t read_ret = peer_transport.read(output + offset, size - offset, &received);
            if ((errorcode_t::success != read_ret) && (errorcode_t::more_data != read_ret)) {
                return false;
            }
            if (0 == received) {
                return false;
            }
            offset += received;
        }
        return true;
    };

    bool received_a = false;
    bool received_b = false;
    tls_record_application_data reader(&peer_session);
    for (size_t i = 0; i < 2; ++i) {
        byte_t header[5] = {};
        const bool header_read = read_exact((char*)header, sizeof(header));
        _test_case.assert(header_read, function_name, "receive a complete TLS record header from TCP");
        if (false == header_read) {
            break;
        }

        const size_t fragment_size = (static_cast<size_t>(header[3]) << 8) | static_cast<size_t>(header[4]);
        _test_case.assert((0x17 == header[0]) && (0x03 == header[1]) && (0x03 == header[2]) && (0 != fragment_size), function_name,
                          "receive a TLS 1.2 application-data record with a non-empty fragment");
        if ((0x17 != header[0]) || (0x03 != header[1]) || (0x03 != header[2]) || (0 == fragment_size)) {
            break;
        }

        binary_t wire(sizeof(header) + fragment_size);
        memcpy(wire.data(), header, sizeof(header));
        const bool body_read = read_exact((char*)wire.data() + sizeof(header), fragment_size);
        _test_case.assert(body_read, function_name, "receive the complete protected record fragment");
        if (false == body_read) {
            break;
        }

        size_t pos = 0;
        ret = reader.read(from_server, wire.data(), wire.size(), pos);
        _test_case.test(ret, function_name, "authenticate and decrypt the received application-data record");
        if ((errorcode_t::success != ret) || (wire.size() != pos)) {
            break;
        }

        const binary_t& plaintext = reader.get_binary();
        if ((payload_a == plaintext) && (false == received_a)) {
            received_a = true;
        } else if ((payload_b == plaintext) && (false == received_b)) {
            received_b = true;
        } else {
            _test_case.assert(false, function_name, "deliver each expected sender payload exactly once");
        }
    }

    _test_case.assert(received_a && received_b, function_name, "decrypt both concurrent sender payloads independent of wire order");
    _test_case.assert(2 == peer_session.get_recordno(from_server), function_name, "advance the peer read sequence exactly twice");
    _test_case.assert(2 == server_session.get_recordno(from_server), function_name, "keep the server write sequence aligned with the two delivered records");

    peer_transport.close();
    server_socket.close(listen_context);
}

static return_t test_write_tls12_renegotiation_client_hello_record(tls_session& session, binary_t& wire) {
    tls_record_builder builder;
    tls_record* record = builder.set(&session).set(tls_content_type_t::handshake).set(from_client).construct().build();
    if (nullptr == record) {
        return errorcode_t::internal_error;
    }

    record->add(tls_handshake_type_t::client_hello, &session, [](tls_handshake* handshake) -> return_t {
        auto hello = static_cast<tls_handshake_client_hello*>(handshake);
        return_t ret = hello->add_ciphersuite(0xc02f);
        if (errorcode_t::success != ret) {
            return ret;
        }

        // RFC 5746 requires the renegotiation_info extension on a
        // renegotiating ClientHello; its writer uses the session's
        // client_verifydata for the verify_connection binding.
        hello->get_extensions().add(new tls_extension_renegotiation_info(hello));

        // Advertise the P-256 group used by this TLS 1.2 ECDHE_RSA fixture.
        auto supported_groups = new tls_extension_supported_groups(hello);
        supported_groups->add(tls_group_t::secp256r1);
        hello->get_extensions().add(supported_groups);

        // Advertise RSA/SHA-256 for the TLS 1.2 ECDHE_RSA ServerKeyExchange.
        auto signature_algorithms = new tls_extension_signature_algorithms(hello);
        signature_algorithms->add(tls_sigscheme_t::rsa_pkcs1_sha256);
        hello->get_extensions().add(signature_algorithms);

        auto supported_versions = new tls_extension_client_supported_versions(hello);
        supported_versions->add(tls1_2);
        hello->get_extensions().add(supported_versions);
        return errorcode_t::success;
    });

    return_t ret = record->write(from_client, wire);
    record->release();
    return ret;
}

static void test_tls12_server_initiated_renegotiation_loopback_tcp_case() {
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 server full renegotiation completes over loopback TCP");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);

    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    test_live_tls12_client_socket client;
    client.set_wto(5000);

    std::thread reader;
    std::thread server_sender;
    tls_session* server_session = nullptr;
    tls_session* client_session = nullptr;
    bool client_connected = false;
    return_t client_send_ret = errorcode_t::internal_error;
    return_t server_send_ret = errorcode_t::internal_error;
    return_t reader_ret = errorcode_t::success;
    size_t client_sent = 0;
    size_t server_sent = 0;
    const binary_t client_payload{'c', 'l', 'i', 'e', 'n', 't'};
    const binary_t server_payload{'s', 'e', 'r', 'v', 'e', 'r'};
    std::atomic<bool> server_sender_finished(false);
    std::atomic<bool> peer_application_record_processed(false);
    auto close_client = [&]() -> void {
        if (client_connected) {
            client.close();
            client_connected = false;
            client_session = nullptr;
        }
    };

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the TLS 1.2 loopback listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = client.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the TLS client with a seeded established TLS 1.2 session");
        if (errorcode_t::success != ret) {
            break;
        }
        client_connected = true;
        client_session = client.get_session();

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the client TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server session");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;
        server_session = server_transport->handle.session;

        // Suppress the production callback while the fixture publishes the
        // established Finished state, then restore the real server composer.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });
        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 state");
        if (errorcode_t::success != ret) {
            break;
        }

        // This is a full renegotiation, not a new-connection RFC 5077
        // ticket resumption. The shared live-session fixture defaults this
        // flag for other tests, so explicitly clear it at both endpoints.
        server_session->get_keyvalue().set(session_tls1_2_ticket_resumed, 0);
        client_session->get_keyvalue().set(session_tls1_2_ticket_resumed, 0);

        auto server_send_wire = [&server_socket, server_transport](tls_session*, binary_t& wire) -> return_t {
            size_t sent = 0;
            return_t send_ret = server_socket.naive_tcp_server_socket::send(server_transport, (const char*)wire.data(), wire.size(), &sent);
            if (errorcode_t::success != send_ret) {
                return send_ret;
            }
            return (sent == wire.size()) ? errorcode_t::success : errorcode_t::send_failure;
        };
        server_session->set_hook_param(server_transport);
        server_session->set_hook_change_session_status([server_send_wire](tls_session* current, uint32 status) -> return_t {
            return current->get_tls_composer()->session_status_changed(status, from_server, 1000, server_send_wire);
        });

        constexpr uint64 sequence_max = ~static_cast<uint64>(0);
        constexpr uint64 sequence_reserve = 65535;
        constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
        server_session->set_recordno(from_server, sequence_reserve_start);
        client_session->set_recordno(from_server, sequence_reserve_start);

        reader = std::thread([&]() {
            auto read_exact = [&](char* output, size_t size) -> bool {
                size_t offset = 0;
                while (offset < size) {
                    size_t received = 0;
                    return_t read_ret = server_socket.naive_tcp_server_socket::read(server_transport, 0, output + offset, size - offset, &received);
                    if ((errorcode_t::success != read_ret) && (errorcode_t::more_data != read_ret)) {
                        reader_ret = read_ret;
                        return false;
                    }
                    if (0 == received) {
                        reader_ret = errorcode_t::closed;
                        return false;
                    }
                    offset += received;
                }
                return true;
            };

            while (false == peer_application_record_processed.load(std::memory_order_acquire)) {
                byte_t header[5] = {};
                if (false == read_exact((char*)header, sizeof(header))) {
                    break;
                }

                const size_t fragment_size = (static_cast<size_t>(header[3]) << 8) | static_cast<size_t>(header[4]);
                if (0 == fragment_size) {
                    reader_ret = errorcode_t::bad_format;
                    break;
                }

                binary_t wire(sizeof(header) + fragment_size);
                memcpy(wire.data(), header, sizeof(header));
                if (false == read_exact((char*)wire.data() + sizeof(header), fragment_size)) {
                    break;
                }

                size_t input_size = wire.size();
                reader_ret = server_socket.read(server_transport, tls_io_flag_t::read_bio_write, (char*)wire.data(), wire.size(), &input_size);
                if (errorcode_t::success != reader_ret) {
                    break;
                }
                if (0x17 == header[0]) {
                    peer_application_record_processed.store(true, std::memory_order_release);
                }
            }
        });

        server_sender = std::thread([&]() {
            server_send_ret = server_socket.send(server_transport, (const char*)server_payload.data(), server_payload.size(), &server_sent);
            server_sender_finished.store(true, std::memory_order_release);
        });

        ret = client.wait_for_hello_request();
        _test_case.test(ret, function_name, "receive the real server HelloRequest through the client socket consumer");
        if (errorcode_t::success != ret) {
            close_client();
            break;
        }
        _test_case.assert(tls_flow_t::renegotiation == client_session->get_tls_protection().get_flow(), function_name,
                          "move the client into TLS 1.2 renegotiation after HelloRequest");
        _test_case.assert(false == server_sender_finished.load(std::memory_order_acquire), function_name,
                          "keep the server application sender pending until the renegotiation completes");

        client_send_ret = client.send((const char*)client_payload.data(), client_payload.size(), &client_sent);
        _test_case.test(client_send_ret, function_name, "complete the client side of the live renegotiation and send its application payload");
        if (errorcode_t::success != client_send_ret) {
            close_client();
        }
    } while (false);

    if (server_sender.joinable()) {
        server_sender.join();
    }

    if ((errorcode_t::success == client_send_ret) && (errorcode_t::success == server_send_ret)) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while ((false == peer_application_record_processed.load(std::memory_order_acquire)) && (std::chrono::steady_clock::now() < deadline)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    if ((false == peer_application_record_processed.load(std::memory_order_acquire)) && client_connected) {
        close_client();
    }
    if (reader.joinable()) {
        reader.join();
    }

    if ((nullptr != server_session) && (nullptr != client_session)) {
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (server_session->get_session_status() & completed_status), function_name,
                          "publish both Finished messages on the server session");
        _test_case.assert(completed_status == (client_session->get_session_status() & completed_status), function_name,
                          "publish both Finished messages on the client session");
    }

    _test_case.assert(errorcode_t::success == server_send_ret, function_name,
                      "retry and send the original server application payload exactly once (actual return 0x%08x)", static_cast<uint32>(server_send_ret));
    _test_case.assert(server_payload.size() == server_sent, function_name, "report the complete server application payload length");
    _test_case.assert(errorcode_t::success == client_send_ret, function_name, "send the client application payload after renegotiation (actual return 0x%08x)",
                      static_cast<uint32>(client_send_ret));
    _test_case.assert(client_payload.size() == client_sent, function_name, "report the complete client application payload length");
    _test_case.assert(true == peer_application_record_processed.load(std::memory_order_acquire), function_name,
                      "receive the client application record over TCP after the handshake");
    if (true == peer_application_record_processed.load(std::memory_order_acquire)) {
        _test_case.assert(errorcode_t::success == reader_ret, function_name, "process the client application record through the production TLS read path");
    }

    if ((errorcode_t::success == server_send_ret) && client_connected) {
        char received[32] = {};
        size_t received_size = 0;
        return_t read_ret = client.read(received, sizeof(received), &received_size);
        _test_case.test(read_ret, function_name, "read and decrypt the server application payload at the client");
        _test_case.assert((server_payload.size() == received_size) && (0 == memcmp(received, server_payload.data(), server_payload.size())), function_name,
                          "deliver the original server application payload exactly once");
    }

    if ((errorcode_t::success == client_send_ret) && (true == peer_application_record_processed.load(std::memory_order_acquire)) && (nullptr != server_transport)) {
        char received[32] = {};
        size_t received_size = 0;
        return_t read_ret = server_socket.read(server_transport, tls_io_flag_t::read_ssl_read, received, sizeof(received), &received_size);
        _test_case.test(read_ret, function_name, "consume and decrypt the client application payload at the server");
        _test_case.assert((client_payload.size() == received_size) && (0 == memcmp(received, client_payload.data(), client_payload.size())), function_name,
                          "deliver the client application payload exactly once");
    }

    if ((errorcode_t::success == server_send_ret) && (errorcode_t::success == client_send_ret) &&
        (true == peer_application_record_processed.load(std::memory_order_acquire))) {
        _test_case.assert(2 == server_session->get_recordno(from_server), function_name, "use one new-key Finished record and exactly one server application record");
        _test_case.assert(2 == client_session->get_recordno(from_server), function_name,
                          "keep the client read sequence aligned with the server Finished and application records");
        _test_case.assert(2 == client_session->get_recordno(from_client), function_name, "use one new-key Finished record and exactly one client application record");
        _test_case.assert(2 == server_session->get_recordno(from_client), function_name,
                          "keep the server read sequence aligned with the client Finished and application records");
    }

    close_client();
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    } else if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_initiated_renegotiation_loopback_tcp() { test_tls12_server_initiated_renegotiation_loopback_tcp_case(); }

static void test_tls12_client_initiated_renegotiation_loopback_tcp() {
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 client full renegotiation starts at the application-data reserve over loopback TCP");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);

    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    test_live_tls12_client_socket client;
    client.set_wto(5000);

    std::thread reader;
    tls_session* server_session = nullptr;
    tls_session* client_session = nullptr;
    bool client_connected = false;
    return_t client_send_ret = errorcode_t::internal_error;
    return_t reader_ret = errorcode_t::success;
    size_t client_sent = 0;
    const binary_t client_payload{'c', 'l', 'i', '-', 'f', 'u', 'l', 'l'};
    std::atomic<bool> peer_application_record_processed(false);
    auto close_client = [&]() -> void {
        if (client_connected) {
            client.close();
            client_connected = false;
            client_session = nullptr;
        }
    };

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the TLS 1.2 loopback listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = client.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the TLS client with a seeded established TLS 1.2 session");
        if (errorcode_t::success != ret) {
            break;
        }
        client_connected = true;
        client_session = client.get_session();

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the client TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server session");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;
        server_session = server_transport->handle.session;

        // Suppress the production callback while the fixture publishes the
        // established Finished state, then restore the real server composer.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });
        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 state");
        if (errorcode_t::success != ret) {
            break;
        }

        // Force a full renegotiation; this is not RFC 5077 ticket resumption.
        server_session->get_keyvalue().set(session_tls1_2_ticket_resumed, 0);
        client_session->get_keyvalue().set(session_tls1_2_ticket_resumed, 0);

        auto server_send_wire = [&server_socket, server_transport](tls_session*, binary_t& wire) -> return_t {
            size_t sent = 0;
            return_t send_ret = server_socket.naive_tcp_server_socket::send(server_transport, (const char*)wire.data(), wire.size(), &sent);
            if (errorcode_t::success != send_ret) {
                return send_ret;
            }
            return (sent == wire.size()) ? errorcode_t::success : errorcode_t::send_failure;
        };
        server_session->set_hook_param(server_transport);
        server_session->set_hook_change_session_status([server_send_wire](tls_session* current, uint32 status) -> return_t {
            return current->get_tls_composer()->session_status_changed(status, from_server, 1000, server_send_wire);
        });

        constexpr uint64 sequence_max = ~static_cast<uint64>(0);
        constexpr uint64 sequence_reserve = 65535;
        constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
        client_session->set_recordno(from_client, sequence_reserve_start);
        server_session->set_recordno(from_client, sequence_reserve_start);

        reader = std::thread([&]() {
            auto read_exact = [&](char* output, size_t size) -> bool {
                size_t offset = 0;
                while (offset < size) {
                    size_t received = 0;
                    return_t read_ret = server_socket.naive_tcp_server_socket::read(server_transport, 0, output + offset, size - offset, &received);
                    if ((errorcode_t::success != read_ret) && (errorcode_t::more_data != read_ret)) {
                        reader_ret = read_ret;
                        return false;
                    }
                    if (0 == received) {
                        reader_ret = errorcode_t::closed;
                        return false;
                    }
                    offset += received;
                }
                return true;
            };

            while (false == peer_application_record_processed.load(std::memory_order_acquire)) {
                byte_t header[5] = {};
                if (false == read_exact((char*)header, sizeof(header))) {
                    break;
                }

                const size_t fragment_size = (static_cast<size_t>(header[3]) << 8) | static_cast<size_t>(header[4]);
                if (0 == fragment_size) {
                    reader_ret = errorcode_t::bad_format;
                    break;
                }

                binary_t wire(sizeof(header) + fragment_size);
                memcpy(wire.data(), header, sizeof(header));
                if (false == read_exact((char*)wire.data() + sizeof(header), fragment_size)) {
                    break;
                }

                size_t input_size = wire.size();
                reader_ret = server_socket.read(server_transport, tls_io_flag_t::read_bio_write, (char*)wire.data(), wire.size(), &input_size);
                if (errorcode_t::success != reader_ret) {
                    break;
                }
                if (0x17 == header[0]) {
                    peer_application_record_processed.store(true, std::memory_order_release);
                }
            }
        });

        _test_case.assert(sequence_reserve_start == client_session->get_recordno(from_client), function_name,
                          "place the client write sequence at the first reserved value");
        _test_case.assert(sequence_reserve_start == server_session->get_recordno(from_client), function_name,
                          "align the server read sequence with the client's reserved write sequence");

        client_send_ret = client.send((const char*)client_payload.data(), client_payload.size(), &client_sent);
        _test_case.test(client_send_ret, function_name, "complete a client-triggered full renegotiation and retry the original application payload");
        if (errorcode_t::success != client_send_ret) {
            close_client();
        }
    } while (false);

    if ((errorcode_t::success == client_send_ret) && (false == peer_application_record_processed.load(std::memory_order_acquire))) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while ((false == peer_application_record_processed.load(std::memory_order_acquire)) && (std::chrono::steady_clock::now() < deadline)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    if ((false == peer_application_record_processed.load(std::memory_order_acquire)) && client_connected) {
        close_client();
    }
    if (reader.joinable()) {
        reader.join();
    }

    if ((nullptr != server_session) && (nullptr != client_session)) {
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (server_session->get_session_status() & completed_status), function_name,
                          "publish both Finished messages on the server session");
        _test_case.assert(completed_status == (client_session->get_session_status() & completed_status), function_name,
                          "publish both Finished messages on the client session");
        _test_case.assert(tls_flow_t::one_rtt == server_session->get_tls_protection().get_flow(), function_name,
                          "restore the server to one_rtt after the full renegotiation");
        _test_case.assert(tls_flow_t::one_rtt == client_session->get_tls_protection().get_flow(), function_name,
                          "restore the client to one_rtt after the full renegotiation");
        const uint32 full_handshake_status =
            session_status_server_hello | session_status_server_cert | session_status_server_key_exchange | session_status_server_hello_done;
        _test_case.assert(full_handshake_status == (server_session->get_session_status() & full_handshake_status), function_name,
                          "complete the full server flight rather than an abbreviated handshake");
        _test_case.assert(full_handshake_status == (client_session->get_session_status() & full_handshake_status), function_name,
                          "process ServerHello, Certificate, ServerKeyExchange, and ServerHelloDone at the client");
        _test_case.assert(0 == server_session->get_keyvalue().get(session_tls1_2_ticket_resumed), function_name,
                          "keep the server renegotiation on the full-handshake path");
        _test_case.assert(0 == client_session->get_keyvalue().get(session_tls1_2_ticket_resumed), function_name,
                          "keep the client renegotiation on the full-handshake path");
    }

    _test_case.assert(errorcode_t::success == client_send_ret, function_name,
                      "return success after the original client application payload is retried (actual return 0x%08x)", static_cast<uint32>(client_send_ret));
    _test_case.assert(client_payload.size() == client_sent, function_name, "report the complete original client application payload length");
    _test_case.assert(true == peer_application_record_processed.load(std::memory_order_acquire), function_name, "receive the retried client application record over TCP");
    if (true == peer_application_record_processed.load(std::memory_order_acquire)) {
        _test_case.assert(errorcode_t::success == reader_ret, function_name, "process the client application record through the production TLS read path");
    }

    if ((errorcode_t::success == client_send_ret) && (true == peer_application_record_processed.load(std::memory_order_acquire)) && (nullptr != server_transport)) {
        char received[32] = {};
        size_t received_size = 0;
        return_t read_ret = server_socket.read(server_transport, tls_io_flag_t::read_ssl_read, received, sizeof(received), &received_size);
        _test_case.test(read_ret, function_name, "consume and decrypt the retried client application payload at the server");
        _test_case.assert((client_payload.size() == received_size) && (0 == memcmp(received, client_payload.data(), client_payload.size())), function_name,
                          "deliver the original client application payload exactly once");
    }

    if ((errorcode_t::success == client_send_ret) && (true == peer_application_record_processed.load(std::memory_order_acquire)) && (nullptr != server_session) &&
        (nullptr != client_session)) {
        _test_case.assert(2 == client_session->get_recordno(from_client), function_name,
                          "use one new-key Finished record and exactly one retried client application record");
        _test_case.assert(2 == server_session->get_recordno(from_client), function_name,
                          "keep the server read sequence aligned with the client Finished and application records");
        _test_case.assert(1 == client_session->get_recordno(from_server), function_name, "read the single server Finished record in the new protection state");
        _test_case.assert(1 == server_session->get_recordno(from_server), function_name, "send the single server Finished record in the new protection state");
    }

    close_client();
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    } else if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_send_retires_after_peer_fatal_alert_loopback_tcp() {
    // Scenario: a peer-initiated TLS 1.2 renegotiation arrives while two
    // application sender threads are entering send() concurrently.
    // Action: pause ClientHello status publication while both senders enter,
    // then release the receive path and deliver a protected fatal alert.
    // Expected: both senders retire without serializing application records.
    // The established session is seeded; this is not a full renegotiation.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 peer ClientHello races two concurrent server application sends");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);

    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);
    tls_session peer_session;

    std::thread client_hello_reader;
    std::thread sender_a;
    std::thread sender_b;
    std::atomic<bool> client_hello_hook_entered(false);
    std::atomic<bool> client_hello_reader_started(false);
    std::atomic<bool> release_client_hello_hook(false);
    std::atomic<bool> server_flight_started(false);
    std::atomic<unsigned> senders_started(0);
    std::atomic<bool> senders_start(false);
    return_t client_hello_read_ret = errorcode_t::internal_error;
    return_t send_ret_a = errorcode_t::internal_error;
    return_t send_ret_b = errorcode_t::internal_error;
    size_t sent_a = 99;
    size_t sent_b = 99;
    tls_session* server_session = nullptr;
    uint64 initial_server_recordno = 0;

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the loopback TLS server listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = peer_transport.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the raw TCP peer");
        if (errorcode_t::success != ret) {
            break;
        }

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the peer TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server socket context");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;  // owned by server_transport

        server_session = server_transport->handle.session;

        // Suppress the production status callback while seeding the established
        // state; the fixture's Finished status updates must not compose a flight.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });

        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }
        ret = test_configure_tls12_live_peer_session(peer_session);
        _test_case.test(ret, function_name, "seed the peer's matching TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }

        auto send_handshake_wire = [&](tls_session*, binary_t& wire) -> return_t {
            server_flight_started.store(true, std::memory_order_release);
            size_t sent = 0;
            return_t wire_ret = server_socket.naive_tcp_server_socket::send(server_transport, (char*)wire.data(), wire.size(), &sent);
            if (errorcode_t::success != wire_ret) {
                return wire_ret;
            }
            if (sent != wire.size()) {
                return errorcode_t::send_failure;
            }
            return errorcode_t::success;
        };
        server_session->set_hook_change_session_status([&](tls_session* session, uint32 status) -> return_t {
            if (0 != (status & session_status_client_hello)) {
                client_hello_hook_entered.store(true, std::memory_order_release);
                while (false == release_client_hello_hook.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
            }
            // Preserve the production tls_accept() status callback: the test
            // adds a deterministic pause but must still compose/send the flight.
            return session->get_tls_composer()->session_status_changed(status, from_server, 1000, send_handshake_wire);
        });

        binary_t client_hello_wire;
        ret = test_write_tls12_renegotiation_client_hello_record(peer_session, client_hello_wire);
        _test_case.test(ret, function_name, "construct the protected RFC 5746 renegotiation ClientHello");
        if (errorcode_t::success != ret) {
            break;
        }

        auto send_all = [&](const binary_t& wire) -> bool {
            size_t offset = 0;
            while (offset < wire.size()) {
                size_t sent_bytes = 0;
                return_t send_result = peer_transport.send((const char*)wire.data() + offset, wire.size() - offset, &sent_bytes);
                if ((errorcode_t::success != send_result) || (0 == sent_bytes)) {
                    return false;
                }
                offset += sent_bytes;
            }
            return true;
        };

        auto receive_and_process = [&](const binary_t& expected_wire) -> return_t {
            binary_t received(expected_wire.size());
            size_t offset = 0;
            while (offset < received.size()) {
                size_t received_bytes = 0;
                return_t read_result =
                    server_socket.naive_tcp_server_socket::read(server_transport, 0, (char*)received.data() + offset, received.size() - offset, &received_bytes);
                if (errorcode_t::success != read_result) {
                    return read_result;
                }
                if (0 == received_bytes) {
                    return errorcode_t::closed;
                }
                offset += received_bytes;
            }
            if (received != expected_wire) {
                return errorcode_t::mismatch;
            }

            size_t input_size = received.size();
            return server_socket.read(server_transport, tls_io_flag_t::read_bio_write, (char*)received.data(), received.size(), &input_size);
        };

        const bool client_hello_sent = send_all(client_hello_wire);
        _test_case.assert(client_hello_sent, function_name, "send the protected renegotiation ClientHello over TCP");
        if (false == client_hello_sent) {
            break;
        }

        client_hello_reader = std::thread([&]() {
            client_hello_reader_started.store(true, std::memory_order_release);
            client_hello_read_ret = receive_and_process(client_hello_wire);
        });

        const auto reader_start_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while ((false == client_hello_reader_started.load(std::memory_order_acquire)) && (std::chrono::steady_clock::now() < reader_start_deadline)) {
            std::this_thread::yield();
        }
        const bool client_hello_reader_started_ok = client_hello_reader_started.load(std::memory_order_acquire);
        _test_case.assert(client_hello_reader_started_ok, function_name, "start the peer ClientHello reader thread");
        if (false == client_hello_reader_started_ok) {
            release_client_hello_hook.store(true, std::memory_order_release);
            break;
        }

        const auto hook_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while ((false == client_hello_hook_entered.load(std::memory_order_acquire)) && (std::chrono::steady_clock::now() < hook_deadline)) {
            std::this_thread::yield();
        }
        const bool client_hello_paused = client_hello_hook_entered.load(std::memory_order_acquire);
        _test_case.assert(client_hello_paused, function_name, "pause the peer ClientHello receive path inside its status callback");
        if (false == client_hello_paused) {
            release_client_hello_hook.store(true, std::memory_order_release);
            break;
        }

        sender_a = std::thread([&]() {
            while (false == senders_start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            senders_started.fetch_add(1, std::memory_order_release);
            send_ret_a = server_socket.send(server_transport, "sender-a", 8, &sent_a);
        });
        sender_b = std::thread([&]() {
            while (false == senders_start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            senders_started.fetch_add(1, std::memory_order_release);
            send_ret_b = server_socket.send(server_transport, "sender-b", 8, &sent_b);
        });

        senders_start.store(true, std::memory_order_release);
        const auto senders_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while ((2 != senders_started.load(std::memory_order_acquire)) && (std::chrono::steady_clock::now() < senders_deadline)) {
            std::this_thread::yield();
        }
        const bool both_senders_entered = (2 == senders_started.load(std::memory_order_acquire));
        _test_case.assert(both_senders_entered, function_name, "start both application senders while peer ClientHello processing holds the TLS I/O lock");
        if (false == both_senders_entered) {
            release_client_hello_hook.store(true, std::memory_order_release);
            break;
        }

        release_client_hello_hook.store(true, std::memory_order_release);
        if (client_hello_reader.joinable()) {
            client_hello_reader.join();
        }
        _test_case.test(client_hello_read_ret, function_name, "finish processing the peer ClientHello after releasing both senders");
        if (errorcode_t::success != client_hello_read_ret) {
            break;
        }

        _test_case.assert(tls_flow_t::renegotiation == server_session->get_tls_protection().get_flow(), function_name,
                          "enter renegotiation flow after the peer ClientHello");
        _test_case.assert(0 != (server_session->get_session_status() & session_status_client_hello), function_name,
                          "publish the peer ClientHello status before the concurrent senders continue");

        const auto server_hello_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while ((false == server_flight_started.load(std::memory_order_acquire)) && (std::chrono::steady_clock::now() < server_hello_deadline)) {
            std::this_thread::yield();
        }
        const bool server_flight_wrote_wire = server_flight_started.load(std::memory_order_acquire);
        _test_case.assert(server_flight_wrote_wire, function_name, "observe the production server-flight transport callback");

        initial_server_recordno = server_session->get_recordno(from_server);

        binary_t fatal_alert_wire;
        tls_record_alert fatal_alert(&peer_session, tls_alertlevel_t::fatal, tls_alertdesc_t::handshake_failure);
        ret = fatal_alert.write(from_client, fatal_alert_wire);
        _test_case.test(ret, function_name, "construct the protected peer fatal handshake_failure alert");
        if (errorcode_t::success != ret) {
            break;
        }

        const bool fatal_alert_sent = send_all(fatal_alert_wire);
        _test_case.assert(fatal_alert_sent, function_name, "send the protected fatal alert over the same TCP connection");
        if (true == fatal_alert_sent) {
            ret = receive_and_process(fatal_alert_wire);
            _test_case.assert(errorcode_t::handshake_failure == ret, function_name,
                              "surface the received fatal alert from the production TLS read path (actual return 0x%08x)", static_cast<uint32>(ret));
        } else {
            ret = errorcode_t::send_failure;
        }

        if (errorcode_t::success != ret) {
            server_session->mark_terminal();
            server_session->get_secure_prosumer()->notify_transport_closed();
        }
    } while (false);

    release_client_hello_hook.store(true, std::memory_order_release);
    if (client_hello_reader.joinable()) {
        client_hello_reader.join();
    }
    if ((sender_a.joinable() || sender_b.joinable()) && (nullptr != server_session) && (false == server_session->is_terminal())) {
        server_session->mark_terminal();
        server_session->get_secure_prosumer()->notify_transport_closed();
    }
    if (sender_a.joinable()) {
        sender_a.join();
    }
    if (sender_b.joinable()) {
        sender_b.join();
    }

    if (0 != senders_started.load(std::memory_order_acquire)) {
        _test_case.assert((nullptr != server_session) && server_session->is_terminal(), function_name, "terminalize the server session after the fatal peer response");
        if (nullptr != server_session) {
            _test_case.assert(initial_server_recordno == server_session->get_recordno(from_server), function_name,
                              "do not serialize an application record while peer renegotiation fails");
        }
        _test_case.assert(errorcode_t::disconnect == send_ret_a, function_name, "wake concurrent sender A with disconnect (actual return 0x%08x)",
                          static_cast<uint32>(send_ret_a));
        _test_case.assert(errorcode_t::disconnect == send_ret_b, function_name, "wake concurrent sender B with disconnect (actual return 0x%08x)",
                          static_cast<uint32>(send_ret_b));
        _test_case.assert(0 == sent_a, function_name, "report no application bytes sent by sender A after the fatal peer response");
        _test_case.assert(0 == sent_b, function_name, "report no application bytes sent by sender B after the fatal peer response");
    }

    peer_transport.close();
    if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_send_retires_after_peer_response_timeout_loopback_tcp() {
    // Scenario: a server application send reaches the TLS 1.2 reserve and
    // starts renegotiation; the peer receives HelloRequest but never answers.
    // Action: let the production composer wait expire on the real TCP socket.
    // Expected: timeout retires the TLS session, wakes secure readers, and
    // never retries or reports the original application payload as sent.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 peer response timeout retires a reserve-triggered server send over loopback TCP");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);

    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);

    std::thread sender;
    std::thread reader;
    tls_session* server_session = nullptr;
    return_t server_send_ret = errorcode_t::internal_error;
    return_t reader_ret = errorcode_t::internal_error;
    size_t server_sent = 99;
    size_t reader_bytes = 99;
    std::atomic<bool> reader_started(false);
    uint64 server_recordno_after_hello_request = 0;
    bool hello_request_received = false;

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the loopback TLS server listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = peer_transport.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the raw TCP peer");
        if (errorcode_t::success != ret) {
            break;
        }

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the peer TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server socket context");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;
        server_session = server_transport->handle.session;

        // Suppress the production callback while seeding the established
        // connection state; restore its composer behavior before the test.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });
        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 state");
        if (errorcode_t::success != ret) {
            break;
        }

        auto server_send_wire = [&server_socket, server_transport](tls_session*, binary_t& wire) -> return_t {
            size_t sent = 0;
            return_t send_ret = server_socket.naive_tcp_server_socket::send(server_transport, (char*)wire.data(), wire.size(), &sent);
            if (errorcode_t::success != send_ret) {
                return send_ret;
            }
            return (sent == wire.size()) ? errorcode_t::success : errorcode_t::send_failure;
        };
        server_session->set_hook_param(server_transport);
        server_session->set_hook_change_session_status([server_send_wire](tls_session* current, uint32 status) -> return_t {
            return current->get_tls_composer()->session_status_changed(status, from_server, 1000, server_send_wire);
        });

        constexpr uint64 sequence_max = ~static_cast<uint64>(0);
        constexpr uint64 sequence_reserve = 65535;
        constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
        server_session->set_recordno(from_server, sequence_reserve_start);

        sender = std::thread([&]() {
            const char application_payload[] = "must-not-send";
            server_send_ret = server_socket.send(server_transport, application_payload, sizeof(application_payload) - 1, &server_sent);
        });

        auto read_exact = [&](char* output, size_t size) -> bool {
            size_t offset = 0;
            while (offset < size) {
                size_t received = 0;
                return_t read_ret = peer_transport.read(output + offset, size - offset, &received);
                if ((errorcode_t::success != read_ret) && (errorcode_t::more_data != read_ret)) {
                    return false;
                }
                if (0 == received) {
                    return false;
                }
                offset += received;
            }
            return true;
        };

        byte_t hello_request_header[5] = {};
        const bool header_read = read_exact((char*)hello_request_header, sizeof(hello_request_header));
        _test_case.assert(header_read, function_name, "receive the server HelloRequest record over TCP");
        if (false == header_read) {
            break;
        }

        const size_t hello_request_size = (static_cast<size_t>(hello_request_header[3]) << 8) | static_cast<size_t>(hello_request_header[4]);
        _test_case.assert((0x16 == hello_request_header[0]) && (0x03 == hello_request_header[1]) && (0x03 == hello_request_header[2]) && (0 != hello_request_size),
                          function_name, "receive a non-empty TLS 1.2 handshake record for HelloRequest");
        if ((0x16 != hello_request_header[0]) || (0x03 != hello_request_header[1]) || (0x03 != hello_request_header[2]) || (0 == hello_request_size)) {
            break;
        }

        byte_t hello_request_body[18432] = {};
        _test_case.assert(hello_request_size <= sizeof(hello_request_body), function_name, "keep the HelloRequest record within the TLS record limit");
        if (hello_request_size > sizeof(hello_request_body)) {
            break;
        }
        const bool body_read = read_exact((char*)hello_request_body, hello_request_size);
        _test_case.assert(body_read, function_name, "receive the complete HelloRequest record body");
        if (false == body_read) {
            break;
        }

        hello_request_received = true;
        server_recordno_after_hello_request = server_session->get_recordno(from_server);
        _test_case.assert(sequence_reserve_start + 1 == server_recordno_after_hello_request, function_name,
                          "consume exactly one old-key record for the server HelloRequest");

        // Start a real secure application reader while the server sender is
        // waiting for the peer. Timeout retirement must wake this blocked read.
        reader = std::thread([&]() {
            char plaintext[1] = {};
            reader_started.store(true, std::memory_order_release);
            reader_ret = server_session->get_secure_prosumer()->consume(SOCK_STREAM, 5000, plaintext, sizeof(plaintext), &reader_bytes, nullptr, nullptr);
        });
        while (true) {
            if (reader_started.load(std::memory_order_acquire)) {
                break;
            }
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // Deliberately send no ClientHello or alert. The production composer
        // must time out using the server socket's 1000 ms wait interval.
        sender.join();
        reader.join();
        _test_case.assert(errorcode_t::timeout == server_send_ret, function_name, "return timeout when the peer does not answer HelloRequest (actual return 0x%08x)",
                          static_cast<uint32>(server_send_ret));
        _test_case.assert((nullptr != server_session) && server_session->is_terminal(), function_name, "terminalize the server session after the peer-response timeout");
        _test_case.assert(0 == server_sent, function_name, "report no application bytes sent after timeout");
        _test_case.assert(server_recordno_after_hello_request == server_session->get_recordno(from_server), function_name,
                          "do not serialize an application record after the timed-out HelloRequest");
        _test_case.assert(errorcode_t::disconnect == reader_ret, function_name,
                          "wake the blocked secure application reader with disconnect after timeout retirement (actual return 0x%08x)", static_cast<uint32>(reader_ret));
        _test_case.assert(0 == reader_bytes, function_name, "deliver no application plaintext after timeout retirement");
        _test_case.assert(0 == test_count_fatal_alerts(*server_session, from_server), function_name,
                          "do not synthesize a fatal TLS alert for a local peer-response timeout");
    } while (false);

    if (sender.joinable()) {
        sender.join();
    }
    if (reader.joinable()) {
        reader.join();
    }
    if (hello_request_received && (nullptr != server_session)) {
        _test_case.assert(errorcode_t::timeout == server_send_ret, function_name, "complete the reserve-triggered sender with timeout");
        _test_case.assert(server_session->is_terminal(), function_name, "retire the timed-out TLS session");
        _test_case.assert(0 == server_sent, function_name, "do not report the application payload as sent");
    }

    peer_transport.close();
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    } else if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_send_retires_after_malformed_peer_client_hello_loopback_tcp() {
    // Scenario: a server application send reaches the TLS 1.2 reserve and
    // starts renegotiation; the peer answers with a protected ClientHello
    // whose RFC 5746 client Finished binding is incorrect.
    // Action: process that record through the production server socket read path.
    // Expected: return illegal_parameter, terminalize the session, wake the
    // waiting sender with disconnect, and never retry the application record.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 malformed peer ClientHello retires a reserve-triggered server send over loopback TCP");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);

    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);
    tls_session peer_session;

    std::thread sender;
    tls_session* server_session = nullptr;
    return_t server_send_ret = errorcode_t::internal_error;
    return_t malformed_read_ret = errorcode_t::internal_error;
    size_t server_sent = 99;
    uint64 server_recordno_after_hello_request = 0;
    bool hello_request_received = false;
    bool malformed_client_hello_sent = false;

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the loopback TLS server listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = peer_transport.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the raw TCP peer");
        if (errorcode_t::success != ret) {
            break;
        }

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the peer TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server socket context");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;
        server_session = server_transport->handle.session;

        // Suppress the production callback while seeding the established
        // connection state; restore its composer behavior before the test.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });
        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 state");
        if (errorcode_t::success != ret) {
            break;
        }
        ret = test_configure_tls12_live_peer_session(peer_session);
        _test_case.test(ret, function_name, "seed the peer's matching TLS 1.2 record protection state");
        if (errorcode_t::success != ret) {
            break;
        }

        // Keep the ClientHello record cryptographically valid, but make only
        // its RFC 5746 binding disagree with the server's previous client Finished.
        peer_session.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, binary_t(12, 0x32));

        auto server_send_wire = [&server_socket, server_transport](tls_session*, binary_t& wire) -> return_t {
            size_t sent = 0;
            return_t send_ret = server_socket.naive_tcp_server_socket::send(server_transport, (char*)wire.data(), wire.size(), &sent);
            if (errorcode_t::success != send_ret) {
                return send_ret;
            }
            return (sent == wire.size()) ? errorcode_t::success : errorcode_t::send_failure;
        };
        server_session->set_hook_param(server_transport);
        server_session->set_hook_change_session_status([server_send_wire](tls_session* current, uint32 status) -> return_t {
            return current->get_tls_composer()->session_status_changed(status, from_server, 1000, server_send_wire);
        });

        constexpr uint64 sequence_max = ~static_cast<uint64>(0);
        constexpr uint64 sequence_reserve = 65535;
        constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
        server_session->set_recordno(from_server, sequence_reserve_start);

        sender = std::thread([&]() {
            const char application_payload[] = "must-not-send";
            server_send_ret = server_socket.send(server_transport, application_payload, sizeof(application_payload) - 1, &server_sent);
        });

        auto read_exact = [&](char* output, size_t size) -> bool {
            size_t offset = 0;
            while (offset < size) {
                size_t received = 0;
                return_t read_ret = peer_transport.read(output + offset, size - offset, &received);
                if ((errorcode_t::success != read_ret) && (errorcode_t::more_data != read_ret)) {
                    return false;
                }
                if (0 == received) {
                    return false;
                }
                offset += received;
            }
            return true;
        };

        byte_t hello_request_header[5] = {};
        const bool header_read = read_exact((char*)hello_request_header, sizeof(hello_request_header));
        _test_case.assert(header_read, function_name, "receive the server HelloRequest record over TCP");
        if (false == header_read) {
            break;
        }

        const size_t hello_request_size = (static_cast<size_t>(hello_request_header[3]) << 8) | static_cast<size_t>(hello_request_header[4]);
        _test_case.assert((0x16 == hello_request_header[0]) && (0x03 == hello_request_header[1]) && (0x03 == hello_request_header[2]) && (0 != hello_request_size),
                          function_name, "receive a non-empty TLS 1.2 handshake record for HelloRequest");
        if ((0x16 != hello_request_header[0]) || (0x03 != hello_request_header[1]) || (0x03 != hello_request_header[2]) || (0 == hello_request_size)) {
            break;
        }

        binary_t hello_request_wire(sizeof(hello_request_header) + hello_request_size);
        memcpy(hello_request_wire.data(), hello_request_header, sizeof(hello_request_header));
        const bool hello_request_body_read = read_exact((char*)hello_request_wire.data() + sizeof(hello_request_header), hello_request_size);
        _test_case.assert(hello_request_body_read, function_name, "receive the complete protected HelloRequest record");
        if (false == hello_request_body_read) {
            break;
        }
        hello_request_received = true;
        server_recordno_after_hello_request = server_session->get_recordno(from_server);
        _test_case.assert(sequence_reserve_start + 1 == server_recordno_after_hello_request, function_name,
                          "consume exactly one old-key record for the server HelloRequest");

        binary_t malformed_client_hello_wire;
        ret = test_write_tls12_renegotiation_client_hello_record(peer_session, malformed_client_hello_wire);
        _test_case.test(ret, function_name, "serialize a protected ClientHello with a mismatched RFC 5746 binding");
        if (errorcode_t::success != ret) {
            break;
        }

        size_t offset = 0;
        while (offset < malformed_client_hello_wire.size()) {
            size_t sent = 0;
            ret = peer_transport.send((const char*)malformed_client_hello_wire.data() + offset, malformed_client_hello_wire.size() - offset, &sent);
            if ((errorcode_t::success != ret) || (0 == sent)) {
                break;
            }
            offset += sent;
        }
        malformed_client_hello_sent = (errorcode_t::success == ret) && (offset == malformed_client_hello_wire.size());
        _test_case.assert(malformed_client_hello_sent, function_name, "send the malformed but correctly protected ClientHello over TCP");
        if (false == malformed_client_hello_sent) {
            break;
        }

        size_t input_size = malformed_client_hello_wire.size();
        malformed_read_ret = server_socket.read(server_transport, tls_io_flag_t::read_bio_write, (char*)malformed_client_hello_wire.data(),
                                                malformed_client_hello_wire.size(), &input_size);
        _test_case.assert(errorcode_t::illegal_parameter == malformed_read_ret, function_name,
                          "surface the RFC 5746 binding mismatch from the production TLS read path (actual return 0x%08x)", static_cast<uint32>(malformed_read_ret));
        _test_case.assert(1 == test_count_fatal_alert(*server_session, from_client, tls_alertdesc_t::illegal_parameter), function_name,
                          "queue one fatal illegal_parameter for the malformed ClientHello binding");
    } while (false);

    if (sender.joinable()) {
        sender.join();
    }

    if (hello_request_received && malformed_client_hello_sent) {
        _test_case.assert(errorcode_t::illegal_parameter == malformed_read_ret, function_name, "reject the malformed peer ClientHello with illegal_parameter");
        _test_case.assert((nullptr != server_session) && server_session->is_terminal(), function_name,
                          "terminalize the server session after the malformed peer handshake");
        _test_case.assert(errorcode_t::disconnect == server_send_ret, function_name, "wake the waiting application sender with disconnect (actual return 0x%08x)",
                          static_cast<uint32>(server_send_ret));
        _test_case.assert(0 == server_sent, function_name, "report no application bytes sent after the malformed peer handshake");
        if (nullptr != server_session) {
            _test_case.assert(server_recordno_after_hello_request == server_session->get_recordno(from_server), function_name,
                              "do not serialize a server application record after the malformed ClientHello");
        }
    }

    peer_transport.close();
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    } else if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_send_retires_after_server_flight_callback_failure_loopback_tcp() {
    // Scenario: a server application sender joins a peer-initiated TLS 1.2
    // renegotiation and waits for the peer ClientHello / server flight.
    // Action: the peer ClientHello crosses loopback TCP; the production
    // handshake composer is invoked, but its server-flight transport callback
    // deterministically reports send_failure.
    // Expected: the read path propagates the callback failure, terminalizes
    // the session, wakes the waiting sender with disconnect, and sends no
    // application payload. The established session is seeded; this is not a
    // complete TLS renegotiation interoperability test.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 server application send retires after server-flight callback failure over loopback TCP");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);
    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);
    tls_session peer_session;

    std::thread sender;
    std::atomic<bool> sender_started(false);
    std::atomic<bool> sender_finished(false);
    std::atomic<unsigned> server_flight_send_attempts(0);
    return_t send_ret = errorcode_t::internal_error;
    size_t sent = 99;
    tls_session* server_session = nullptr;
    uint64 initial_server_recordno = 0;

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the loopback TLS server listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = peer_transport.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the raw TCP peer");
        if (errorcode_t::success != ret) {
            break;
        }

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the peer TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server socket context");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;

        server_session = server_transport->handle.session;
        // Avoid invoking the production hook while the test seeds the
        // established Finished state, then install a composer-backed callback.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });
        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }
        ret = test_configure_tls12_live_peer_session(peer_session);
        _test_case.test(ret, function_name, "seed the peer's matching TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }

        // Model the state after the peer has initiated renegotiation but
        // before its ClientHello has been consumed. The sender must wait.
        server_session->get_tls_protection().set_flow(tls_flow_t::renegotiation);
        server_session->clear_session_status(session_status_client_finished | session_status_server_finished);
        server_session->set_hook_change_session_status([&server_flight_send_attempts](tls_session* session, uint32 status) -> return_t {
            return session->get_tls_composer()->session_status_changed(status, from_server, 1000, [&server_flight_send_attempts](tls_session*, binary_t&) -> return_t {
                server_flight_send_attempts.fetch_add(1, std::memory_order_acq_rel);
                return errorcode_t::send_failure;
            });
        });

        binary_t client_hello_wire;
        ret = test_write_tls12_renegotiation_client_hello_record(peer_session, client_hello_wire);
        _test_case.test(ret, function_name, "construct the protected RFC 5746 renegotiation ClientHello");
        if (errorcode_t::success != ret) {
            break;
        }

        auto send_all = [&](const binary_t& wire) -> bool {
            size_t offset = 0;
            while (offset < wire.size()) {
                size_t sent_bytes = 0;
                return_t send_result = peer_transport.send((const char*)wire.data() + offset, wire.size() - offset, &sent_bytes);
                if ((errorcode_t::success != send_result) || (0 == sent_bytes)) {
                    return false;
                }
                offset += sent_bytes;
            }
            return true;
        };

        auto receive_and_process = [&](const binary_t& expected_wire) -> return_t {
            binary_t received(expected_wire.size());
            size_t offset = 0;
            while (offset < received.size()) {
                size_t received_bytes = 0;
                return_t read_result =
                    server_socket.naive_tcp_server_socket::read(server_transport, 0, (char*)received.data() + offset, received.size() - offset, &received_bytes);
                if (errorcode_t::success != read_result) {
                    return read_result;
                }
                if (0 == received_bytes) {
                    return errorcode_t::closed;
                }
                offset += received_bytes;
            }
            if (received != expected_wire) {
                return errorcode_t::mismatch;
            }

            size_t input_size = received.size();
            return server_socket.read(server_transport, tls_io_flag_t::read_bio_write, (char*)received.data(), received.size(), &input_size);
        };

        initial_server_recordno = server_session->get_recordno(from_server);
        sender = std::thread([&]() {
            sender_started.store(true, std::memory_order_release);
            send_ret = server_socket.send(server_transport, "pending", 7, &sent);
            sender_finished.store(true, std::memory_order_release);
        });
        while (false == sender_started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        _test_case.assert(false == sender_finished.load(std::memory_order_acquire), function_name,
                          "keep the application sender waiting for the peer ClientHello and server flight");

        const bool client_hello_sent = send_all(client_hello_wire);
        _test_case.assert(client_hello_sent, function_name, "send the protected renegotiation ClientHello over TCP");
        if (false == client_hello_sent) {
            break;
        }

        ret = receive_and_process(client_hello_wire);
        _test_case.assert(errorcode_t::send_failure == ret, function_name, "return the injected server-flight transport error (actual return 0x%08x)",
                          static_cast<uint32>(ret));
        _test_case.assert(1 == server_flight_send_attempts.load(std::memory_order_acquire), function_name, "attempt exactly one server-flight transport callback");
        _test_case.assert(server_session->is_terminal(), function_name, "terminalize the TLS session after server-flight transport failure");
        _test_case.assert(initial_server_recordno + 1 == server_session->get_recordno(from_server), function_name,
                          "serialize only the first server-flight record before the callback fails");
    } while (false);

    if ((nullptr != server_session) && (true == sender_started.load(std::memory_order_acquire)) && (false == sender_finished.load(std::memory_order_acquire))) {
        server_session->mark_terminal();
        server_session->get_secure_prosumer()->notify_transport_closed();
    }
    if (sender.joinable()) {
        sender.join();
    }

    if (true == sender_started.load(std::memory_order_acquire)) {
        _test_case.assert(errorcode_t::disconnect == send_ret, function_name, "wake the waiting application sender with disconnect (actual return 0x%08x)",
                          static_cast<uint32>(send_ret));
        _test_case.assert(0 == sent, function_name, "report no application bytes sent after server-flight callback failure");
    }

    peer_transport.close();
    if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_send_retires_after_server_flight_os_send_failure_loopback_tcp() {
    // Scenario: a server application sender joins a peer-initiated TLS 1.2
    // renegotiation and waits for the peer ClientHello / server flight.
    // Action: the peer sends a protected ClientHello over loopback TCP, then
    // closes with SO_LINGER(0) to reset the TCP connection before the parser
    // invokes the server-flight transport callback.
    // Expected: the real socket send fails at the OS boundary, the production
    // TLS read path propagates that failure and terminalizes the session, and
    // the waiting application sender sends no application data. The session
    // is seeded; this is not a complete renegotiation interoperability test.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 server application send retires after OS-level server-flight TCP send failure");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);
    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);
    tls_session peer_session;

    std::thread sender;
    std::atomic<bool> sender_started(false);
    std::atomic<bool> sender_finished(false);
    std::atomic<unsigned> server_flight_send_attempts(0);
    return_t send_ret = errorcode_t::internal_error;
    return_t server_flight_send_ret = errorcode_t::success;
    size_t sent = 99;
    tls_session* server_session = nullptr;
    uint64 initial_server_recordno = 0;
    bool peer_socket_aborted = false;

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the loopback TLS server listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = peer_transport.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the raw TCP peer");
        if (errorcode_t::success != ret) {
            break;
        }

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the peer TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server socket context");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;

        server_session = server_transport->handle.session;
        // Temporarily suppress the production status hook while seeding the
        // established connection, then install a composer callback whose
        // transport operation is the real production TCP socket send.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });
        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }
        ret = test_configure_tls12_live_peer_session(peer_session);
        _test_case.test(ret, function_name, "seed the peer's matching TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }

        server_session->get_tls_protection().set_flow(tls_flow_t::renegotiation);
        server_session->clear_session_status(session_status_client_finished | session_status_server_finished);
        server_session->set_hook_change_session_status([&](tls_session* session, uint32 status) -> return_t {
            return session->get_tls_composer()->session_status_changed(status, from_server, 1000, [&](tls_session*, binary_t& wire) -> return_t {
                server_flight_send_attempts.fetch_add(1, std::memory_order_acq_rel);
                size_t sent_bytes = 0;
                server_flight_send_ret = server_socket.naive_tcp_server_socket::send(server_transport, (const char*)wire.data(), wire.size(), &sent_bytes);
                if (errorcode_t::success != server_flight_send_ret) {
                    return server_flight_send_ret;
                }
                if (sent_bytes != wire.size()) {
                    server_flight_send_ret = errorcode_t::send_failure;
                    return server_flight_send_ret;
                }
                return errorcode_t::success;
            });
        });

        binary_t client_hello_wire;
        ret = test_write_tls12_renegotiation_client_hello_record(peer_session, client_hello_wire);
        _test_case.test(ret, function_name, "construct the protected RFC 5746 renegotiation ClientHello");
        if (errorcode_t::success != ret) {
            break;
        }

        initial_server_recordno = server_session->get_recordno(from_server);
        sender = std::thread([&]() {
            sender_started.store(true, std::memory_order_release);
            send_ret = server_socket.send(server_transport, "pending", 7, &sent);
            sender_finished.store(true, std::memory_order_release);
        });
        while (false == sender_started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        _test_case.assert(false == sender_finished.load(std::memory_order_acquire), function_name,
                          "keep the application sender waiting for the peer ClientHello and server flight");

        size_t peer_sent = 0;
        while (peer_sent < client_hello_wire.size()) {
            size_t sent_bytes = 0;
            ret = peer_transport.send((const char*)client_hello_wire.data() + peer_sent, client_hello_wire.size() - peer_sent, &sent_bytes);
            if ((errorcode_t::success != ret) || (0 == sent_bytes)) {
                break;
            }
            peer_sent += sent_bytes;
        }
        _test_case.test(ret, function_name, "send the protected renegotiation ClientHello over TCP");
        _test_case.assert(client_hello_wire.size() == peer_sent, function_name, "send the complete ClientHello record");
        if ((errorcode_t::success != ret) || (client_hello_wire.size() != peer_sent)) {
            break;
        }

        // Read the complete ClientHello from the accepted TCP socket without
        // parsing it yet. This ensures the peer's reset cannot discard input
        // before the production TLS parser gets the already-buffered record.
        binary_t received(client_hello_wire.size());
        size_t received_offset = 0;
        while (received_offset < received.size()) {
            size_t received_bytes = 0;
            ret = server_socket.naive_tcp_server_socket::read(server_transport, 0, (char*)received.data() + received_offset, received.size() - received_offset,
                                                              &received_bytes);
            if (errorcode_t::success != ret) {
                break;
            }
            if (0 == received_bytes) {
                ret = errorcode_t::closed;
                break;
            }
            received_offset += received_bytes;
        }
        _test_case.test(ret, function_name, "receive the complete protected ClientHello before parsing it");
        _test_case.assert(received == client_hello_wire, function_name, "preserve the exact protected ClientHello bytes");
        if ((errorcode_t::success != ret) || (received != client_hello_wire)) {
            break;
        }

        struct linger reset_on_close = {};
        reset_on_close.l_onoff = 1;
        reset_on_close.l_linger = 0;
        int linger_ret = setsockopt(peer_transport.get_socket(), SOL_SOCKET, SO_LINGER, (const char*)&reset_on_close, (socklen_t)sizeof(reset_on_close));
        _test_case.assert(0 == linger_ret, function_name, "configure an abortive TCP close for the peer");
        if (0 != linger_ret) {
            break;
        }
#if defined __linux__
        int peer_close_ret = ::close(peer_transport.get_socket());
#elif defined _WIN32 || defined _WIN64
        int peer_close_ret = ::closesocket(peer_transport.get_socket());
#endif
        peer_socket_aborted = (0 == peer_close_ret);
        _test_case.assert(peer_socket_aborted, function_name, "abortively close the peer TCP socket with SO_LINGER(0)");
        if (false == peer_socket_aborted) {
            break;
        }

        // Wait until the server TCP stack reports the reset before processing
        // the buffered ClientHello and invoking the production socket send.
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_transport->fd, &readfds);
        timeval wait_reset = {};
        wait_reset.tv_sec = 3;
#if defined _WIN32 || defined _WIN64
        int select_ret = ::select(0, &readfds, nullptr, nullptr, &wait_reset);
#else
        int select_ret = ::select((int)server_transport->fd + 1, &readfds, nullptr, nullptr, &wait_reset);
#endif
        _test_case.assert((1 == select_ret) && FD_ISSET(server_transport->fd, &readfds), function_name, "observe the peer TCP reset on the server socket");
        if ((1 != select_ret) || (false == FD_ISSET(server_transport->fd, &readfds))) {
            break;
        }
        char reset_probe = 0;
        int probe_ret = ::recv(server_transport->fd, &reset_probe, 1, MSG_PEEK);
        _test_case.assert(-1 == probe_ret, function_name, "confirm the server socket reports the peer reset");
        if (-1 != probe_ret) {
            break;
        }

        size_t input_size = received.size();
        ret = server_socket.read(server_transport, tls_io_flag_t::read_bio_write, (char*)received.data(), received.size(), &input_size);
        _test_case.assert((errorcode_t::success != server_flight_send_ret) && (errorcode_t::send_failure != server_flight_send_ret), function_name,
                          "observe an OS send error rather than a synthesized short-write result");
        _test_case.assert(errorcode_t::success != ret, function_name, "return the server-flight socket send error from the production TLS read path");
        _test_case.assert(ret.error_code() == server_flight_send_ret.error_code(), function_name,
                          "propagate the exact OS send error through the production TLS read path");
        _test_case.assert(1 == server_flight_send_attempts.load(std::memory_order_acquire), function_name, "attempt exactly one server-flight TCP send");
        _test_case.assert(server_session->is_terminal(), function_name, "terminalize the TLS session after the OS send failure");
        _test_case.assert(initial_server_recordno + 1 == server_session->get_recordno(from_server), function_name,
                          "serialize only the first server-flight record before the TCP send fails");
    } while (false);

    if ((nullptr != server_session) && (true == sender_started.load(std::memory_order_acquire)) && (false == sender_finished.load(std::memory_order_acquire))) {
        server_session->mark_terminal();
        server_session->get_secure_prosumer()->notify_transport_closed();
    }
    if (sender.joinable()) {
        sender.join();
    }

    if (true == sender_started.load(std::memory_order_acquire)) {
        _test_case.assert(errorcode_t::disconnect == send_ret, function_name, "wake the waiting application sender with disconnect (actual return 0x%08x)",
                          static_cast<uint32>(send_ret));
        _test_case.assert(0 == sent, function_name, "report no application bytes sent after the OS send failure");
    }

    if (false == peer_socket_aborted) {
        peer_transport.close();
    }
    if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_send_retires_after_server_flight_short_tcp_write_loopback_tcp() {
    // Scenario: a server application sender joins a peer-initiated TLS 1.2
    // renegotiation and waits for the peer ClientHello / server flight.
    // Action: the peer sends a protected ClientHello over loopback TCP. The
    // server-flight callback deliberately submits only a prefix of the TLS
    // record to the real TCP socket send function.
    // Expected: the partial record is written to TCP, the callback detects
    // that fewer bytes than the complete TLS record were sent and returns
    // send_failure, and the production read path terminalizes the session.
    // The session is seeded; this is not a complete renegotiation test.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 server application send retires after a short server-flight TCP write");

    trial_tls_server_socket server_socket(tls1_2, tls1_2);
    socket_context_t* listen_context = nullptr;
    socket_context_t* server_transport = nullptr;
    socket_t accepted_socket = INVALID_SOCKET;
    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);
    tls_session peer_session;

    std::thread sender;
    std::atomic<bool> sender_started(false);
    std::atomic<bool> sender_finished(false);
    std::atomic<unsigned> server_flight_send_attempts(0);
    return_t send_ret = errorcode_t::internal_error;
    return_t server_flight_send_ret = errorcode_t::success;
    size_t server_flight_wire_size = 0;
    size_t server_flight_sent_bytes = 0;
    binary_t server_flight_prefix;
    size_t sent = 99;
    tls_session* server_session = nullptr;
    uint64 initial_server_recordno = 0;

    do {
        return_t ret = server_socket.open(&listen_context, AF_INET, 0);
        _test_case.test(ret, function_name, "open the loopback TLS server listener");
        if ((errorcode_t::success != ret) || (nullptr == listen_context)) {
            break;
        }

        sockaddr_in listen_address = {};
        socklen_t listen_address_size = sizeof(listen_address);
        int name_ret = getsockname(listen_context->fd, (sockaddr*)&listen_address, &listen_address_size);
        _test_case.assert(0 == name_ret, function_name, "retrieve the ephemeral listener port");
        if (0 != name_ret) {
            break;
        }

        ret = peer_transport.connect("127.0.0.1", ntohs(listen_address.sin_port), 3);
        _test_case.test(ret, function_name, "connect the raw TCP peer");
        if (errorcode_t::success != ret) {
            break;
        }

        sockaddr_storage_t accepted_address = {};
        socklen_t accepted_address_size = sizeof(accepted_address);
        ret = server_socket.accept(&accepted_socket, listen_context->fd, (sockaddr*)&accepted_address, &accepted_address_size);
        _test_case.test(ret, function_name, "accept the peer TCP connection");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = server_socket.tls_accept(&server_transport, accepted_socket);
        _test_case.test(ret, function_name, "create the production TLS server socket context");
        if (errorcode_t::success != ret) {
            server_socket.tls_accept_fails(accepted_socket);
            accepted_socket = INVALID_SOCKET;
            break;
        }
        accepted_socket = INVALID_SOCKET;

        server_session = server_transport->handle.session;
        // Temporarily suppress the production status hook while seeding the
        // established connection, then install a composer callback whose
        // transport operation is the real production TCP socket send.
        server_session->set_hook_change_session_status([](tls_session*, uint32) -> return_t { return errorcode_t::success; });
        ret = test_configure_tls12_live_peer_session(*server_session);
        _test_case.test(ret, function_name, "seed the server's established TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }
        ret = test_configure_tls12_live_peer_session(peer_session);
        _test_case.test(ret, function_name, "seed the peer's matching TLS 1.2 connection state");
        if (errorcode_t::success != ret) {
            break;
        }

        server_session->get_tls_protection().set_flow(tls_flow_t::renegotiation);
        server_session->clear_session_status(session_status_client_finished | session_status_server_finished);
        server_session->set_hook_change_session_status([&](tls_session* session, uint32 status) -> return_t {
            return session->get_tls_composer()->session_status_changed(status, from_server, 1000, [&](tls_session*, binary_t& wire) -> return_t {
                server_flight_send_attempts.fetch_add(1, std::memory_order_acq_rel);
                if (wire.size() <= 1) {
                    return errorcode_t::invalid_parameter;
                }
                const size_t partial_size = wire.size() - 1;
                size_t sent_bytes = 0;
                server_flight_send_ret = server_socket.naive_tcp_server_socket::send(server_transport, (const char*)wire.data(), partial_size, &sent_bytes);
                server_flight_wire_size = wire.size();
                server_flight_sent_bytes = sent_bytes;
                server_flight_prefix.assign(wire.begin(), wire.begin() + sent_bytes);
                if (errorcode_t::success != server_flight_send_ret) {
                    return server_flight_send_ret;
                }
                if (sent_bytes != wire.size()) {
                    return errorcode_t::send_failure;
                }
                return errorcode_t::success;
            });
        });

        binary_t client_hello_wire;
        ret = test_write_tls12_renegotiation_client_hello_record(peer_session, client_hello_wire);
        _test_case.test(ret, function_name, "construct the protected RFC 5746 renegotiation ClientHello");
        if (errorcode_t::success != ret) {
            break;
        }

        initial_server_recordno = server_session->get_recordno(from_server);
        sender = std::thread([&]() {
            sender_started.store(true, std::memory_order_release);
            send_ret = server_socket.send(server_transport, "pending", 7, &sent);
            sender_finished.store(true, std::memory_order_release);
        });
        while (false == sender_started.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        _test_case.assert(false == sender_finished.load(std::memory_order_acquire), function_name,
                          "keep the application sender waiting for the peer ClientHello and server flight");

        size_t peer_sent = 0;
        while (peer_sent < client_hello_wire.size()) {
            size_t sent_bytes = 0;
            ret = peer_transport.send((const char*)client_hello_wire.data() + peer_sent, client_hello_wire.size() - peer_sent, &sent_bytes);
            if ((errorcode_t::success != ret) || (0 == sent_bytes)) {
                break;
            }
            peer_sent += sent_bytes;
        }
        _test_case.test(ret, function_name, "send the protected renegotiation ClientHello over TCP");
        _test_case.assert(client_hello_wire.size() == peer_sent, function_name, "send the complete ClientHello record");
        if ((errorcode_t::success != ret) || (client_hello_wire.size() != peer_sent)) {
            break;
        }

        // Read the complete ClientHello from the accepted TCP socket without
        // parsing it yet, so the production TLS parser can process the exact
        // buffered record after the peer has sent it.
        binary_t received(client_hello_wire.size());
        size_t received_offset = 0;
        while (received_offset < received.size()) {
            size_t received_bytes = 0;
            ret = server_socket.naive_tcp_server_socket::read(server_transport, 0, (char*)received.data() + received_offset, received.size() - received_offset,
                                                              &received_bytes);
            if (errorcode_t::success != ret) {
                break;
            }
            if (0 == received_bytes) {
                ret = errorcode_t::closed;
                break;
            }
            received_offset += received_bytes;
        }
        _test_case.test(ret, function_name, "receive the complete protected ClientHello before resetting the TCP peer");
        _test_case.assert(received == client_hello_wire, function_name, "preserve the exact protected ClientHello bytes");
        if ((errorcode_t::success != ret) || (received != client_hello_wire)) {
            break;
        }

        // Parse the buffered ClientHello. The status hook writes a strict
        // prefix of the first server-flight record to the peer TCP socket.
        size_t input_size = received.size();
        ret = server_socket.read(server_transport, tls_io_flag_t::read_bio_write, (char*)received.data(), received.size(), &input_size);
        _test_case.assert(errorcode_t::success == server_flight_send_ret, function_name, "the underlying TCP send accepts the deliberately shortened write");
        _test_case.assert((0 < server_flight_sent_bytes) && (server_flight_sent_bytes + 1 == server_flight_wire_size), function_name,
                          "write exactly all but the final byte of the TLS server-flight record");
        _test_case.assert(errorcode_t::send_failure == ret, function_name, "propagate send_failure when the server-flight TCP write is short");
        binary_t received_prefix(server_flight_sent_bytes);
        size_t received_prefix_offset = 0;
        while (received_prefix_offset < received_prefix.size()) {
            size_t received_bytes = 0;
            return_t read_ret =
                peer_transport.read((char*)received_prefix.data() + received_prefix_offset, received_prefix.size() - received_prefix_offset, &received_bytes);
            if (((errorcode_t::success != read_ret) && (errorcode_t::more_data != read_ret)) || (0 == received_bytes)) {
                break;
            }
            received_prefix_offset += received_bytes;
        }
        _test_case.assert(received_prefix.size() == received_prefix_offset, function_name, "receive the partial TLS server-flight record prefix at the raw TCP peer");
        _test_case.assert(received_prefix == server_flight_prefix, function_name, "verify the exact prefix written before the short-write failure");
        _test_case.assert(1 == server_flight_send_attempts.load(std::memory_order_acquire), function_name, "attempt exactly one server-flight TCP send");
        _test_case.assert(server_session->is_terminal(), function_name, "terminalize the TLS session after the short TCP write");
        _test_case.assert(initial_server_recordno + 1 == server_session->get_recordno(from_server), function_name,
                          "serialize only the first server-flight record before the short write is reported");
    } while (false);

    if ((nullptr != server_session) && (true == sender_started.load(std::memory_order_acquire)) && (false == sender_finished.load(std::memory_order_acquire))) {
        server_session->mark_terminal();
        server_session->get_secure_prosumer()->notify_transport_closed();
    }
    if (sender.joinable()) {
        sender.join();
    }

    if (true == sender_started.load(std::memory_order_acquire)) {
        _test_case.assert(errorcode_t::disconnect == send_ret, function_name, "wake the waiting application sender with disconnect (actual return 0x%08x)",
                          static_cast<uint32>(send_ret));
        _test_case.assert(0 == sent, function_name, "report no application bytes sent after the short TCP write");
    }

    peer_transport.close();
    if (INVALID_SOCKET != accepted_socket) {
        server_socket.tls_accept_fails(accepted_socket);
    }
    if (nullptr != server_transport) {
        server_socket.close(server_transport);
    }
    if (nullptr != listen_context) {
        server_socket.close(listen_context);
    }
}

static void test_tls12_server_send_retires_through_network_event_loop_loopback_tcp() {
    // Scenario: a real network_server owns an accepted TLS 1.2 session on
    // Linux epoll or Windows IOCP. The application send reaches the reserve
    // while local renegotiation is disabled.
    // Action: production retire_transport() marks the session terminal and
    // shuts down the accepted socket; the peer observes EOF and closes.
    // Expected: the platform event loop dispatches session_closed(), removes
    // the session mapping, emits one disconnect callback, and releases the
    // accepted socket_context_t through network_session destruction.
    const char* function_name = __FUNCTION__;
    _test_case.begin("TLS 1.2 reserve retirement closes the accepted socket through the network event loop");

    test_tls12_network_server_retirement_state state;
    test_tls12_network_server_socket server_socket(&state);
    network_server server;
    network_multiplexer_context_t* server_context = nullptr;
    naive_tcp_client_socket peer_transport;
    peer_transport.set_wto(3000);

    bool server_open = false;
    bool peer_connected = false;
    return_t ret = errorcode_t::success;
    return_t send_ret = errorcode_t::internal_error;
    return_t peer_read_ret = errorcode_t::internal_error;
    size_t application_bytes_sent = 0;
    size_t peer_bytes_received = 0;

    server_conf conf;
    conf.set(netserver_config_t::serverconf_concurrent_event, 16);
    conf.set(netserver_config_t::serverconf_concurrent_tls_accept, 1);
    conf.set(netserver_config_t::serverconf_concurrent_network, 1);
    conf.set(netserver_config_t::serverconf_concurrent_consume, 1);

    do {
        ret = server.open(&server_context, AF_INET, 0, &server_socket, &conf, test_tls12_network_server_retirement_callback, &state);
        _test_case.test(ret, function_name, "open the real TLS network_server on an ephemeral loopback port");
        if (errorcode_t::success != ret) {
            break;
        }
        server_open = true;

        const uint16 listen_port = state.listen_port.load(std::memory_order_acquire);
        _test_case.assert(0 != listen_port, function_name, "capture the ephemeral listener port");
        if (0 == listen_port) {
            break;
        }

        ret = server.event_loop_run(server_context, 1);
        _test_case.test(ret, function_name, "start the platform network event loop");
        if (errorcode_t::success != ret) {
            break;
        }

        ret = peer_transport.connect("127.0.0.1", listen_port, 3);
        _test_case.test(ret, function_name, "connect a raw loopback TCP peer to the network_server");
        if (errorcode_t::success != ret) {
            break;
        }
        peer_connected = true;

        ret = state.connected.wait(3000);
        _test_case.test(ret, function_name, "wait for TLS accept and network_session registration");
        if (errorcode_t::success != ret) {
            break;
        }

        auto transport = state.transport.load(std::memory_order_acquire);
        auto session = state.session.load(std::memory_order_acquire);
        _test_case.assert((nullptr != transport) && (nullptr != session), function_name, "capture the accepted TLS socket context and session");
        if ((nullptr == transport) || (nullptr == session)) {
            break;
        }

        ret = test_configure_tls12_live_peer_session(*session);
        _test_case.test(ret, function_name, "seed the accepted TLS session with established TLS 1.2 state");
        if (errorcode_t::success != ret) {
            break;
        }

        // Force the production reserve path to retire rather than renegotiate.
        session->get_keyvalue().set(session_conf_enable_tls12_renegotiation, 0);
        constexpr uint64 sequence_max = ~static_cast<uint64>(0);
        constexpr uint64 sequence_reserve = 65535;
        constexpr uint64 sequence_reserve_start = sequence_max - (sequence_reserve - 1);
        session->set_recordno(from_server, sequence_reserve_start);

        const char application_payload[] = "must-not-send";
        send_ret = server_socket.send(transport, application_payload, sizeof(application_payload) - 1, &application_bytes_sent);
        _test_case.assert(errorcode_t::exceed == send_ret, function_name, "refuse the reserved application record and return exceed (actual 0x%08x)",
                          static_cast<uint32>(send_ret));
        _test_case.assert(0 == application_bytes_sent, function_name, "report zero application bytes sent");
        _test_case.assert(session->is_terminal(), function_name, "mark the TLS session terminal before event-loop retirement");

        // The production shutdown must be visible to the peer before it closes.
        char peer_buffer[16] = {};
        peer_read_ret = peer_transport.read(peer_buffer, sizeof(peer_buffer), &peer_bytes_received);
        _test_case.assert(errorcode_t::closed == peer_read_ret, function_name, "observe EOF from production socket shutdown (actual 0x%08x)",
                          static_cast<uint32>(peer_read_ret));
        _test_case.assert(0 == peer_bytes_received, function_name, "do not deliver the application payload to the peer");
        peer_transport.close();
        peer_connected = false;

        ret = state.disconnected.wait(3000);
        _test_case.test(ret, function_name, "receive the network_server disconnect callback from epoll/IOCP");
        ret = state.accepted_context_closed.wait(3000);
        _test_case.test(ret, function_name, "release the accepted socket_context_t after session_closed");
        _test_case.assert(1 == state.disconnect_count.load(std::memory_order_acquire), function_name, "dispatch exactly one disconnect callback");
        _test_case.assert(1 == state.accepted_context_close_count.load(std::memory_order_acquire), function_name, "close the accepted socket context exactly once");
    } while (false);

    if (true == peer_connected) {
        peer_transport.close();
    }
    if (true == server_open) {
        return_t close_ret = server.close(server_context);
        _test_case.test(close_ret, function_name, "stop the network_server and release its listener/event-loop resources");
        server_context = nullptr;
    }

    // server.close() joins the event-loop threads. Only then is it safe to
    // release the test's independent reference to the captured TLS session.
    auto retained_session = state.session.exchange(nullptr, std::memory_order_acq_rel);
    if (nullptr != retained_session) {
        retained_session->release();
    }
}

void testcase_gpt_loopback_tcp() {
    test_tls12_socket_hello_request_loopback_tcp();
    test_tls12_client_initiated_renegotiation_loopback_tcp();
    test_tls12_server_concurrent_application_sends_loopback_tcp();
    test_tls12_server_initiated_renegotiation_loopback_tcp();
    test_tls12_server_send_retires_after_peer_fatal_alert_loopback_tcp();
    test_tls12_server_send_retires_after_peer_response_timeout_loopback_tcp();
    test_tls12_server_send_retires_after_malformed_peer_client_hello_loopback_tcp();
    test_tls12_server_send_retires_after_server_flight_callback_failure_loopback_tcp();
    test_tls12_server_send_retires_after_server_flight_os_send_failure_loopback_tcp();
    test_tls12_server_send_retires_after_server_flight_short_tcp_write_loopback_tcp();
    test_tls12_server_send_retires_through_network_event_loop_loopback_tcp();
}
