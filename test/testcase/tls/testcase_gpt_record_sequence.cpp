/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_record_sequence.cpp
 * @author GPT
 * @desc   TLS 1.2 directional record sequence reserve and no-wrap tests.
 */

#include "testcase_gpt_common.hpp"

// Isolate the low-level no-wrap tests from the application-data reserve policy.
// This test-only record keeps the normal protection/sequence processing but
// bypasses the application-data preprocessor gate.
class tls12_no_reserve_test_record : public tls_record_application_data {
   public:
    using tls_record_application_data::tls_record_application_data;

   protected:
    virtual return_t do_preprocess(tls_direction_t) override { return errorcode_t::success; }
};

static void test_configure_tls12_record_sequence_session(tls_session& session, bool cbc) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    const uint16 ciphersuite = cbc ? 0xc027 : 0xc02f;
    protection.set_cipher_suite(ciphersuite);
    session.get_keyvalue().set(session_tls_version, tls1_2);

    if (cbc) {
        protection.get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x31));
        protection.get_secrets().assign(tls_secret_t::client_mac_key, binary_t(32, 0x52));
        session.get_keyvalue().set(session_encrypt_then_mac, 0);
    } else {
        protection.get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
        protection.get_secrets().assign(tls_secret_t::client_iv, binary_t(4, 0x21));
        protection.get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x12));
        protection.get_secrets().assign(tls_secret_t::server_iv, binary_t(4, 0x22));
        session.update_session_status(session_status_server_key_exchange);
        session.update_session_status(session_status_client_key_exchange);
    }

    auto& info = session.get_session_info(from_client);
    info.set_active_cipher_suite(ciphersuite);
    info.begin_protection();
    info.set_status(tls_handshake_type_t::finished);
    session.update_session_status(session_status_server_finished);
}

static void test_tls12_batch_serialization_failure_is_terminal() {
    // Scenario: a TLS 1.2 record batch serializes one record, then fails on the next record at sequence exhaustion.
    // Action: serialize the batch and attempt a later direct record write.
    // Expected: no transport callback is invoked and the session refuses all further record I/O.
    const char* function_name = __FUNCTION__;
    constexpr uint64 terminal_recordno = ~static_cast<uint64>(0);
    const binary_t plaintext{'b', 'a', 't'};

    tls_session session;
    test_configure_tls12_record_sequence_session(session, false);
    session.set_recordno(from_client, terminal_recordno - 1);

    tls_records records;
    records.add(new tls12_no_reserve_test_record(&session, plaintext));
    records.add(new tls12_no_reserve_test_record(&session, plaintext));

    bool transport_called = false;
    return_t ret = records.write(&session, from_client, [&](tls_session*, binary_t&) -> return_t {
        transport_called = true;
        return errorcode_t::success;
    });
    _test_case.assert(errorcode_t::exceed == ret, function_name, "return the second record's sequence exhaustion");
    _test_case.assert(terminal_recordno == session.get_recordno(from_client), function_name, "retain the first record's consumed sequence");
    _test_case.assert(false == transport_called, function_name, "do not pass a partially serialized batch to transport");
    _test_case.assert(session.is_terminal(), function_name, "mark the TLS 1.2 session terminal after partial batch serialization");

    tls12_no_reserve_test_record retry(&session, plaintext);
    binary_t retry_wire;
    ret = retry.write(from_client, retry_wire);
    _test_case.assert(errorcode_t::disconnect == ret, function_name, "reject later record writes on the terminal session");
    _test_case.assert(true == retry_wire.empty(), function_name, "emit no record after terminal serialization failure");

    const binary_t blocked_input{0x17, 0x03, 0x03, 0x00, 0x00};
    size_t pos = 0;
    ret = retry.read(from_client, blocked_input.data(), blocked_input.size(), pos);
    _test_case.assert(errorcode_t::disconnect == ret, function_name, "reject later record reads on the terminal session");
    _test_case.assert(0 == pos, function_name, "consume no input after terminal serialization failure");
}

static void test_tls12_application_data_sequence_reserve() {
    // Scenario: one TLS 1.2 directional sequence reaches the first reserved value.
    // Action: accept the preceding application-data record, then try application
    // data again on both the writer and reader at the reserve boundary.
    // Expected: exactly 65,535 sequence values remain unused; the refusal does
    // not consume the counter or mark the session terminal.
    const char* function_name = __FUNCTION__;
    constexpr uint64 sequence_max = ~static_cast<uint64>(0);
    constexpr uint64 reserve = 65535;
    constexpr uint64 reserve_start = sequence_max - (reserve - 1);
    const binary_t plaintext{'r', 's', 'v'};

    auto verify_direction = [&](tls_direction_t dir) -> void {
        tls_session writer;
        test_configure_tls12_record_sequence_session(writer, false);
        if (from_server == dir) {
            auto& info = writer.get_session_info(dir);
            info.set_active_cipher_suite(0xc02f);
            info.begin_protection();
            info.set_status(tls_handshake_type_t::finished);
        }
        writer.set_recordno(dir, reserve_start - 1);

        tls_record_application_data allowed_outbound(&writer, plaintext);
        binary_t wire;
        return_t ret = allowed_outbound.write(dir, wire);
        _test_case.test(ret, function_name, "allow the final application-data record before the reserve");
        _test_case.assert(reserve_start == writer.get_recordno(dir), function_name, "advance exactly to the first reserved sequence value");
        _test_case.assert(false == wire.empty(), function_name, "serialize application data immediately before the reserve");

        tls_record_application_data blocked_outbound(&writer, plaintext);
        binary_t blocked_wire;
        ret = blocked_outbound.write(dir, blocked_wire);
        _test_case.assert(errorcode_t::exceed == ret, function_name, "refuse outbound application data at the reserve boundary");
        _test_case.assert(true == blocked_wire.empty(), function_name, "emit no bytes for a reserve refusal");
        _test_case.assert(reserve_start == writer.get_recordno(dir), function_name, "preserve the write sequence at the reserve boundary");
        _test_case.assert(false == writer.is_terminal(), function_name, "keep the session usable for control traffic after intentional refusal");

        tls_session reader;
        test_configure_tls12_record_sequence_session(reader, false);
        if (from_server == dir) {
            auto& info = reader.get_session_info(dir);
            info.set_active_cipher_suite(0xc02f);
            info.begin_protection();
            info.set_status(tls_handshake_type_t::finished);
        }
        reader.set_recordno(dir, reserve_start - 1);

        tls_record_application_data allowed_inbound(&reader);
        size_t pos = 0;
        ret = allowed_inbound.read(dir, wire.data(), wire.size(), pos);
        _test_case.test(ret, function_name, "accept inbound application data immediately before the reserve");
        _test_case.assert(wire.size() == pos, function_name, "consume the complete pre-reserve record");
        _test_case.assert(reserve_start == reader.get_recordno(dir), function_name, "advance the read sequence to the first reserved value");

        const binary_t blocked_input{0x17, 0x03, 0x03, 0x00, 0x00};
        tls_record_application_data blocked_inbound(&reader);
        pos = 0;
        ret = blocked_inbound.read(dir, blocked_input.data(), blocked_input.size(), pos);
        _test_case.assert(errorcode_t::exceed == ret, function_name, "refuse inbound application data at the reserve boundary");
        _test_case.assert(0 == pos, function_name, "consume no bytes for a reserve refusal");
        _test_case.assert(reserve_start == reader.get_recordno(dir), function_name, "preserve the read sequence at the reserve boundary");
        _test_case.assert(false == reader.is_terminal(), function_name, "do not terminalize the session for intentional inbound refusal");
    };

    verify_direction(from_client);
    verify_direction(from_server);
}

static void test_tls12_inbound_application_data_reserve_retires_secure_consumer() {
    // Scenario: a peer sends protected TLS 1.2 application data after the local
    // receive direction has entered its reserved sequence range.
    // Action: pass the record through the secure prosumer, not only the record API.
    // Expected: refuse the record, retire the TLS session/secure consumer, and
    // wake application readers instead of leaving the same record buffered forever.
    const char* function_name = __FUNCTION__;
    constexpr uint64 sequence_max = ~static_cast<uint64>(0);
    constexpr uint64 reserve = 65535;
    constexpr uint64 reserve_start = sequence_max - (reserve - 1);

    tls_session session;
    session.set_type(session_type_t::tls);
    test_configure_tls12_record_sequence_session(session, false);
    session.set_recordno(from_client, reserve_start);

    secure_prosumer prosumer;
    const binary_t blocked_input{0x17, 0x03, 0x03, 0x00, 0x00};
    return_t ret = prosumer.produce(&session, from_client, blocked_input.data(), blocked_input.size());
    _test_case.assert(errorcode_t::exceed == ret, function_name, "surface the inbound application-data reserve refusal");
    _test_case.assert(session.is_terminal(), function_name, "mark the TLS session terminal after inbound reserve refusal");
    _test_case.assert(reserve_start == session.get_recordno(from_client), function_name, "preserve the inbound record sequence at the reserve boundary");
    _test_case.assert(0 == test_count_fatal_alerts(session, from_client), function_name, "do not misreport the local reserve policy as a peer protocol alert");

    char output[1] = {};
    size_t read = 0;
    ret = prosumer.consume(SOCK_STREAM, 0, output, sizeof(output), &read);
    _test_case.assert(errorcode_t::disconnect == ret, function_name, "wake application readers with a terminal secure-consumer result");
    _test_case.assert(0 == read, function_name, "deliver no plaintext from the refused record");
}

static void test_tls12_record_sequence_no_wrap() {
    // Scenario: a TLS 1.2 directional record sequence reaches its final representable transition.
    // Action: transmit and receive the record using UINT64_MAX - 1, then attempt another record.
    // Expected: the final non-wrapping record succeeds; the next read/write is rejected without wrapping.
    const char* function_name = __FUNCTION__;
    constexpr uint64 terminal_recordno = ~static_cast<uint64>(0);
    const binary_t plaintext{'s', 'e', 'q'};

    auto verify_cipher = [&](bool cbc) -> void {
        const uint16 ciphertext_size = cbc ? 32 : 24;

        tls_session writer;
        test_configure_tls12_record_sequence_session(writer, cbc);
        writer.set_recordno(from_client, terminal_recordno - 1);

        tls12_no_reserve_test_record outbound(&writer, plaintext);
        binary_t wire;
        return_t ret = outbound.write(from_client, wire);
        _test_case.test(ret, function_name, "write the final non-wrapping TLS 1.2 record");
        _test_case.assert(false == wire.empty(), function_name, "serialize the final non-wrapping TLS 1.2 record");
        _test_case.assert(terminal_recordno == writer.get_recordno(from_client), function_name, "advance to the terminal sequence without wrapping");
        _test_case.assert(0 == writer.get_recordno(from_server), function_name, "leave the opposite write direction unchanged");

        tls_session reader;
        test_configure_tls12_record_sequence_session(reader, cbc);
        reader.set_recordno(from_client, terminal_recordno - 1);

        tls12_no_reserve_test_record inbound(&reader);
        size_t pos = 0;
        ret = inbound.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, function_name, "read the final non-wrapping TLS 1.2 record");
        _test_case.assert(terminal_recordno == reader.get_recordno(from_client), function_name, "advance the read sequence to the terminal value without wrapping");
        _test_case.assert(0 == reader.get_recordno(from_server), function_name, "leave the opposite read direction unchanged");

        tls12_no_reserve_test_record blocked_outbound(&writer, plaintext);
        binary_t blocked_wire;
        ret = blocked_outbound.write(from_client, blocked_wire);
        _test_case.assert(errorcode_t::exceed == ret, function_name, "refuse a TLS 1.2 write that would wrap the sequence number");
        _test_case.assert(true == blocked_wire.empty(), function_name, "emit no record after TLS 1.2 write-sequence exhaustion");
        _test_case.assert(terminal_recordno == writer.get_recordno(from_client), function_name, "preserve the terminal write sequence");
        _test_case.assert(1 == test_count_fatal_alert(writer, from_client, tls_alertdesc_t::internal_error), function_name,
                          "queue fatal internal_error for TLS 1.2 write-sequence exhaustion");

        binary_t terminal_wire{0x17, 0x03, 0x03, static_cast<byte_t>(ciphertext_size >> 8), static_cast<byte_t>(ciphertext_size)};
        terminal_wire.insert(terminal_wire.end(), ciphertext_size, 0);
        tls12_no_reserve_test_record blocked_inbound(&reader);
        pos = 0;
        ret = blocked_inbound.read(from_client, terminal_wire.data(), terminal_wire.size(), pos);
        _test_case.assert(errorcode_t::exceed == ret, function_name, "refuse a TLS 1.2 read that would wrap the sequence number");
        _test_case.assert(terminal_recordno == reader.get_recordno(from_client), function_name, "preserve the terminal read sequence");
        _test_case.assert(1 == test_count_fatal_alert(reader, from_client, tls_alertdesc_t::internal_error), function_name,
                          "queue fatal internal_error for TLS 1.2 read-sequence exhaustion");
    };

    verify_cipher(false);  // AES-GCM
    verify_cipher(true);   // CBC MtE
}

void testcase_gpt_record_sequence() {
    test_tls12_batch_serialization_failure_is_terminal();
    test_tls12_application_data_sequence_reserve();
    test_tls12_inbound_application_data_reserve_retires_secure_consumer();
    test_tls12_record_sequence_no_wrap();
}
