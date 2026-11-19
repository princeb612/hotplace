/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_early_data_buffer.cpp
 * @author GPT
 * @desc   TLS 1.3 in-flight early-data buffering, discard limits, and rejected-0-RTT record handling.
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>
#include <utility>

#include "testcase_gpt_common.hpp"

static void test_tls13_server_defers_inflight_early_data_until_encrypted_extensions() {
    // Scenario under test: TLS 1.3 server defers in-flight early data until EncryptedExtensions decides acceptance.
    // Action: prepare a valid protected 0-RTT record for the server.
    // Expected: commit ClientHello state after a one-to-three-byte header split.
    _test_case.begin("TLS 1.3 server defers in-flight early data until EncryptedExtensions decides acceptance");

    tls_session client;
    client.set_type(session_type_t::tls);
    auto& client_protection = client.get_tls_protection();
    client_protection.set_tls_version(tls_13);
    client_protection.set_cipher_suite(0x1301);
    client_protection.set_flow(tls_flow_t::zero_rtt);
    client_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
    client_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
    client.update_session_status(session_status_client_hello);
    client.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    client.get_session_info(from_client).begin_protection();
    auto& client_early_state = client.get_session_info(from_server).get_keyvalue();
    client_early_state.set(session_early_data_offered, 1);
    client_early_state.set(session_early_data_limit, 4);
    client_early_state.set(session_early_data_sent, 0);

    tls_record_application_data client_early_record(&client);
    client_early_record.set_binary(binary_t{0x31, 0x32, 0x33});
    binary_t early_record_wire;
    return_t ret = client_early_record.write(from_client, early_record_wire);
    _test_case.test(ret, __FUNCTION__, "prepare a valid protected 0-RTT record for the server");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session coalesced_client;
    coalesced_client.set_type(session_type_t::tls);
    auto& coalesced_client_protection = coalesced_client.get_tls_protection();
    coalesced_client_protection.set_tls_version(tls_13);
    coalesced_client_protection.set_cipher_suite(0x1301);
    // Generate an ordinary valid ClientHello, then add early_data to its
    // serialized extension vector below. The fixture has no PSK ticket, so
    // its composer flow must remain one_rtt.
    coalesced_client_protection.set_flow(tls_flow_t::one_rtt);
    binary_t coalesced_client_hello_wire;
    ret = test_client_supportedversion_clienthello(&coalesced_client, tls_13, tls_13, coalesced_client_hello_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a baseline TLS 1.3 ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Scenario: retain incomplete ClientHello records until the complete record body arrives
    {
        // A TCP input chunk may end after part of the TLS record header, after the
        // complete header, or in the middle of the record body. Preserve the
        // incomplete tail and parse the ClientHello only after its final byte.
        for (size_t header_fragment_size = 1; header_fragment_size < 4; ++header_fragment_size) {
            tls_session partial_header_server;
            partial_header_server.set_type(session_type_t::tls);
            partial_header_server.get_tls_protection().set_tls_version(tls_13);
            partial_header_server.get_tls_protection().set_cipher_suite(0x1301);
            auto partial_header_prosumer = partial_header_server.get_secure_prosumer();
            ret = partial_header_prosumer->produce(&partial_header_server, from_client, coalesced_client_hello_wire.data(), header_fragment_size);
            _test_case.test(ret, __FUNCTION__, "retain a one-to-three-byte TLS record header fragment");
            if (errorcode_t::success != ret) {
                return;
            }
            ret = partial_header_prosumer->produce(&partial_header_server, from_client, coalesced_client_hello_wire.data() + header_fragment_size,
                                                   coalesced_client_hello_wire.size() - header_fragment_size);
            _test_case.test(ret, __FUNCTION__, "parse ClientHello after the remaining record bytes arrive");
            _test_case.assert(0 != (partial_header_server.get_session_status() & session_status_client_hello), __FUNCTION__,
                              "commit ClientHello state after a one-to-three-byte header split");
            if (errorcode_t::success != ret) {
                return;
            }
        }

        tls_session fragmented_client_hello_server;
        fragmented_client_hello_server.set_type(session_type_t::tls);
        fragmented_client_hello_server.get_tls_protection().set_tls_version(tls_13);
        fragmented_client_hello_server.get_tls_protection().set_cipher_suite(0x1301);
        auto fragmented_client_hello_prosumer = fragmented_client_hello_server.get_secure_prosumer();
        size_t fragmented_pos = 0;
        const size_t fragmented_sizes[] = {4, 1, 7};
        for (size_t i = 0; i < RTL_NUMBER_OF(fragmented_sizes); ++i) {
            ret = fragmented_client_hello_prosumer->produce(&fragmented_client_hello_server, from_client, coalesced_client_hello_wire.data() + fragmented_pos,
                                                            fragmented_sizes[i]);
            _test_case.test(ret, __FUNCTION__, "retain a partial ClientHello TLS record across input chunks");
            fragmented_pos += fragmented_sizes[i];
            if (errorcode_t::success != ret) {
                return;
            }
        }
        ret = fragmented_client_hello_prosumer->produce(&fragmented_client_hello_server, from_client, coalesced_client_hello_wire.data() + fragmented_pos,
                                                        coalesced_client_hello_wire.size() - fragmented_pos);
        _test_case.test(ret, __FUNCTION__, "parse a fragmented ClientHello after the complete TLS record arrives");
        _test_case.assert(0 != (fragmented_client_hello_server.get_session_status() & session_status_client_hello), __FUNCTION__,
                          "commit ClientHello state only after its complete record body is received");

        // Pin the exact five-byte record-header boundary and distinct partial-body
        // offsets. None of these prefixes may commit ClientHello before the body
        // is complete; the remaining bytes must produce the same final state.
        const size_t client_hello_record_body_size = (static_cast<size_t>(coalesced_client_hello_wire[3]) << 8) | coalesced_client_hello_wire[4];
        const size_t client_hello_split_sizes[] = {5, 6, 5 + client_hello_record_body_size / 2};
        for (size_t i = 0; i < RTL_NUMBER_OF(client_hello_split_sizes); ++i) {
            const size_t split_size = client_hello_split_sizes[i];
            if (split_size >= coalesced_client_hello_wire.size()) {
                _test_case.assert(false, __FUNCTION__, "ClientHello split point is inside the record");
                return;
            }

            tls_session split_client_hello_server;
            split_client_hello_server.set_type(session_type_t::tls);
            split_client_hello_server.get_tls_protection().set_tls_version(tls_13);
            split_client_hello_server.get_tls_protection().set_cipher_suite(0x1301);
            auto split_client_hello_prosumer = split_client_hello_server.get_secure_prosumer();
            ret = split_client_hello_prosumer->produce(&split_client_hello_server, from_client, coalesced_client_hello_wire.data(), split_size);
            _test_case.test(ret, __FUNCTION__, "retain ClientHello at a record-header or partial-body boundary");
            _test_case.assert(0 == (split_client_hello_server.get_session_status() & session_status_client_hello), __FUNCTION__,
                              "do not commit ClientHello before the complete record body arrives");
            if (errorcode_t::success != ret) {
                return;
            }

            ret = split_client_hello_prosumer->produce(&split_client_hello_server, from_client, coalesced_client_hello_wire.data() + split_size,
                                                       coalesced_client_hello_wire.size() - split_size);
            _test_case.test(ret, __FUNCTION__, "complete ClientHello after a header/body boundary split");
            _test_case.assert(0 != (split_client_hello_server.get_session_status() & session_status_client_hello), __FUNCTION__,
                              "commit ClientHello after the remaining record body arrives");
            if (errorcode_t::success != ret) {
                return;
            }
        }
    }

    // Scenario: enforce pending-ciphertext limits when ClientHello and early data arrive together
    {
        // Add psk_key_exchange_modes, early_data, and a structurally valid
        // pre_shared_key extension. RFC 8446 requires the modes extension when PSK
        // is offered and pre_shared_key to be the final ClientHello extension.
        if (coalesced_client_hello_wire.size() < 9 || coalesced_client_hello_wire[0] != 0x16 || coalesced_client_hello_wire[5] != 0x01) {
            _test_case.assert(false, __FUNCTION__, "baseline ClientHello has TLS record and handshake framing");
            return;
        }
        size_t coalesced_handshake_end = 9 + test_read_u24(coalesced_client_hello_wire, 6);
        size_t coalesced_pos = 9 + 2 + 32;
        uint8 coalesced_session_id_len = coalesced_client_hello_wire[coalesced_pos++];
        coalesced_pos += coalesced_session_id_len;
        uint16 coalesced_cipher_suites_len = test_read_u16(coalesced_client_hello_wire, coalesced_pos);
        coalesced_pos += 2 + coalesced_cipher_suites_len;
        uint8 coalesced_compression_len = coalesced_client_hello_wire[coalesced_pos++];
        coalesced_pos += coalesced_compression_len;
        size_t coalesced_extensions_len_pos = coalesced_pos;
        uint16 coalesced_extensions_len = test_read_u16(coalesced_client_hello_wire, coalesced_extensions_len_pos);
        size_t coalesced_extensions_end = coalesced_extensions_len_pos + 2 + coalesced_extensions_len;
        if (coalesced_extensions_end != coalesced_handshake_end || coalesced_handshake_end != coalesced_client_hello_wire.size()) {
            _test_case.assert(false, __FUNCTION__, "baseline ClientHello extension vector is well framed");
            return;
        }
        // early_data (empty), then pre_shared_key with one identity and one
        // 32-byte binder. The binder is only structurally parsed in this test.
        binary_t coalesced_early_data_and_psk = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x29, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x01, 0x01, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x21, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        // The composer may already include psk_key_exchange_modes. Keep the
        // synthesized ClientHello unique so this test reaches the pending-record
        // limit path rather than the independent duplicate-extension rejection.
        bool has_psk_key_exchange_modes = false;
        size_t existing_extension_pos = coalesced_extensions_len_pos + 2;
        while (existing_extension_pos + 4 <= coalesced_extensions_end) {
            uint16 extension_type = test_read_u16(coalesced_client_hello_wire, existing_extension_pos);
            uint16 extension_size = test_read_u16(coalesced_client_hello_wire, existing_extension_pos + 2);
            if (0x002d == extension_type) {
                has_psk_key_exchange_modes = true;
                break;
            }
            existing_extension_pos += 4 + extension_size;
        }
        if (has_psk_key_exchange_modes) {
            coalesced_early_data_and_psk.erase(coalesced_early_data_and_psk.begin(), coalesced_early_data_and_psk.begin() + 6);
        }
        coalesced_client_hello_wire.insert(coalesced_client_hello_wire.end(), coalesced_early_data_and_psk.begin(), coalesced_early_data_and_psk.end());
        test_write_u16(coalesced_client_hello_wire, coalesced_extensions_len_pos, coalesced_extensions_len + coalesced_early_data_and_psk.size());
        test_write_u24(coalesced_client_hello_wire, 6, test_read_u24(coalesced_client_hello_wire, 6) + coalesced_early_data_and_psk.size());
        test_write_u16(coalesced_client_hello_wire, 3, test_read_u16(coalesced_client_hello_wire, 3) + coalesced_early_data_and_psk.size());

        tls_session coalesced_server;
        coalesced_server.set_type(session_type_t::tls);
        auto& coalesced_server_protection = coalesced_server.get_tls_protection();
        coalesced_server_protection.set_tls_version(tls_13);
        coalesced_server_protection.set_cipher_suite(0x1301);
        coalesced_server_protection.set_flow(tls_flow_t::zero_rtt);
        coalesced_server_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
        coalesced_server_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
        binary_t coalesced_input = coalesced_client_hello_wire;
        coalesced_input.insert(coalesced_input.end(), early_record_wire.begin(), early_record_wire.end());
        auto coalesced_prosumer = coalesced_server.get_secure_prosumer();
        coalesced_prosumer->set_pending_early_data_buffer_limit(1);
        ret = coalesced_prosumer->produce(&coalesced_server, from_client, coalesced_input.data(), coalesced_input.size());
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the pending ciphertext limit when ClientHello and 0-RTT arrive in one input chunk");
        _test_case.assert(0 == coalesced_server.get_session_status(), __FUNCTION__, "reset the handshake after coalesced pending ciphertext overflow");

        tls_session oversized_coalesced_server;
        oversized_coalesced_server.set_type(session_type_t::tls);
        auto& oversized_coalesced_protection = oversized_coalesced_server.get_tls_protection();
        oversized_coalesced_protection.set_tls_version(tls_13);
        oversized_coalesced_protection.set_cipher_suite(0x1301);
        oversized_coalesced_protection.set_flow(tls_flow_t::zero_rtt);
        oversized_coalesced_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
        oversized_coalesced_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
        auto oversized_coalesced_prosumer = oversized_coalesced_server.get_secure_prosumer();
        oversized_coalesced_prosumer->set_pending_early_data_buffer_limit(0);
        const size_t pending_record_wire_limit = 5 + 0xffff;
        const size_t pending_record_buffer_limit = 64 * pending_record_wire_limit;
        binary_t oversized_coalesced_input = coalesced_client_hello_wire;
        const size_t oversized_early_data_offset = oversized_coalesced_input.size();
        oversized_coalesced_input.resize(oversized_early_data_offset + pending_record_buffer_limit + 1, 0);
        for (size_t i = 0; i < 64; ++i) {
            size_t record_pos = oversized_early_data_offset + i * pending_record_wire_limit;
            oversized_coalesced_input[record_pos] = 0x17;
            oversized_coalesced_input[record_pos + 1] = 0x03;
            oversized_coalesced_input[record_pos + 2] = 0x03;
            oversized_coalesced_input[record_pos + 3] = 0xff;
            oversized_coalesced_input[record_pos + 4] = 0xff;
        }
        ret = oversized_coalesced_prosumer->produce(&oversized_coalesced_server, from_client, oversized_coalesced_input.data(), oversized_coalesced_input.size());
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__,
                          "reject coalesced 0-RTT input beyond the hard buffer ceiling after parsing ClientHello but before buffering early records");
        _test_case.assert(0 == oversized_coalesced_server.get_session_status(), __FUNCTION__, "reset the handshake after coalesced hard-buffer overflow");
    }

    auto prepare_server = [&](tls_session& session, bool eligible) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        protection.set_flow(tls_flow_t::zero_rtt);
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, binary_t(16, 0x11));
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, binary_t(12, 0x22));
        protection.reset_transcript_hash(&session);
        session.update_session_status(session_status_client_hello);
        session.update_session_status(session_status_server_hello);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::server_hello);
        session.get_session_info(from_client).begin_protection();
        session.get_keyvalue().set(session_server_psk_selected_identity, 0);
        session.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);

        tls_resumption_ticket ticket;
        ticket.identity = binary_t{0x01};
        ticket.version = static_cast<uint16>(tls_13);
        ticket.cipher_suite = 0x1301;
        ticket.max_early_data_size = 4;
        session.set_early_data_ticket(ticket);

        auto& early_state = session.get_session_info(from_server).get_keyvalue();
        early_state.set(session_early_data_offered, 1);
        early_state.set(session_early_data_accepted, 0);
        early_state.set(session_early_data_limit, eligible ? 4 : 0);
        early_state.set(session_early_data_received, 0);
        early_state.set(session_early_data_discard_limit, 4096);
        early_state.set(session_early_data_discarded, 0);
    };

    tls_session accepted_server;
    prepare_server(accepted_server, true);
    auto accepted_prosumer = accepted_server.get_secure_prosumer();
    _test_case.assert((1024 * 1024) == accepted_prosumer->get_pending_early_data_buffer_limit(), __FUNCTION__,
                      "apply a bounded 1 MiB pending ciphertext buffer by default");
    accepted_prosumer->set_pending_early_data_buffer_limit(early_record_wire.size());
    _test_case.assert(early_record_wire.size() == accepted_prosumer->get_pending_early_data_buffer_limit(), __FUNCTION__,
                      "allow the server to configure the pending ciphertext buffer limit");
    size_t first_fragment_size = 7;
    ret = accepted_prosumer->produce(&accepted_server, from_client, early_record_wire.data(), first_fragment_size);
    _test_case.test(ret, __FUNCTION__, "buffer a partial in-flight 0-RTT record until the server's EncryptedExtensions decision");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 == accepted_server.get_session_info(from_server).get_keyvalue().get(session_early_data_received), __FUNCTION__,
                      "do not decrypt or account early data before the server decides");
    char accepted_output[8] = {};
    size_t accepted_read = 0;
    accepted_prosumer->consume(0, 0, accepted_output, sizeof(accepted_output), &accepted_read);
    _test_case.assert(0 == accepted_read, __FUNCTION__, "do not deliver early data before EncryptedExtensions");

    tls_handshake_encrypted_extensions accepted_ee(&accepted_server);
    accepted_ee.get_extensions().add(new tls_extension_early_data(&accepted_ee));
    binary_t accepted_ee_wire;
    ret = accepted_ee.write(from_server, accepted_ee_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the acceptance signal and resume buffered early data");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == accepted_server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                      "record server acceptance before resuming in-flight early data");
    ret = accepted_prosumer->produce(&accepted_server, from_client, early_record_wire.data() + first_fragment_size, early_record_wire.size() - first_fragment_size);
    _test_case.test(ret, __FUNCTION__, "complete the buffered TLS record after EncryptedExtensions has committed acceptance");
    size_t accepted_after_ee = 0;
    ret = accepted_prosumer->consume(0, 0, accepted_output, sizeof(accepted_output), &accepted_after_ee);
    _test_case.test(ret, __FUNCTION__, "deliver buffered early data after EncryptedExtensions acceptance");
    _test_case.assert(3 == accepted_after_ee, __FUNCTION__, "deliver the complete buffered early-data payload");
    _test_case.assert(3 == accepted_server.get_session_info(from_server).get_keyvalue().get(session_early_data_received), __FUNCTION__,
                      "account the accepted early-data payload only after it is processed");
    _test_case.assert(binary_t({0x31, 0x32, 0x33}) == binary_t(accepted_output, accepted_output + accepted_after_ee), __FUNCTION__,
                      "preserve the buffered early-data plaintext");

    // Fragment the same pending 0-RTT record at multiple offsets, but deliver
    // every fragment before EncryptedExtensions. The EE write must resume and
    // process the complete retained record exactly once.
    const size_t early_record_split_sizes[] = {1, 4, 5, 6, early_record_wire.size() / 2};
    for (size_t i = 0; i < RTL_NUMBER_OF(early_record_split_sizes); ++i) {
        const size_t split_size = early_record_split_sizes[i];
        if (0 == split_size || split_size >= early_record_wire.size()) {
            _test_case.assert(false, __FUNCTION__, "early-data split point is inside the TLS record");
            return;
        }

        tls_session partitioned_accepted_server;
        prepare_server(partitioned_accepted_server, true);
        auto partitioned_accepted_prosumer = partitioned_accepted_server.get_secure_prosumer();
        partitioned_accepted_prosumer->set_pending_early_data_buffer_limit(early_record_wire.size());
        ret = partitioned_accepted_prosumer->produce(&partitioned_accepted_server, from_client, early_record_wire.data(), split_size);
        _test_case.test(ret, __FUNCTION__, "buffer the first fragment of an in-flight early-data record");
        if (errorcode_t::success != ret) {
            return;
        }
        ret = partitioned_accepted_prosumer->produce(&partitioned_accepted_server, from_client, early_record_wire.data() + split_size,
                                                     early_record_wire.size() - split_size);
        _test_case.test(ret, __FUNCTION__, "retain the complete fragmented early-data record before EncryptedExtensions");
        if (errorcode_t::success != ret) {
            return;
        }

        char partitioned_output[8] = {};
        size_t partitioned_read = 0;
        partitioned_accepted_prosumer->consume(0, 0, partitioned_output, sizeof(partitioned_output), &partitioned_read);
        _test_case.assert(0 == partitioned_read, __FUNCTION__, "do not deliver fragmented early data before the EncryptedExtensions decision");

        tls_handshake_encrypted_extensions partitioned_accepted_ee(&partitioned_accepted_server);
        partitioned_accepted_ee.get_extensions().add(new tls_extension_early_data(&partitioned_accepted_ee));
        binary_t partitioned_accepted_ee_wire;
        ret = partitioned_accepted_ee.write(from_server, partitioned_accepted_ee_wire);
        _test_case.test(ret, __FUNCTION__, "resume the complete fragmented early-data record after EncryptedExtensions acceptance");
        if (errorcode_t::success != ret) {
            return;
        }
        ret = partitioned_accepted_prosumer->consume(0, 0, partitioned_output, sizeof(partitioned_output), &partitioned_read);
        _test_case.test(ret, __FUNCTION__, "deliver accepted early data retained across multiple input chunks");
        _test_case.assert(3 == partitioned_read, __FUNCTION__, "deliver exactly one accepted early-data payload after fragmented buffering");
        _test_case.assert(binary_t({0x31, 0x32, 0x33}) == binary_t(partitioned_output, partitioned_output + partitioned_read), __FUNCTION__,
                          "preserve plaintext for fragmented pending early data");
        _test_case.assert(3 == partitioned_accepted_server.get_session_info(from_server).get_keyvalue().get(session_early_data_received), __FUNCTION__,
                          "account fragmented accepted early data exactly once");
    }

    // Coalesce multiple complete 0-RTT records with an incomplete trailing
    // record. Resuming after EncryptedExtensions must process each complete
    // record once, retain the tail, and finish it when the final bytes arrive.
    client_early_state.set(session_early_data_limit, 12);
    tls_record_application_data second_early_record(&client);
    second_early_record.set_binary(binary_t{0x41, 0x42, 0x43});
    binary_t second_early_record_wire;
    ret = second_early_record.write(from_client, second_early_record_wire);
    _test_case.test(ret, __FUNCTION__, "prepare a second sequential protected 0-RTT record");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_record_application_data third_early_record(&client);
    third_early_record.set_binary(binary_t{0x51, 0x52, 0x53});
    binary_t third_early_record_wire;
    ret = third_early_record.write(from_client, third_early_record_wire);
    _test_case.test(ret, __FUNCTION__, "prepare a third sequential protected 0-RTT record");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_session coalesced_early_server;
    prepare_server(coalesced_early_server, true);
    auto coalesced_early_ticket = coalesced_early_server.get_early_data_ticket();
    coalesced_early_ticket.max_early_data_size = 12;
    coalesced_early_server.set_early_data_ticket(coalesced_early_ticket);
    auto& coalesced_early_state = coalesced_early_server.get_session_info(from_server).get_keyvalue();
    coalesced_early_state.set(session_early_data_limit, 12);
    auto coalesced_early_prosumer = coalesced_early_server.get_secure_prosumer();
    coalesced_early_prosumer->set_pending_early_data_buffer_limit(3 * early_record_wire.size());

    binary_t coalesced_early_input = early_record_wire;
    coalesced_early_input.insert(coalesced_early_input.end(), second_early_record_wire.begin(), second_early_record_wire.end());
    const size_t third_record_prefix_size = 7;
    coalesced_early_input.insert(coalesced_early_input.end(), third_early_record_wire.begin(), third_early_record_wire.begin() + third_record_prefix_size);
    ret = coalesced_early_prosumer->produce(&coalesced_early_server, from_client, coalesced_early_input.data(), coalesced_early_input.size());
    _test_case.test(ret, __FUNCTION__, "buffer two complete coalesced 0-RTT records and an incomplete trailing record before EncryptedExtensions");
    if (errorcode_t::success != ret) {
        return;
    }

    char coalesced_early_output[16] = {};
    size_t coalesced_early_read = 0;
    coalesced_early_prosumer->consume(0, 0, coalesced_early_output, sizeof(coalesced_early_output), &coalesced_early_read);
    _test_case.assert(0 == coalesced_early_read, __FUNCTION__, "do not deliver coalesced early data before the EncryptedExtensions decision");

    tls_handshake_encrypted_extensions coalesced_early_ee(&coalesced_early_server);
    coalesced_early_ee.get_extensions().add(new tls_extension_early_data(&coalesced_early_ee));
    binary_t coalesced_early_ee_wire;
    ret = coalesced_early_ee.write(from_server, coalesced_early_ee_wire);
    _test_case.test(ret, __FUNCTION__, "resume coalesced complete early-data records after EncryptedExtensions acceptance");
    if (errorcode_t::success != ret) {
        return;
    }
    ret = coalesced_early_prosumer->consume(0, 0, coalesced_early_output, sizeof(coalesced_early_output), &coalesced_early_read);
    _test_case.assert((errorcode_t::success == ret) || (errorcode_t::more_data == ret), __FUNCTION__,
                      "deliver the first complete record retained before EncryptedExtensions");
    if ((errorcode_t::success != ret) && (errorcode_t::more_data != ret)) {
        return;
    }
    size_t second_coalesced_early_read = 0;
    ret = coalesced_early_prosumer->consume(0, 0, coalesced_early_output + coalesced_early_read, sizeof(coalesced_early_output) - coalesced_early_read,
                                            &second_coalesced_early_read);
    _test_case.assert((errorcode_t::success == ret) || (errorcode_t::more_data == ret), __FUNCTION__,
                      "deliver the second complete record retained before EncryptedExtensions");
    coalesced_early_read += second_coalesced_early_read;
    _test_case.assert(6 == coalesced_early_read, __FUNCTION__, "deliver both complete coalesced records exactly once while retaining the incomplete tail");
    _test_case.assert(binary_t({0x31, 0x32, 0x33, 0x41, 0x42, 0x43}) == binary_t(coalesced_early_output, coalesced_early_output + coalesced_early_read), __FUNCTION__,
                      "preserve the ordered plaintext from both coalesced records");
    _test_case.assert(6 == coalesced_early_state.get(session_early_data_received), __FUNCTION__,
                      "account only the two complete coalesced records before the trailing fragment is completed");

    ret = coalesced_early_prosumer->produce(&coalesced_early_server, from_client, third_early_record_wire.data() + third_record_prefix_size,
                                            third_early_record_wire.size() - third_record_prefix_size);
    _test_case.test(ret, __FUNCTION__, "complete the retained trailing 0-RTT record after EncryptedExtensions");
    if (errorcode_t::success != ret) {
        return;
    }
    size_t trailing_early_read = 0;
    ret = coalesced_early_prosumer->consume(0, 0, coalesced_early_output, sizeof(coalesced_early_output), &trailing_early_read);
    _test_case.test(ret, __FUNCTION__, "deliver the trailing record after its final fragment arrives");
    _test_case.assert(3 == trailing_early_read, __FUNCTION__, "deliver the trailing record exactly once");
    _test_case.assert(binary_t({0x51, 0x52, 0x53}) == binary_t(coalesced_early_output, coalesced_early_output + trailing_early_read), __FUNCTION__,
                      "preserve plaintext from the completed trailing record");
    _test_case.assert(9 == coalesced_early_state.get(session_early_data_received), __FUNCTION__, "account all coalesced and trailing early-data records exactly once");

    // Exercise every two-chunk partition of the coalesced stream. This pins
    // chunking invariance across record headers, record bodies, record
    // boundaries, and the incomplete trailing record.
    for (size_t split_size = 1; split_size < coalesced_early_input.size(); ++split_size) {
        tls_session partitioned_coalesced_server;
        prepare_server(partitioned_coalesced_server, true);
        auto partitioned_coalesced_ticket = partitioned_coalesced_server.get_early_data_ticket();
        partitioned_coalesced_ticket.max_early_data_size = 12;
        partitioned_coalesced_server.set_early_data_ticket(partitioned_coalesced_ticket);
        auto& partitioned_coalesced_state = partitioned_coalesced_server.get_session_info(from_server).get_keyvalue();
        partitioned_coalesced_state.set(session_early_data_limit, 12);

        auto partitioned_coalesced_prosumer = partitioned_coalesced_server.get_secure_prosumer();
        partitioned_coalesced_prosumer->set_pending_early_data_buffer_limit(3 * early_record_wire.size());
        ret = partitioned_coalesced_prosumer->produce(&partitioned_coalesced_server, from_client, coalesced_early_input.data(), split_size);
        _test_case.test(ret, __FUNCTION__, "retain the first partition of coalesced early-data records");
        if (errorcode_t::success != ret) {
            return;
        }
        ret = partitioned_coalesced_prosumer->produce(&partitioned_coalesced_server, from_client, coalesced_early_input.data() + split_size,
                                                      coalesced_early_input.size() - split_size);
        _test_case.test(ret, __FUNCTION__, "process the second partition of coalesced early-data records");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(0 == partitioned_coalesced_state.get(session_early_data_received), __FUNCTION__,
                          "defer all coalesced plaintext until the EncryptedExtensions decision");

        tls_handshake_encrypted_extensions partitioned_coalesced_ee(&partitioned_coalesced_server);
        partitioned_coalesced_ee.get_extensions().add(new tls_extension_early_data(&partitioned_coalesced_ee));
        binary_t partitioned_coalesced_ee_wire;
        ret = partitioned_coalesced_ee.write(from_server, partitioned_coalesced_ee_wire);
        _test_case.test(ret, __FUNCTION__, "resume every complete record after the partitioned EncryptedExtensions acceptance");
        if (errorcode_t::success != ret) {
            return;
        }

        char partitioned_coalesced_output[16] = {};
        size_t partitioned_first_read = 0;
        ret = partitioned_coalesced_prosumer->consume(0, 0, partitioned_coalesced_output, sizeof(partitioned_coalesced_output), &partitioned_first_read);
        _test_case.assert((errorcode_t::success == ret) || (errorcode_t::more_data == ret), __FUNCTION__, "consume the first partitioned coalesced early-data record");
        if ((errorcode_t::success != ret) && (errorcode_t::more_data != ret)) {
            return;
        }
        size_t partitioned_second_read = 0;
        ret = partitioned_coalesced_prosumer->consume(0, 0, partitioned_coalesced_output + partitioned_first_read,
                                                      sizeof(partitioned_coalesced_output) - partitioned_first_read, &partitioned_second_read);
        _test_case.assert((errorcode_t::success == ret) || (errorcode_t::more_data == ret), __FUNCTION__, "consume the second partitioned coalesced early-data record");
        const size_t partitioned_total_read = partitioned_first_read + partitioned_second_read;
        _test_case.assert(6 == partitioned_total_read, __FUNCTION__, "deliver both complete records for every stream split exactly once");
        _test_case.assert(binary_t({0x31, 0x32, 0x33, 0x41, 0x42, 0x43}) == binary_t(partitioned_coalesced_output, partitioned_coalesced_output + partitioned_total_read),
                          __FUNCTION__, "preserve coalesced plaintext ordering for every stream split");
        _test_case.assert(6 == partitioned_coalesced_state.get(session_early_data_received), __FUNCTION__,
                          "account complete coalesced records once for every stream split");

        ret = partitioned_coalesced_prosumer->produce(&partitioned_coalesced_server, from_client, third_early_record_wire.data() + third_record_prefix_size,
                                                      third_early_record_wire.size() - third_record_prefix_size);
        _test_case.test(ret, __FUNCTION__, "complete the trailing record after every coalesced stream split");
        if (errorcode_t::success != ret) {
            return;
        }
        size_t partitioned_trailing_read = 0;
        ret = partitioned_coalesced_prosumer->consume(0, 0, partitioned_coalesced_output, sizeof(partitioned_coalesced_output), &partitioned_trailing_read);
        _test_case.test(ret, __FUNCTION__, "consume the trailing record after every coalesced stream split");
        _test_case.assert(3 == partitioned_trailing_read, __FUNCTION__, "deliver the completed trailing record exactly once for every stream split");
        _test_case.assert(binary_t({0x51, 0x52, 0x53}) == binary_t(partitioned_coalesced_output, partitioned_coalesced_output + partitioned_trailing_read), __FUNCTION__,
                          "preserve trailing plaintext for every coalesced stream split");
        _test_case.assert(9 == partitioned_coalesced_state.get(session_early_data_received), __FUNCTION__,
                          "account all coalesced and trailing records exactly once for every stream split");
    }

    // Scenario: enforce pending early-data byte, record-count, and callback buffer limits
    {
        tls_session overflow_server;
        prepare_server(overflow_server, true);
        auto overflow_prosumer = overflow_server.get_secure_prosumer();
        overflow_prosumer->set_pending_early_data_buffer_limit(first_fragment_size);
        ret = overflow_prosumer->produce(&overflow_server, from_client, early_record_wire.data(), first_fragment_size);
        _test_case.test(ret, __FUNCTION__, "accept a pending ciphertext fragment exactly at the configured buffer limit");
        ret = overflow_prosumer->produce(&overflow_server, from_client, early_record_wire.data() + first_fragment_size, 1);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject cumulative pending 0-RTT ciphertext beyond the configured buffer limit");
        size_t pending_buffer_overflow_alert_count = 0;
        overflow_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
                ++pending_buffer_overflow_alert_count;
            }
        });
        _test_case.assert(1 == pending_buffer_overflow_alert_count, __FUNCTION__,
                          "raise exactly one fatal internal_error when the pending ciphertext buffer limit is exceeded");
        _test_case.assert(0 == overflow_server.get_session_status(), __FUNCTION__, "reset the handshake state after pending ciphertext buffer overflow");
        char overflow_output[8] = {};
        size_t overflow_read = 0;
        overflow_prosumer->consume(0, 0, overflow_output, sizeof(overflow_output), &overflow_read);
        _test_case.assert(0 == overflow_read, __FUNCTION__, "do not deliver data after the pending ciphertext buffer overflow");

        tls_session record_count_boundary_server;
        prepare_server(record_count_boundary_server, true);
        auto record_count_boundary_prosumer = record_count_boundary_server.get_secure_prosumer();
        record_count_boundary_prosumer->set_pending_early_data_buffer_limit(0);
        binary_t max_pending_records;
        for (size_t i = 0; i < 64; ++i) {
            max_pending_records.insert(max_pending_records.end(), early_record_wire.begin(), early_record_wire.end());
        }
        ret = record_count_boundary_prosumer->produce(&record_count_boundary_server, from_client, max_pending_records.data(), max_pending_records.size());
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow exactly 64 pending records when the byte cap is disabled");

        tls_session record_count_server;
        prepare_server(record_count_server, true);
        auto record_count_prosumer = record_count_server.get_secure_prosumer();
        record_count_prosumer->set_pending_early_data_buffer_limit(0);
        binary_t too_many_pending_records;
        for (size_t i = 0; i < 65; ++i) {
            too_many_pending_records.insert(too_many_pending_records.end(), early_record_wire.begin(), early_record_wire.end());
        }
        ret = record_count_prosumer->produce(&record_count_server, from_client, too_many_pending_records.data(), too_many_pending_records.size());
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the pending 0-RTT record-count limit independently of the byte limit");

        tls_session record_buffer_limit_server;
        prepare_server(record_buffer_limit_server, true);
        auto record_buffer_limit_prosumer = record_buffer_limit_server.get_secure_prosumer();
        record_buffer_limit_prosumer->set_pending_early_data_buffer_limit(0);
        const size_t record_buffer_limit = 64 * (5 + 0xffff);
        binary_t oversized_pending_input(record_buffer_limit + 1, 0);
        oversized_pending_input[0] = 0x17;
        oversized_pending_input[1] = 0x03;
        oversized_pending_input[2] = 0x03;
        oversized_pending_input[3] = 0xff;
        oversized_pending_input[4] = 0xff;
        ret = record_buffer_limit_prosumer->produce(&record_buffer_limit_server, from_client, oversized_pending_input.data(), oversized_pending_input.size());
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject input beyond the record-count-derived hard buffer ceiling before copying it");
        size_t record_count_overflow_alert_count = 0;
        record_count_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
                ++record_count_overflow_alert_count;
            }
        });
        _test_case.assert(1 == record_count_overflow_alert_count, __FUNCTION__, "raise exactly one fatal internal_error for pending record-count overflow");

        tls_session callback_overflow_server;
        prepare_server(callback_overflow_server, true);
        auto callback_overflow_prosumer = callback_overflow_server.get_secure_prosumer();
        callback_overflow_prosumer->set_pending_early_data_buffer_limit(1);
        bool callback_write_rejected = false;
        ret = callback_overflow_prosumer->produce(&callback_overflow_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
            callback_write_rejected = (errorcode_t::overflow == stream.write(early_record_wire.data(), early_record_wire.size()));
        });
        _test_case.assert(callback_write_rejected, __FUNCTION__, "reject callback input before it grows the pending buffer beyond its byte limit");
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the pending ciphertext bound on callback-based input");
        size_t callback_overflow_alert_count = 0;
        callback_overflow_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::internal_error == desc)) {
                ++callback_overflow_alert_count;
            }
        });
        _test_case.assert(1 == callback_overflow_alert_count, __FUNCTION__, "raise exactly one fatal internal_error for callback-based buffer overflow");

        tls_session callback_api_server;
        prepare_server(callback_api_server, true);
        auto callback_api_prosumer = callback_api_server.get_secure_prosumer();
        callback_api_prosumer->set_pending_early_data_buffer_limit(1);
        bool callback_printf_rejected = false;
        bool callback_large_printf_rejected = false;
        bool callback_insert_rejected = false;
        bool callback_fill_rejected = false;
        bool callback_resize_rejected = false;
        const std::string large_printf_output(4096, 'p');
        ret = callback_api_prosumer->produce(&callback_api_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
            callback_printf_rejected = (errorcode_t::overflow == stream.printf("%s", "formatted output"));
            callback_large_printf_rejected = (errorcode_t::overflow == stream.printf("%s", large_printf_output.c_str()));
            callback_insert_rejected = (errorcode_t::overflow == stream.insert(0, early_record_wire.data(), early_record_wire.size()));
            callback_fill_rejected = (errorcode_t::overflow == stream.fill(2, 'x'));
            stream.resize(2);
            callback_resize_rejected = (0 == stream.size());
        });
        _test_case.assert(callback_printf_rejected, __FUNCTION__, "bound printf output before formatted data grows the pending buffer");
        _test_case.assert(callback_large_printf_rejected, __FUNCTION__, "bound a large formatted output chunk without materializing it in an intermediate stream");
        _test_case.assert(callback_insert_rejected, __FUNCTION__, "bound insert output before inserted data grows the pending buffer");
        _test_case.assert(callback_fill_rejected, __FUNCTION__, "bound fill output before it grows the pending buffer");
        _test_case.assert(callback_resize_rejected, __FUNCTION__, "reject callback resize before it grows the pending buffer");
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject callback mutation APIs that exceed the pending ciphertext limit");

        tls_session callback_encoder_server;
        prepare_server(callback_encoder_server, true);
        auto callback_encoder_prosumer = callback_encoder_server.get_secure_prosumer();
        callback_encoder_prosumer->set_pending_early_data_buffer_limit(1);
        return_t callback_encoder_ret = errorcode_t::success;
        ret = callback_encoder_prosumer->produce(&callback_encoder_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
            callback_encoder_ret = base64_encode(binary_t{0x01, 0x02, 0x03}, stream);
        });
        _test_case.assert(errorcode_t::overflow == callback_encoder_ret, __FUNCTION__,
                          "reject a Base64 encoder reservation before writing through its raw output pointer");
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "propagate an over-limit Base64 reservation to pending ciphertext handling");

        tls_session callback_base16_server;
        prepare_server(callback_base16_server, true);
        auto callback_base16_prosumer = callback_base16_server.get_secure_prosumer();
        callback_base16_prosumer->set_pending_early_data_buffer_limit(1);
        return_t callback_base16_ret = errorcode_t::success;
        ret = callback_base16_prosumer->produce(&callback_base16_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
            callback_base16_ret = base16_encode(binary_t{0x01, 0x02, 0x03}, stream);
        });
        _test_case.assert(errorcode_t::overflow == callback_base16_ret, __FUNCTION__,
                          "reject a Base16 encoder reservation before writing through its raw output pointer");
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "propagate an over-limit Base16 reservation to pending ciphertext handling");

        tls_session callback_integer_server;
        prepare_server(callback_integer_server, true);
        auto callback_integer_prosumer = callback_integer_server.get_secure_prosumer();
        callback_integer_prosumer->set_pending_early_data_buffer_limit(1);
        ret = callback_integer_prosumer->produce(&callback_integer_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void { stream << 123456; });
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "bound integral stream insertion through the formatted output hook");

        tls_session callback_assignment_server;
        prepare_server(callback_assignment_server, true);
        auto callback_assignment_prosumer = callback_assignment_server.get_secure_prosumer();
        callback_assignment_prosumer->set_pending_early_data_buffer_limit(1);
        ret = callback_assignment_prosumer->produce(&callback_assignment_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
            basic_stream oversized;
            oversized.write("oversized", 9);
            stream = oversized;
        });
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "bound callback stream copy assignment before replacing the pending buffer");

        tls_session callback_move_assignment_server;
        prepare_server(callback_move_assignment_server, true);
        auto callback_move_assignment_prosumer = callback_move_assignment_server.get_secure_prosumer();
        callback_move_assignment_prosumer->set_pending_early_data_buffer_limit(1);
        ret = callback_move_assignment_prosumer->produce(&callback_move_assignment_server, from_client, [&](basic_stream& stream, sockaddr_storage_t&) -> void {
            basic_stream oversized;
            oversized.write("oversized", 9);
            stream = std::move(oversized);
        });
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "bound callback stream move assignment before replacing the pending buffer");
    }

    // Scenario: defer rejected in-flight early data until EncryptedExtensions and discard it without delivery
    {
        tls_session rejected_server;
        prepare_server(rejected_server, false);
        // PSK rejection may select one_rtt during ClientHello processing, but
        // in-flight early data must remain pending until EncryptedExtensions.
        rejected_server.get_tls_protection().set_flow(tls_flow_t::one_rtt);
        auto rejected_prosumer = rejected_server.get_secure_prosumer();
        ret = rejected_prosumer->produce(&rejected_server, from_client, early_record_wire.data(), early_record_wire.size());
        _test_case.test(ret, __FUNCTION__, "buffer in-flight early data after PSK rejection has selected one_rtt but before EncryptedExtensions");
        if (errorcode_t::success != ret) {
            return;
        }
        char rejected_output[8] = {};
        size_t rejected_read = 0;
        rejected_prosumer->consume(0, 0, rejected_output, sizeof(rejected_output), &rejected_read);
        _test_case.assert(0 == rejected_read, __FUNCTION__, "do not deliver data before a rejection decision");

        tls_handshake_encrypted_extensions rejected_ee(&rejected_server);
        binary_t rejected_ee_wire;
        ret = rejected_ee.write(from_server, rejected_ee_wire);
        _test_case.test(ret, __FUNCTION__, "omit early_data and discard the buffered rejected ciphertext under handshake keys");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(0 == rejected_server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), __FUNCTION__,
                          "retain rejection state when EncryptedExtensions omits early_data");
        _test_case.assert(tls_flow_t::one_rtt == rejected_server.get_tls_protection().get_flow(), __FUNCTION__,
                          "retain handshake-key flow while resuming rejected records");
        _test_case.assert(early_record_wire.size() - 5 == rejected_server.get_session_info(from_server).get_keyvalue().get(session_early_data_discarded), __FUNCTION__,
                          "discard the buffered ciphertext within the configured skip bound");
        size_t rejected_after_ee = 0;
        ret = rejected_prosumer->consume(0, 0, rejected_output, sizeof(rejected_output), &rejected_after_ee);
        _test_case.assert(0 == rejected_after_ee, __FUNCTION__, "never deliver rejected early-data plaintext");

        // A record may be split across the EncryptedExtensions decision. Keep its
        // prefix buffered, then finish it after rejection so the completed record
        // still follows the rejected-0-RTT trial-decryption path.
        tls_session rejected_split_server;
        prepare_server(rejected_split_server, false);
        rejected_split_server.get_tls_protection().set_flow(tls_flow_t::one_rtt);
        auto rejected_split_prosumer = rejected_split_server.get_secure_prosumer();
        ret = rejected_split_prosumer->produce(&rejected_split_server, from_client, early_record_wire.data(), first_fragment_size);
        _test_case.test(ret, __FUNCTION__, "buffer a partial rejected early-data record before EncryptedExtensions");
        if (errorcode_t::success != ret) {
            return;
        }
        tls_handshake_encrypted_extensions rejected_split_ee(&rejected_split_server);
        binary_t rejected_split_ee_wire;
        ret = rejected_split_ee.write(from_server, rejected_split_ee_wire);
        _test_case.test(ret, __FUNCTION__, "commit early-data rejection while retaining the incomplete record");
        if (errorcode_t::success != ret) {
            return;
        }
        ret = rejected_split_prosumer->produce(&rejected_split_server, from_client, early_record_wire.data() + first_fragment_size,
                                               early_record_wire.size() - first_fragment_size);
        _test_case.test(ret, __FUNCTION__, "trial-decrypt and discard the record completed after EncryptedExtensions rejection");
        if (errorcode_t::success != ret) {
            return;
        }
        const auto& rejected_split_state = rejected_split_server.get_session_info(from_server).get_keyvalue();
        _test_case.assert(early_record_wire.size() - 5 == rejected_split_state.get(session_early_data_discarded), __FUNCTION__,
                          "account the rejected ciphertext completed after EncryptedExtensions exactly once");
        _test_case.assert(1 == rejected_split_state.get(session_early_data_discarded_records), __FUNCTION__, "count the post-decision rejected record exactly once");
        size_t rejected_split_read = 0;
        rejected_split_prosumer->consume(0, 0, rejected_output, sizeof(rejected_output), &rejected_split_read);
        _test_case.assert(0 == rejected_split_read, __FUNCTION__, "never deliver a record completed after early-data rejection");

        for (size_t i = 0; i < RTL_NUMBER_OF(early_record_split_sizes); ++i) {
            const size_t split_size = early_record_split_sizes[i];
            tls_session partitioned_rejected_server;
            prepare_server(partitioned_rejected_server, false);
            partitioned_rejected_server.get_tls_protection().set_flow(tls_flow_t::one_rtt);
            auto partitioned_rejected_prosumer = partitioned_rejected_server.get_secure_prosumer();
            ret = partitioned_rejected_prosumer->produce(&partitioned_rejected_server, from_client, early_record_wire.data(), split_size);
            _test_case.test(ret, __FUNCTION__, "buffer the first fragment of rejected in-flight early data");
            if (errorcode_t::success != ret) {
                return;
            }
            ret = partitioned_rejected_prosumer->produce(&partitioned_rejected_server, from_client, early_record_wire.data() + split_size,
                                                         early_record_wire.size() - split_size);
            _test_case.test(ret, __FUNCTION__, "retain the complete rejected early-data record before EncryptedExtensions");
            if (errorcode_t::success != ret) {
                return;
            }

            tls_handshake_encrypted_extensions partitioned_rejected_ee(&partitioned_rejected_server);
            binary_t partitioned_rejected_ee_wire;
            ret = partitioned_rejected_ee.write(from_server, partitioned_rejected_ee_wire);
            _test_case.test(ret, __FUNCTION__, "resume and discard fragmented early data after EncryptedExtensions rejection");
            if (errorcode_t::success != ret) {
                return;
            }
            const auto& partitioned_rejected_state = partitioned_rejected_server.get_session_info(from_server).get_keyvalue();
            _test_case.assert(early_record_wire.size() - 5 == partitioned_rejected_state.get(session_early_data_discarded), __FUNCTION__,
                              "account the fragmented rejected ciphertext exactly once");
            _test_case.assert(1 == partitioned_rejected_state.get(session_early_data_discarded_records), __FUNCTION__, "count one fragmented rejected early-data record");
            size_t partitioned_rejected_read = 0;
            partitioned_rejected_prosumer->consume(0, 0, rejected_output, sizeof(rejected_output), &partitioned_rejected_read);
            _test_case.assert(0 == partitioned_rejected_read, __FUNCTION__, "never deliver fragmented rejected early-data plaintext");
        }
    }
}

class test_tls13_client_hello_preprocess_probe : public tls_handshake_client_hello {
   public:
    using tls_handshake_client_hello::tls_handshake_client_hello;
    return_t preprocess(tls_direction_t dir) { return do_preprocess(dir); }
};

static void test_tls13_client_hello_resets_rejected_early_data_counters() {
    // Scenario under test: TLS 1.3 fresh ClientHello resets rejected early-data counters but ClientHello2 preserves them.
    // Action: start a fresh ClientHello processing epoch.
    // Expected: clear the prior rejected-ciphertext byte limit.
    _test_case.begin("TLS 1.3 fresh ClientHello resets rejected early-data counters but ClientHello2 preserves them");

    tls_session fresh_session;
    fresh_session.set_type(session_type_t::tls);
    fresh_session.get_tls_protection().set_tls_version(tls_13);
    fresh_session.get_tls_protection().set_flow(tls_flow_t::one_rtt);
    auto& fresh_state = fresh_session.get_session_info(from_server).get_keyvalue();
    fresh_state.set(session_early_data_discard_limit, 4096);
    fresh_state.set(session_early_data_discarded, 1024);
    fresh_state.set(session_early_data_discarded_records, 7);

    test_tls13_client_hello_preprocess_probe fresh_client_hello(&fresh_session);
    return_t ret = fresh_client_hello.preprocess(from_client);
    _test_case.test(ret, __FUNCTION__, "start a fresh ClientHello processing epoch");
    _test_case.assert(0 == fresh_state.get(session_early_data_discard_limit), __FUNCTION__, "clear the prior rejected-ciphertext byte limit");
    _test_case.assert(0 == fresh_state.get(session_early_data_discarded), __FUNCTION__, "clear the prior rejected-ciphertext byte count");
    _test_case.assert(0 == fresh_state.get(session_early_data_discarded_records), __FUNCTION__, "clear the prior rejected-record count together with its byte count");

    tls_session hrr_session;
    hrr_session.set_type(session_type_t::tls);
    hrr_session.get_tls_protection().set_tls_version(tls_13);
    hrr_session.get_tls_protection().set_flow(tls_flow_t::hello_retry_request);
    auto& hrr_state = hrr_session.get_session_info(from_server).get_keyvalue();
    hrr_state.set(session_early_data_discard_limit, 4096);
    hrr_state.set(session_early_data_discarded, 1024);
    hrr_state.set(session_early_data_discarded_records, 7);

    test_tls13_client_hello_preprocess_probe client_hello2(&hrr_session);
    ret = client_hello2.preprocess(from_client);
    _test_case.test(ret, __FUNCTION__, "process ClientHello2 after HelloRetryRequest");
    _test_case.assert(4096 == hrr_state.get(session_early_data_discard_limit), __FUNCTION__, "preserve the original HRR discard byte limit");
    _test_case.assert(1024 == hrr_state.get(session_early_data_discarded), __FUNCTION__, "preserve ciphertext already discarded after HRR");
    _test_case.assert(7 == hrr_state.get(session_early_data_discarded_records), __FUNCTION__, "preserve the cumulative HRR record count");
}

static void test_tls13_hrr_drains_buffered_early_data() {
    // Scenario under test: TLS 1.3 HelloRetryRequest drains already-buffered rejected early data.
    // Action: buffer in-flight 0-RTT while the early-data decision is pending.
    // Expected: do not discard the record before the server chooses its HRR response.
    _test_case.begin("TLS 1.3 HelloRetryRequest drains already-buffered rejected early data");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::zero_rtt);
    // The probe bypasses ServerHello serialization; provide the RFC-defined
    // HRR random so postprocess recognizes HRR before key-schedule processing.
    const binary_t hrr_random{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                              0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    protection.get_secrets().assign(tls_secret_t::server_hello_random, hrr_random);
    protection.get_protection_context().add_supported_version(tls_13);
    session.update_session_status(session_status_client_hello);
    // HRR does not select a PSK identity. Keep the synthetic ServerHello
    // state explicit so calc() derives the zero-PSK early secret.
    session.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
    auto& early_state = session.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_offered_initial, 1);
    early_state.set(session_early_data_discard_limit, 4096);

    // Simulate a complete 0-RTT record coalesced after ClientHello1 while the
    // server has not yet committed its response.
    binary_t in_flight_record{0x17, 0x03, 0x03, 0x00, 0x10};
    in_flight_record.insert(in_flight_record.end(), 16, 0xaa);
    auto prosumer = session.get_secure_prosumer();
    return_t ret = prosumer->produce(&session, from_client, in_flight_record.data(), in_flight_record.size());
    _test_case.test(ret, __FUNCTION__, "buffer in-flight 0-RTT while the early-data decision is pending");
    _test_case.assert(0 == early_state.get(session_early_data_discarded), __FUNCTION__, "do not discard the record before the server chooses its HRR response");

    test_tls13_server_hello_postprocess_probe hrr(&session);
    hrr.set_version(tls_13);
    ret = hrr.postprocess_write();
    _test_case.test(ret, __FUNCTION__, "commit HelloRetryRequest and drain pending first-flight records");
    _test_case.assert(tls_flow_t::hello_retry_request == protection.get_flow(), __FUNCTION__, "enter HRR flow before processing buffered records");
    _test_case.assert(16 == early_state.get(session_early_data_discarded), __FUNCTION__,
                      "account for the buffered ciphertext as rejected early data immediately after HRR");
    _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__,
                      "count the drained HRR early-data record against the independent record ceiling");

    // ClientHello2 still carries pre_shared_key, but it must not reset the
    // rejected-record ceiling accumulated for ClientHello1's 0-RTT flight.
    tls_handshake_client_hello client_hello2(&session);
    tls_extension_client_psk client_hello2_psk(&client_hello2);
    binary_t client_hello2_psk_wire{0x00, 0x29, 0x00, 0x2c, 0x00, 0x07, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x20};
    client_hello2_psk_wire.insert(client_hello2_psk_wire.end(), 32, 0x00);
    size_t client_hello2_psk_pos = 0;
    ret = client_hello2_psk.read(from_client, client_hello2_psk_wire.data(), client_hello2_psk_wire.size(), client_hello2_psk_pos);
    _test_case.test(ret, __FUNCTION__, "parse ClientHello2 pre_shared_key without resetting the HRR discard counter");
    _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__, "preserve the rejected-record count across ClientHello2 PSK parsing");
    _test_case.assert(16 == early_state.get(session_early_data_discarded), __FUNCTION__, "preserve the rejected-ciphertext byte count across ClientHello2 PSK parsing");

    binary_t remaining_hrr_records;
    for (size_t i = 0; i < 63; ++i) {
        remaining_hrr_records.insert(remaining_hrr_records.end(), in_flight_record.begin(), in_flight_record.end());
    }
    ret = prosumer->produce(&session, from_client, remaining_hrr_records.data(), remaining_hrr_records.size());
    _test_case.test(ret, __FUNCTION__, "accept the remaining rejected records up to the connection-wide 64-record ceiling");
    _test_case.assert(64 == early_state.get(session_early_data_discarded_records), __FUNCTION__, "retain one cumulative 64-record ceiling across HRR and ClientHello2");

    ret = prosumer->produce(&session, from_client, in_flight_record.data(), in_flight_record.size());
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject the 65th rejected early-data record after ClientHello2");
    _test_case.assert(0 == session.get_session_status(), __FUNCTION__, "abort after the cumulative rejected-record ceiling is exceeded");
    size_t hrr_overflow_alert_count = 0;
    session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
            ++hrr_overflow_alert_count;
        }
    });
    _test_case.assert(1 == hrr_overflow_alert_count, __FUNCTION__, "queue one fatal alert when the post-ClientHello2 record ceiling is exceeded");

    char output[32] = {};
    size_t consumed = 0;
    ret = prosumer->consume(0, 0, output, sizeof(output), &consumed);
    _test_case.assert(0 == consumed, __FUNCTION__, "never deliver HRR-rejected early-data plaintext to the application");

    const size_t hrr_record_split_sizes[] = {1, 4, 5, 6, in_flight_record.size() / 2};
    for (size_t i = 0; i < RTL_NUMBER_OF(hrr_record_split_sizes); ++i) {
        const size_t split_size = hrr_record_split_sizes[i];
        tls_session partitioned_hrr_session;
        partitioned_hrr_session.set_type(session_type_t::tls);
        auto& partitioned_protection = partitioned_hrr_session.get_tls_protection();
        partitioned_protection.set_tls_version(tls_13);
        partitioned_protection.set_cipher_suite(0x1301);
        partitioned_protection.set_flow(tls_flow_t::zero_rtt);
        partitioned_protection.get_secrets().assign(tls_secret_t::server_hello_random, hrr_random);
        partitioned_protection.get_protection_context().add_supported_version(tls_13);
        partitioned_hrr_session.update_session_status(session_status_client_hello);
        partitioned_hrr_session.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
        auto& partitioned_early_state = partitioned_hrr_session.get_session_info(from_server).get_keyvalue();
        partitioned_early_state.set(session_early_data_offered, 1);
        partitioned_early_state.set(session_early_data_offered_initial, 1);
        partitioned_early_state.set(session_early_data_discard_limit, 4096);
        auto partitioned_prosumer = partitioned_hrr_session.get_secure_prosumer();

        ret = partitioned_prosumer->produce(&partitioned_hrr_session, from_client, in_flight_record.data(), split_size);
        _test_case.test(ret, __FUNCTION__, "buffer the first fragment of an in-flight record before HRR");
        if (errorcode_t::success != ret) {
            return;
        }
        ret = partitioned_prosumer->produce(&partitioned_hrr_session, from_client, in_flight_record.data() + split_size, in_flight_record.size() - split_size);
        _test_case.test(ret, __FUNCTION__, "retain the complete fragmented 0-RTT record until HRR");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(0 == partitioned_early_state.get(session_early_data_discarded), __FUNCTION__, "do not account fragmented early data before the HRR decision");

        test_tls13_server_hello_postprocess_probe partitioned_hrr(&partitioned_hrr_session);
        partitioned_hrr.set_version(tls_13);
        ret = partitioned_hrr.postprocess_write();
        _test_case.test(ret, __FUNCTION__, "drain fragmented in-flight 0-RTT after committing HRR");
        _test_case.assert(16 == partitioned_early_state.get(session_early_data_discarded), __FUNCTION__, "account fragmented HRR-rejected ciphertext exactly once");
        _test_case.assert(1 == partitioned_early_state.get(session_early_data_discarded_records), __FUNCTION__,
                          "count one fragmented record against the HRR discard ceiling");
    }

    tls_session over_limit_session;
    over_limit_session.set_type(session_type_t::tls);
    auto& over_limit_protection = over_limit_session.get_tls_protection();
    over_limit_protection.set_tls_version(tls_13);
    over_limit_protection.set_cipher_suite(0x1301);
    over_limit_protection.set_flow(tls_flow_t::zero_rtt);
    over_limit_protection.get_secrets().assign(tls_secret_t::server_hello_random, hrr_random);
    over_limit_protection.get_protection_context().add_supported_version(tls_13);
    over_limit_session.update_session_status(session_status_client_hello);
    over_limit_session.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);
    auto& over_limit_state = over_limit_session.get_session_info(from_server).get_keyvalue();
    over_limit_state.set(session_early_data_offered, 1);
    over_limit_state.set(session_early_data_offered_initial, 1);
    over_limit_state.set(session_early_data_discard_limit, 8);
    auto over_limit_prosumer = over_limit_session.get_secure_prosumer();
    ret = over_limit_prosumer->produce(&over_limit_session, from_client, in_flight_record.data(), in_flight_record.size());
    _test_case.test(ret, __FUNCTION__, "buffer the over-budget record before the HRR decision");

    test_tls13_server_hello_postprocess_probe over_limit_hrr(&over_limit_session);
    over_limit_hrr.set_version(tls_13);
    ret = over_limit_hrr.postprocess_write();
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "enforce the rejected-ciphertext budget while committing HRR");
    _test_case.assert(0 == over_limit_session.get_session_status(), __FUNCTION__, "abort the handshake when buffered HRR data exceeds the discard budget");
    size_t fatal_unexpected_message_count = 0;
    over_limit_session.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
            ++fatal_unexpected_message_count;
        }
    });
    _test_case.assert(1 == fatal_unexpected_message_count, __FUNCTION__, "queue one fatal unexpected_message for over-budget HRR data");
}

static void test_tls13_server_discards_rejected_early_data_records() {
    // Scenario under test: TLS 1.3 server discards rejected early-data records before Server Finished.
    // Action: trial-decrypt rejected 0-RTT with handshake keys and discard failed records.
    // Expected: consume the rejected early-data record.
    _test_case.begin("TLS 1.3 server discards rejected early-data records before Server Finished");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::one_rtt);
    session.update_session_status(session_status_client_hello);
    session.update_session_status(session_status_server_hello);
    session.get_session_info(from_client).begin_protection();
    auto& early_state = session.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_accepted, 0);
    early_state.set(session_early_data_discard_limit, 4096);
    early_state.set(session_early_data_discarded, 0);
    session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);

    binary_t rejected_record{0x17, 0x03, 0x03, 0x00, 0x10};
    rejected_record.insert(rejected_record.end(), 16, 0xaa);
    tls_records records;
    return_t ret = records.read(&session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "trial-decrypt rejected 0-RTT with handshake keys and discard failed records");
    _test_case.assert(1 == records.size(), __FUNCTION__, "consume the rejected early-data record");
    if (records.size()) {
        auto decoded = static_cast<tls_record_application_data*>(records.getat(0));
        _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "do not deliver rejected early-data plaintext");
    }
    _test_case.assert(false == session.has_alert(from_client, tls_alertlevel_t::fatal), __FUNCTION__,
                      "do not raise bad_record_mac for intentionally rejected 0-RTT data");
    _test_case.assert(16 == early_state.get(session_early_data_discarded), __FUNCTION__, "count discarded ciphertext against the configured early-data skip bound");
    _test_case.assert(0 == session.get_session_info(from_client).get_recordno(false), __FUNCTION__,
                      "restore the handshake record sequence after failed trial decryption");

    // A rejected 0-RTT record may be followed immediately by the
    // client's first handshake-key-protected record. Exercise both records
    // through the real writer/reader so a failed trial decrypt must restore
    // the sequence number before Client Finished is authenticated.
    {
        auto configure_handshake = [](tls_session& endpoint) -> void {
            endpoint.set_type(session_type_t::tls);
            auto& endpoint_protection = endpoint.get_tls_protection();
            endpoint_protection.set_tls_version(tls_13);
            endpoint_protection.set_cipher_suite(0x1301);
            endpoint_protection.set_flow(tls_flow_t::one_rtt);
            endpoint_protection.use_pre_master_secret(true);
            auto& secrets = endpoint_protection.get_secrets();
            secrets.assign(tls_secret_t::s_hs_traffic, binary_t(32, 0x11));
            secrets.assign(tls_secret_t::c_hs_traffic, binary_t(32, 0x22));
            secrets.assign(tls_secret_t::s_ap_traffic, binary_t(32, 0x33));
            secrets.assign(tls_secret_t::c_ap_traffic, binary_t(32, 0x44));
            secrets.assign(tls_secret_t::application, binary_t(32, 0x99));
            secrets.assign(tls_secret_t::handshake_server_key, binary_t(16, 0x55));
            secrets.assign(tls_secret_t::handshake_server_iv, binary_t(12, 0x66));
            secrets.assign(tls_secret_t::handshake_client_key, binary_t(16, 0x77));
            secrets.assign(tls_secret_t::handshake_client_iv, binary_t(12, 0x88));
            endpoint.update_session_status(session_status_server_hello);
            endpoint.update_session_status(session_status_encrypted_extensions);
            endpoint.update_session_status(session_status_server_cert_verified);
            endpoint.get_session_info(from_server).set_status(tls_handshake_type_t::certificate_verify);
            endpoint.get_session_info(from_server).begin_protection();
            endpoint.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
            endpoint.get_session_info(from_client).begin_protection();
            endpoint.update_session_status(session_status_server_finished);
        };

        tls_session writer;
        tls_session reader;
        configure_handshake(writer);
        configure_handshake(reader);

        auto& reader_early_state = reader.get_session_info(from_server).get_keyvalue();
        reader_early_state.set(session_early_data_offered, 1);
        reader_early_state.set(session_early_data_offered_initial, 1);
        reader_early_state.set(session_early_data_accepted, 0);
        reader_early_state.set(session_early_data_discard_limit, 4096);
        reader_early_state.set(session_early_data_discarded, 0);
        reader_early_state.set(session_early_data_discarded_records, 0);

        tls_record_application_data outgoing_finished(&writer);
        outgoing_finished << new tls_handshake_finished(&writer);
        binary_t finished_wire;
        ret = outgoing_finished.write(from_client, finished_wire);
        _test_case.test(ret, __FUNCTION__, "write a valid Client Finished with the handshake traffic key");
        if (errorcode_t::success == ret) {
            binary_t coalesced_wire{0x17, 0x03, 0x03, 0x00, 0x10};
            coalesced_wire.insert(coalesced_wire.end(), 16, 0xaa);
            coalesced_wire.insert(coalesced_wire.end(), finished_wire.begin(), finished_wire.end());

            tls_records coalesced_records;
            ret = coalesced_records.read(&reader, from_client, coalesced_wire);
            _test_case.test(ret, __FUNCTION__, "discard rejected 0-RTT then authenticate the following Client Finished");
            _test_case.assert(2 == coalesced_records.size(), __FUNCTION__, "consume both the rejected record and the valid handshake record");
            if (2 == coalesced_records.size()) {
                auto rejected = static_cast<tls_record_application_data*>(coalesced_records.getat(0));
                _test_case.assert(rejected->get_binary().empty(), __FUNCTION__, "do not deliver rejected early-data plaintext");
                auto accepted = static_cast<tls_record_application_data*>(coalesced_records.getat(1));
                _test_case.assert(1 == accepted->get_handshakes().size(), __FUNCTION__, "parse Client Finished from the following record");
            }
            _test_case.assert(16 == reader_early_state.get(session_early_data_discarded), __FUNCTION__, "account for only the rejected ciphertext");
            _test_case.assert(1 == reader_early_state.get(session_early_data_discarded_records), __FUNCTION__, "count exactly one rejected record");
            _test_case.assert(0 != (reader.get_session_status() & session_status_client_finished), __FUNCTION__,
                              "advance the handshake after authenticating Client Finished");
            _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "apply the Client Finished traffic-key transition after the successful trial decrypt");
            _test_case.assert(false == reader.has_alert(from_client, tls_alertlevel_t::fatal), __FUNCTION__,
                              "do not raise a fatal alert for the rejected record preceding valid Client Finished");
        }
    }

    tls_session pre_server_hello_session;
    pre_server_hello_session.set_type(session_type_t::tls);
    auto& pre_server_hello_protection = pre_server_hello_session.get_tls_protection();
    pre_server_hello_protection.set_tls_version(tls_13);
    pre_server_hello_protection.set_cipher_suite(0x1301);
    pre_server_hello_protection.set_flow(tls_flow_t::one_rtt);
    pre_server_hello_session.update_session_status(session_status_client_hello);
    pre_server_hello_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    pre_server_hello_session.get_session_info(from_client).begin_protection();
    auto& pre_server_hello_state = pre_server_hello_session.get_session_info(from_server).get_keyvalue();
    pre_server_hello_state.set(session_early_data_offered, 1);
    pre_server_hello_state.set(session_early_data_accepted, 0);
    pre_server_hello_state.set(session_early_data_discard_limit, 4096);
    tls_records pre_server_hello_records;
    ret = pre_server_hello_records.read(&pre_server_hello_session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "discard rejected 0-RTT records that arrive before ServerHello");
    _test_case.assert(16 == pre_server_hello_state.get(session_early_data_discarded), __FUNCTION__,
                      "account for rejected data received before handshake traffic keys exist");

    tls_session hrr_session;
    hrr_session.set_type(session_type_t::tls);
    auto& hrr_protection = hrr_session.get_tls_protection();
    hrr_protection.set_tls_version(tls_13);
    hrr_protection.set_cipher_suite(0x1301);
    hrr_protection.set_flow(tls_flow_t::hello_retry_request);
    hrr_session.update_session_status(session_status_client_hello);
    hrr_session.update_session_status(session_status_hello_retry_request);
    hrr_session.get_session_info(from_client).begin_protection();
    auto& hrr_early_state = hrr_session.get_session_info(from_server).get_keyvalue();
    hrr_early_state.set(session_early_data_offered, 1);
    hrr_early_state.set(session_early_data_accepted, 0);
    hrr_early_state.set(session_early_data_discard_limit, 4096);
    tls_records hrr_records;
    ret = hrr_records.read(&hrr_session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "skip already-in-flight 0-RTT records after HelloRetryRequest");
    _test_case.assert(16 == hrr_early_state.get(session_early_data_discarded), __FUNCTION__, "bound HRR early-data skipping by the configured ciphertext discard limit");

    tls_session over_limit_session;
    over_limit_session.set_type(session_type_t::tls);
    auto& over_limit_protection = over_limit_session.get_tls_protection();
    over_limit_protection.set_tls_version(tls_13);
    over_limit_protection.set_cipher_suite(0x1301);
    over_limit_protection.set_flow(tls_flow_t::one_rtt);
    over_limit_session.update_session_status(session_status_client_hello);
    over_limit_session.update_session_status(session_status_server_hello);
    over_limit_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    over_limit_session.get_session_info(from_client).begin_protection();
    auto& over_limit_state = over_limit_session.get_session_info(from_server).get_keyvalue();
    over_limit_state.set(session_early_data_offered, 1);
    over_limit_state.set(session_early_data_accepted, 0);
    over_limit_state.set(session_early_data_discard_limit, 8);
    tls_records over_limit_records;
    ret = over_limit_records.read(&over_limit_session, from_client, rejected_record);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "abort when rejected early-data ciphertext exceeds the configured skip limit");
    _test_case.assert(over_limit_session.has_alert(from_client, tls_alertlevel_t::fatal), __FUNCTION__, "raise a fatal alert when the rejection skip bound is exceeded");

    tls_session default_limit_session;
    _test_case.assert(1024 * 1024 == default_limit_session.get_early_data_discard_limit(), __FUNCTION__,
                      "use an independent bounded ciphertext discard budget by default");

    default_limit_session.set_type(session_type_t::tls);
    auto& default_protection = default_limit_session.get_tls_protection();
    default_protection.set_tls_version(tls_13);
    default_protection.set_cipher_suite(0x1301);
    default_protection.set_flow(tls_flow_t::one_rtt);
    default_limit_session.update_session_status(session_status_client_hello);
    default_limit_session.update_session_status(session_status_server_hello);
    default_limit_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    default_limit_session.get_session_info(from_client).begin_protection();
    auto& default_state = default_limit_session.get_session_info(from_server).get_keyvalue();
    default_state.set(session_early_data_offered, 1);
    default_state.set(session_early_data_accepted, 0);
    default_state.set(session_early_data_discard_limit, default_limit_session.get_early_data_discard_limit());
    tls_records default_records;
    ret = default_records.read(&default_limit_session, from_client, rejected_record);
    _test_case.test(ret, __FUNCTION__, "discard rejected ciphertext using the independent default budget without a per-session override");
    _test_case.assert(16 == default_state.get(session_early_data_discarded), __FUNCTION__, "count the encrypted record body rather than the ticket plaintext allowance");
    _test_case.assert(1 == default_state.get(session_early_data_discarded_records), __FUNCTION__, "count rejected records independently from ciphertext bytes");

    tls_session record_count_session;
    record_count_session.set_type(session_type_t::tls);
    auto& count_protection = record_count_session.get_tls_protection();
    count_protection.set_tls_version(tls_13);
    count_protection.set_cipher_suite(0x1301);
    count_protection.set_flow(tls_flow_t::one_rtt);
    record_count_session.update_session_status(session_status_client_hello);
    record_count_session.update_session_status(session_status_server_hello);
    record_count_session.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    record_count_session.get_session_info(from_client).begin_protection();
    auto& count_state = record_count_session.get_session_info(from_server).get_keyvalue();
    count_state.set(session_early_data_offered, 1);
    count_state.set(session_early_data_accepted, 0);
    count_state.set(session_early_data_discard_limit, record_count_session.get_early_data_discard_limit());
    bool discarded_64_records = true;
    for (size_t i = 0; i < 64; ++i) {
        tls_records one_record;
        ret = one_record.read(&record_count_session, from_client, rejected_record);
        if (errorcode_t::success != ret) {
            discarded_64_records = false;
            break;
        }
    }
    _test_case.assert(discarded_64_records, __FUNCTION__, "allow at most 64 rejected TLS records within the discard budget");
    _test_case.assert(64 == count_state.get(session_early_data_discarded_records), __FUNCTION__, "account for all discarded records");
    tls_records sixty_fifth_record;
    ret = sixty_fifth_record.read(&record_count_session, from_client, rejected_record);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject the 65th discarded early-data record");

    tls_session empty_record_session;
    empty_record_session.set_type(session_type_t::tls);
    auto& empty_protection = empty_record_session.get_tls_protection();
    empty_protection.set_tls_version(tls_13);
    empty_protection.set_cipher_suite(0x1301);
    empty_protection.set_flow(tls_flow_t::zero_rtt);
    empty_record_session.update_session_status(session_status_client_hello);
    auto& empty_state = empty_record_session.get_session_info(from_server).get_keyvalue();
    empty_state.set(session_early_data_offered, 1);
    empty_state.set(session_early_data_accepted, 0);
    empty_state.set(session_early_data_discard_limit, empty_record_session.get_early_data_discard_limit());
    const binary_t empty_record_wire{0x17, 0x03, 0x03, 0x00, 0x00};
    tls_records empty_record;
    ret = empty_record.read(&empty_record_session, from_client, empty_record_wire);
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject an empty ciphertext fragment instead of counting it as discarded early data");
}

static void test_tls13_rejected_early_data_trial_decrypt_success() {
    // Scenario under test: TLS 1.3 rejected early-data trial decryption accepts the first handshake-key record.
    // Action: write Server Finished under server handshake traffic keys.
    // Expected: successfully decoded Client Finished after rejecting 0-RTT.
    _test_case.begin("TLS 1.3 rejected early-data trial decryption accepts the first handshake-key record");

    auto configure = [](tls_session& session) -> void {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);  // TLS_AES_128_GCM_SHA256
        protection.use_pre_master_secret(true);

        auto& secrets = protection.get_secrets();
        secrets.assign(tls_secret_t::s_hs_traffic, binary_t(32, 0x11));
        secrets.assign(tls_secret_t::c_hs_traffic, binary_t(32, 0x22));
        secrets.assign(tls_secret_t::s_ap_traffic, binary_t(32, 0x33));
        secrets.assign(tls_secret_t::c_ap_traffic, binary_t(32, 0x44));
        secrets.assign(tls_secret_t::application, binary_t(32, 0x99));
        secrets.assign(tls_secret_t::handshake_server_key, binary_t(16, 0x55));
        secrets.assign(tls_secret_t::handshake_server_iv, binary_t(12, 0x66));
        secrets.assign(tls_secret_t::handshake_client_key, binary_t(16, 0x77));
        secrets.assign(tls_secret_t::handshake_client_iv, binary_t(12, 0x88));

        session.update_session_status(session_status_server_hello);
        session.update_session_status(session_status_encrypted_extensions);
        session.update_session_status(session_status_server_cert_verified);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::certificate_verify);
        session.get_session_info(from_server).begin_protection();
        session.get_session_info(from_client).set_status(tls_handshake_type_t::server_hello);
        session.get_session_info(from_client).begin_protection();
        session.set_recordno(from_server, 7);
        session.set_recordno(from_client, 9);
    };

    tls_session writer;
    tls_session reader;
    configure(writer);
    configure(reader);

    // Follow the TLS 1.3 handshake order: the client sends Finished only after
    // it has received and verified the server's Finished.
    tls_record_application_data outgoing_server_finished(&writer);
    outgoing_server_finished << new tls_handshake_finished(&writer);
    binary_t server_finished_wire;
    return_t ret = outgoing_server_finished.write(from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "write Server Finished under server handshake traffic keys");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records decoded_server_finished;
    ret = decoded_server_finished.read(&reader, from_server, server_finished_wire);
    _test_case.test(ret, __FUNCTION__, "read Server Finished before client handshake completion");
    if (errorcode_t::success != ret) {
        return;
    }

    // The server has rejected the early-data offer and has not yet received
    // Client Finished. The next client record must therefore be trial-decrypted
    // with handshake traffic keys, not treated as a rejected 0-RTT fragment.
    auto& early_state = reader.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_accepted, 0);
    early_state.set(session_early_data_discard_limit, 4096);

    tls_record_application_data outgoing_finished(&writer);
    outgoing_finished << new tls_handshake_finished(&writer);
    binary_t finished_wire;
    ret = outgoing_finished.write(from_client, finished_wire);
    _test_case.test(ret, __FUNCTION__, "write Client Finished under client handshake traffic keys");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records decoded_finished;
    ret = decoded_finished.read(&reader, from_client, finished_wire);
    _test_case.test(ret, __FUNCTION__, "trial-decrypt and process the first valid post-rejection handshake record");
    if (errorcode_t::success != ret || 1 != decoded_finished.size()) {
        _test_case.assert(false, __FUNCTION__, "successfully decoded Client Finished after rejecting 0-RTT");
        return;
    }

    _test_case.assert(0 != (reader.get_session_status() & session_status_client_finished), __FUNCTION__, "record Client Finished after successful trial decryption");
    _test_case.assert(0 == early_state.get(session_early_data_discarded), __FUNCTION__,
                      "do not charge a successfully authenticated handshake record to the rejected-early-data discard budget");
    _test_case.assert(0 == early_state.get(session_early_data_discarded_records), __FUNCTION__,
                      "do not count a successfully authenticated handshake record as a discarded 0-RTT record");
    _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "reset the client record sequence for the application epoch after Client Finished");
}

static void test_tls13_rejected_early_data_trial_decryption_sequence() {
    // Scenario under test: TLS 1.3 rejected 0-RTT trial decryption restores record sequence.
    // Action: serialize a real client 0-RTT application_data record.
    // Expected: emit a protected 0-RTT record with the complete AES-GCM authentication tag.
    _test_case.begin("TLS 1.3 rejected 0-RTT trial decryption restores record sequence");

    constexpr uint16 cipher_suite = 0x1301;
    const binary_t early_key(16, 0x31);
    const binary_t early_iv(12, 0x32);
    const binary_t handshake_key(16, 0x41);
    const binary_t handshake_iv(12, 0x42);
    const binary_t application_data = {0x70, 0x69, 0x6e, 0x67};

    auto configure_writer = [&](tls_session& writer, tls_flow_t flow, tls_secret_t key_type, tls_secret_t iv_type, const binary_t& key, const binary_t& iv) {
        writer.set_type(session_type_t::tls);
        auto& protection = writer.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(cipher_suite);
        protection.set_flow(flow);
        protection.get_secrets().assign(key_type, key);
        protection.get_secrets().assign(iv_type, iv);
        writer.update_session_status(session_status_client_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        if (tls_flow_t::zero_rtt == flow) {
            auto& early_state = writer.get_session_info(from_server).get_keyvalue();
            early_state.set(session_early_data_offered, 1);
            early_state.set(session_early_data_limit, 1024);
            early_state.set(session_early_data_sent, 0);
        } else {
            writer.update_session_status(session_status_server_hello);
        }
        // Record protection is an explicit session-info state; installing
        // traffic secrets and advancing handshake status alone is not enough.
        writer.get_session_info(from_client).begin_protection();
    };

    tls_session early_writer;
    configure_writer(early_writer, tls_flow_t::zero_rtt, tls_secret_t::c_e_traffic_key, tls_secret_t::c_e_traffic_iv, early_key, early_iv);
    tls_record_application_data early_record(&early_writer, application_data);
    binary_t rejected_early_wire;
    return_t ret = early_record.write(from_client, rejected_early_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a real client 0-RTT application_data record");
    _test_case.assert(5 + application_data.size() + 1 + 16 == rejected_early_wire.size(), __FUNCTION__,
                      "emit a protected 0-RTT record with the complete AES-GCM authentication tag");

    tls_session handshake_writer;
    configure_writer(handshake_writer, tls_flow_t::one_rtt, tls_secret_t::handshake_client_key, tls_secret_t::handshake_client_iv, handshake_key, handshake_iv);
    // The writer must have sent Finished before ordinary application data can
    // be serialized. The receiver intentionally has not processed client
    // Finished, so this authenticated record must be rejected by message order.
    handshake_writer.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    // The writer's Finished state selects the application-key slots for
    // serialization. Alias those slots to the handshake traffic key so the
    // deliberately premature application_data record is still authenticated
    // with the handshake key that the receiver is trial-decrypting.
    handshake_writer.get_tls_protection().get_secrets().assign(tls_secret_t::application_client_key, handshake_key);
    handshake_writer.get_tls_protection().get_secrets().assign(tls_secret_t::application_client_iv, handshake_iv);
    tls_record_application_data handshake_record(&handshake_writer, application_data);
    binary_t handshake_wire;
    ret = handshake_record.write(from_client, handshake_wire);
    _test_case.test(ret, __FUNCTION__, "serialize application_data with the handshake traffic key after the writer's Finished state");
    _test_case.assert(5 + application_data.size() + 1 + 16 == handshake_wire.size(), __FUNCTION__,
                      "emit TLSInnerPlaintext ciphertext plus the complete AES-GCM authentication tag");

    tls_session server;
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls_13);
    server_protection.set_cipher_suite(cipher_suite);
    server_protection.set_flow(tls_flow_t::one_rtt);
    server_protection.get_secrets().assign(tls_secret_t::handshake_client_key, handshake_key);
    server_protection.get_secrets().assign(tls_secret_t::handshake_client_iv, handshake_iv);
    server.update_session_status(session_status_server_hello);
    server.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    server.get_session_info(from_client).begin_protection();

    auto& early_state = server.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered_initial, 1);
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_accepted, 0);
    early_state.set(session_early_data_discard_limit, 4096);
    early_state.set(session_early_data_discarded, 0);
    early_state.set(session_early_data_discarded_records, 0);
    server.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);

    if (errorcode_t::success == ret && false == rejected_early_wire.empty()) {
        tls_records rejected_records;
        ret = rejected_records.read(&server, from_client, rejected_early_wire);
        _test_case.test(ret, __FUNCTION__, "discard a real 0-RTT record that fails handshake-key trial decryption");
        _test_case.assert(0 == server.get_session_info(from_client).get_recordno(false), __FUNCTION__, "restore the client record number after failed trial decryption");
        _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__, "count the rejected 0-RTT record after authentication failure");
        _test_case.assert(rejected_early_wire.size() - 5 == early_state.get(session_early_data_discarded), __FUNCTION__, "account only the rejected ciphertext fragment");
        size_t bad_record_mac_count = 0;
        server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::bad_record_mac == desc)) {
                ++bad_record_mac_count;
            }
        });
        _test_case.assert(0 == bad_record_mac_count, __FUNCTION__, "suppress bad_record_mac while probing rejected early data");
    }

    if (errorcode_t::success == ret && false == handshake_wire.empty()) {
        tls_records handshake_records;
        ret = handshake_records.read(&server, from_client, handshake_wire);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__,
                          "reject application_data before the client's Finished after successful handshake-key authentication");
        _test_case.assert(1 == server.get_session_info(from_client).get_recordno(false), __FUNCTION__,
                          "keep the record number consumed by successful handshake-key trial decryption");
        _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__,
                          "do not count an authenticated handshake-key record as discarded early data");
        size_t unexpected_message_count = 0;
        server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::unexpected_message == desc)) {
                ++unexpected_message_count;
            }
        });
        _test_case.assert(1 == unexpected_message_count, __FUNCTION__, "report unexpected_message for application_data sent before the client's Finished");
    }
}

static void test_tls13_rejected_early_data_ccm_authentication() {
    // Scenario under test: TLS 1.3 rejected 0-RTT CCM records distinguish authentication failure from handshake-key success.
    // Action: serialize a real TLS 1.3 AES-CCM 0-RTT record.
    // Expected: emit the CCM record with its complete 16-byte authentication tag.
    _test_case.begin("TLS 1.3 rejected 0-RTT CCM records distinguish authentication failure from handshake-key success");

    constexpr uint16 cipher_suite = 0x1304;  // TLS_AES_128_CCM_SHA256
    const binary_t early_key(16, 0x31);
    const binary_t early_iv(12, 0x32);
    const binary_t handshake_key(16, 0x41);
    const binary_t handshake_iv(12, 0x42);
    const binary_t application_data = {0x70, 0x69, 0x6e, 0x67};

    auto configure_writer = [&](tls_session& writer, tls_flow_t flow, tls_secret_t key_type, tls_secret_t iv_type, const binary_t& key, const binary_t& iv) {
        writer.set_type(session_type_t::tls);
        auto& protection = writer.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(cipher_suite);
        protection.set_flow(flow);
        protection.get_secrets().assign(key_type, key);
        protection.get_secrets().assign(iv_type, iv);
        writer.update_session_status(session_status_client_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        if (tls_flow_t::zero_rtt == flow) {
            auto& early_state = writer.get_session_info(from_server).get_keyvalue();
            early_state.set(session_early_data_offered, 1);
            early_state.set(session_early_data_limit, 1024);
            early_state.set(session_early_data_sent, 0);
        } else {
            writer.update_session_status(session_status_server_hello);
        }
        writer.get_session_info(from_client).begin_protection();
    };

    tls_session early_writer;
    configure_writer(early_writer, tls_flow_t::zero_rtt, tls_secret_t::c_e_traffic_key, tls_secret_t::c_e_traffic_iv, early_key, early_iv);
    tls_record_application_data early_record(&early_writer, application_data);
    binary_t rejected_early_wire;
    return_t ret = early_record.write(from_client, rejected_early_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a real TLS 1.3 AES-CCM 0-RTT record");
    _test_case.assert(5 + application_data.size() + 1 + 16 == rejected_early_wire.size(), __FUNCTION__,
                      "emit the CCM record with its complete 16-byte authentication tag");

    tls_session handshake_writer;
    configure_writer(handshake_writer, tls_flow_t::one_rtt, tls_secret_t::handshake_client_key, tls_secret_t::handshake_client_iv, handshake_key, handshake_iv);
    handshake_writer.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
    handshake_writer.get_tls_protection().get_secrets().assign(tls_secret_t::application_client_key, handshake_key);
    handshake_writer.get_tls_protection().get_secrets().assign(tls_secret_t::application_client_iv, handshake_iv);
    tls_record_application_data handshake_record(&handshake_writer, application_data);
    binary_t handshake_wire;
    ret = handshake_record.write(from_client, handshake_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a handshake-key-protected AES-CCM record");
    _test_case.assert(5 + application_data.size() + 1 + 16 == handshake_wire.size(), __FUNCTION__,
                      "emit a handshake-key CCM record with its complete authentication tag");

    tls_session server;
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls_13);
    server_protection.set_cipher_suite(cipher_suite);
    server_protection.set_flow(tls_flow_t::one_rtt);
    server_protection.get_secrets().assign(tls_secret_t::handshake_client_key, handshake_key);
    server_protection.get_secrets().assign(tls_secret_t::handshake_client_iv, handshake_iv);
    server.update_session_status(session_status_server_hello);
    server.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    server.get_session_info(from_client).begin_protection();

    auto& early_state = server.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered_initial, 1);
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_accepted, 0);
    early_state.set(session_early_data_discard_limit, 4096);
    early_state.set(session_early_data_discarded, 0);
    early_state.set(session_early_data_discarded_records, 0);
    server.get_keyvalue().set(session_server_psk_selected_identity, 0xffff);

    if (errorcode_t::success == ret && false == rejected_early_wire.empty()) {
        tls_records rejected_records;
        ret = rejected_records.read(&server, from_client, rejected_early_wire);
        _test_case.test(ret, __FUNCTION__, "discard rejected 0-RTT ciphertext after CCM handshake-key authentication fails");
        _test_case.assert(0 == server.get_session_info(from_client).get_recordno(false), __FUNCTION__, "restore the record number after failed CCM trial authentication");
        _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__, "count the rejected CCM 0-RTT record");
        _test_case.assert(rejected_early_wire.size() - 5 == early_state.get(session_early_data_discarded), __FUNCTION__, "account the rejected CCM ciphertext fragment");
        size_t bad_record_mac_count = 0;
        server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
            if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::bad_record_mac == desc)) {
                ++bad_record_mac_count;
            }
        });
        _test_case.assert(0 == bad_record_mac_count, __FUNCTION__, "suppress bad_record_mac for rejected CCM 0-RTT probing");
    }

    if (errorcode_t::success == ret && false == handshake_wire.empty()) {
        tls_records handshake_records;
        ret = handshake_records.read(&server, from_client, handshake_wire);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "authenticate a handshake-key CCM record before rejecting its premature application_data message");
        _test_case.assert(1 == server.get_session_info(from_client).get_recordno(false), __FUNCTION__,
                          "consume the record number after successful CCM handshake-key authentication");
        _test_case.assert(1 == early_state.get(session_early_data_discarded_records), __FUNCTION__,
                          "do not count authenticated CCM handshake ciphertext as discarded early data");
    }
}

static void test_tls13_hrr_rejected_early_data_discard_bounds() {
    // Scenario under test: TLS 1.3 HRR bounds discarded in-flight 0-RTT records.
    // Action: skip an in-flight rejected 0-RTT record during HRR.
    // Expected: consume one rejected record without exposing an error.
    _test_case.begin("TLS 1.3 HRR bounds discarded in-flight 0-RTT records");

    tls_session server;
    server.set_type(session_type_t::tls);
    auto& protection = server.get_tls_protection();
    protection.set_tls_version(tls_13);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::hello_retry_request);
    server.update_session_status(session_status_hello_retry_request);
    server.set_early_data_discard_limit(1024);

    auto& early_state = server.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered_initial, 1);
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_accepted, 0);
    early_state.set(session_early_data_discard_limit, 1024);
    early_state.set(session_early_data_discarded, 0);
    early_state.set(session_early_data_discarded_records, 0);

    // An opaque application_data record is intentionally not decryptable.
    // During HRR it must be skipped without attempting 0-RTT authentication.
    binary_t rejected_record = {0x17, 0x03, 0x03, 0x00, 0x10};
    rejected_record.insert(rejected_record.end(), 16, 0xa5);

    for (size_t i = 0; i < 64; ++i) {
        tls_records records;
        return_t ret = records.read(&server, from_client, rejected_record);
        _test_case.test(ret, __FUNCTION__, "skip an in-flight rejected 0-RTT record during HRR");
        if (errorcode_t::success != ret) {
            break;
        }
        _test_case.assert(1 == records.size(), __FUNCTION__, "consume one rejected record without exposing an error");
        if (records.size()) {
            auto decoded = static_cast<tls_record_application_data*>(records.getat(0));
            _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "do not expose rejected 0-RTT ciphertext as plaintext");
        }
    }

    _test_case.assert(1024 == early_state.get(session_early_data_discarded), __FUNCTION__, "account the ciphertext bytes skipped during HRR");
    _test_case.assert(64 == early_state.get(session_early_data_discarded_records), __FUNCTION__, "account each skipped TLS record during HRR");

    tls_records over_limit_records;
    return_t over_limit_ret = over_limit_records.read(&server, from_client, rejected_record);
    _test_case.assert(errorcode_t::success != over_limit_ret, __FUNCTION__, "reject the sixty-fifth in-flight 0-RTT record");
    _test_case.assert(1024 == early_state.get(session_early_data_discarded), __FUNCTION__, "do not increase the discarded-byte counter after the record-count limit");
    _test_case.assert(64 == early_state.get(session_early_data_discarded_records), __FUNCTION__,
                      "do not increase the discarded-record counter after the record-count limit");

    // A separate session verifies that the configured byte budget is enforced
    // independently of the 64-record ceiling.
    tls_session byte_limited_server;
    byte_limited_server.set_type(session_type_t::tls);
    auto& byte_limited_protection = byte_limited_server.get_tls_protection();
    byte_limited_protection.set_tls_version(tls_13);
    byte_limited_protection.set_cipher_suite(0x1301);
    byte_limited_protection.set_flow(tls_flow_t::hello_retry_request);
    byte_limited_server.update_session_status(session_status_hello_retry_request);
    byte_limited_server.set_early_data_discard_limit(15);
    auto& byte_limited_state = byte_limited_server.get_session_info(from_server).get_keyvalue();
    byte_limited_state.set(session_early_data_offered_initial, 1);
    byte_limited_state.set(session_early_data_discard_limit, 15);

    tls_records byte_limited_records;
    return_t byte_limited_ret = byte_limited_records.read(&byte_limited_server, from_client, rejected_record);
    _test_case.assert(errorcode_t::success != byte_limited_ret, __FUNCTION__, "reject a record larger than the configured ciphertext budget");
    _test_case.assert(0 == byte_limited_state.get(session_early_data_discarded), __FUNCTION__,
                      "leave the discarded-byte counter unchanged when the byte budget is exceeded");
    _test_case.assert(0 == byte_limited_state.get(session_early_data_discarded_records), __FUNCTION__,
                      "leave the discarded-record counter unchanged when the byte budget is exceeded");
}

void testcase_gpt_early_data_buffer() {
    test_tls13_server_defers_inflight_early_data_until_encrypted_extensions();
    test_tls13_client_hello_resets_rejected_early_data_counters();
    test_tls13_hrr_drains_buffered_early_data();
    test_tls13_server_discards_rejected_early_data_records();
    test_tls13_rejected_early_data_trial_decrypt_success();
    test_tls13_rejected_early_data_trial_decryption_sequence();
    test_tls13_rejected_early_data_ccm_authentication();
    test_tls13_hrr_rejected_early_data_discard_bounds();
}
