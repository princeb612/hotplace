/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_record.cpp
 * @author GPT
 * @desc   TLS and DTLS record framing, protection, size-limit, and AEAD boundary tests.
 */

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "testcase_gpt_common.hpp"

static void test_configure_tls12_cbc_mte_session(tls_session& session) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc027);  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    protection.get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x31));
    protection.get_secrets().assign(tls_secret_t::client_mac_key, binary_t(32, 0x52));
    session.get_keyvalue().set(session_encrypt_then_mac, 0);
}

static return_t test_build_tls12_cbc_mte_record(tls_session& session, const binary_t& content, const binary_t& padding, const binary_t& iv, binary_t& wire,
                                                bool corrupt_mac = false, uint64 record_no = 0) {
    auto& protection = session.get_tls_protection();
    const binary_t& enckey = protection.get_secrets().get(tls_secret_t::client_key);
    const binary_t& mackey = protection.get_secrets().get(tls_secret_t::client_mac_key);

    binary_t aad;
    binary_append(aad, record_no, hton64);
    binary_append(aad, uint8(0x17));
    binary_append(aad, uint16(0x0303), hton16);  // application_data || TLS 1.2
    crypto_hmac_builder builder;
    crypto_hmac* hmac = builder.set(hash_algorithm_t::sha2_256).set(mackey).build();
    if (nullptr == hmac) {
        return errorcode_t::not_supported;
    }

    binary_t mac;
    hmac->update(aad).update(static_cast<uint16>(content.size()), hton16).update(content).finalize(mac);
    hmac->release();
    if (corrupt_mac && false == mac.empty()) {
        mac[0] ^= 0x01;
    }

    binary_t raw;
    binary_append(raw, content);
    binary_append(raw, mac);
    binary_append(raw, padding);

    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    binary_t ciphertext;
    return_t ret = crypt.open(&handle, crypt_algorithm_t::aes128, crypt_mode_t::cbc, enckey, iv);
    if (errorcode_t::success == ret) {
        ret = crypt.set(handle, crypt_ctrl_t::padding, 0);
    }
    if (errorcode_t::success == ret) {
        ret = crypt.encrypt(handle, raw, ciphertext);
    }
    if (nullptr != handle) {
        crypt.close(handle);
    }
    if (errorcode_t::success != ret) {
        return ret;
    }

    binary_t fragment = iv;
    fragment.insert(fragment.end(), ciphertext.begin(), ciphertext.end());
    const uint16 fragment_size = static_cast<uint16>(fragment.size());
    wire = binary_t{0x17, 0x03, 0x03, static_cast<byte_t>(fragment_size >> 8), static_cast<byte_t>(fragment_size)};
    wire.insert(wire.end(), fragment.begin(), fragment.end());
    return errorcode_t::success;
}

static return_t test_build_tls12_cbc_mte_raw_record(tls_session& session, const binary_t& raw, const binary_t& iv, binary_t& wire) {
    const binary_t& enckey = session.get_tls_protection().get_secrets().get(tls_secret_t::client_key);
    openssl_crypt crypt;
    crypt_context_t* handle = nullptr;
    binary_t ciphertext;
    return_t ret = crypt.open(&handle, crypt_algorithm_t::aes128, crypt_mode_t::cbc, enckey, iv);
    if (errorcode_t::success == ret) {
        ret = crypt.set(handle, crypt_ctrl_t::padding, 0);
    }
    if (errorcode_t::success == ret) {
        ret = crypt.encrypt(handle, raw, ciphertext);
    }
    if (nullptr != handle) {
        crypt.close(handle);
    }
    if (errorcode_t::success != ret) {
        return ret;
    }

    binary_t fragment = iv;
    fragment.insert(fragment.end(), ciphertext.begin(), ciphertext.end());
    const uint16 fragment_size = static_cast<uint16>(fragment.size());
    wire = binary_t{0x17, 0x03, 0x03, static_cast<byte_t>(fragment_size >> 8), static_cast<byte_t>(fragment_size)};
    wire.insert(wire.end(), fragment.begin(), fragment.end());
    return errorcode_t::success;
}

static void test_configure_tls12_ccs_session(tls_session& session) {
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    protection.get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
    protection.get_secrets().assign(tls_secret_t::client_iv, binary_t(4, 0x21));
    protection.get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x12));
    protection.get_secrets().assign(tls_secret_t::server_iv, binary_t(4, 0x22));
    session.get_keyvalue().set(session_tls_version, tls1_2);
    session.update_session_status(session_status_server_key_exchange);
    session.update_session_status(session_status_client_key_exchange);
}

static return_t test_configure_tls12_renegotiation_ccs_session(tls_session& session) {
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

static void test_tls12_renegotiation_ccs_transition() {
    // RFC 5746 + RFC 5246 §7.1: the old directional keys remain active until
    // that direction's CCS installs its pending renegotiation key block.
    _test_case.begin("TLS 1.2 renegotiation CCS activates pending directional keys");

    const binary_t ccs_wire{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

    binary_t client_ccs_wire;
    binary_t server_ccs_wire;
    {
        tls_session writer;
        return_t setup_ret = test_configure_tls12_renegotiation_ccs_session(writer);
        _test_case.test(setup_ret, __FUNCTION__, "derive the pending renegotiation key block without replacing active keys");
        const binary_t pending_client_key = writer.get_tls_protection().get_secrets().get(tls_secret_t::client_key_renegotiation);
        const binary_t pending_server_key = writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key_renegotiation);
        _test_case.assert(16 == pending_client_key.size() && 16 == pending_server_key.size(), __FUNCTION__, "derive both AES-128 directional renegotiation keys");
        _test_case.assert(binary_t(16, 0x11) == writer.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "keep the active client key unchanged while deriving pending keys");
        _test_case.assert(binary_t(16, 0x12) == writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "keep the active server key unchanged while deriving pending keys");
        writer.set_recordno(from_client, 101);
        writer.set_recordno(from_server, 103);
        tls_record_change_cipher_spec ccs(&writer);

        return_t ret = ccs.write(from_client, client_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "write the client renegotiation CCS");
        _test_case.assert((client_ccs_wire.size() > ccs_wire.size()) && (0x14 == client_ccs_wire[0]), __FUNCTION__,
                          "encrypt the client CCS under the old client write state");
        _test_case.assert(pending_client_key == writer.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "activate the derived client write key at client CCS");
        _test_case.assert(binary_t(16, 0x12) == writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "preserve the old server write key until server CCS");
        _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "reset only the client record sequence at renegotiation CCS");
        _test_case.assert(103 == writer.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence until its CCS");
        _test_case.assert(1 == writer.get_session_info(from_client).get_keyvalue().get(session_tls12_renegotiation_ccs), __FUNCTION__,
                          "remember that the client direction has switched");

        writer.update_session_status(session_status_client_finished);
        ret = ccs.write(from_server, server_ccs_wire);
        _test_case.test(ret, __FUNCTION__, "write the server renegotiation CCS after Client Finished");
        _test_case.assert((server_ccs_wire.size() > ccs_wire.size()) && (0x14 == server_ccs_wire[0]), __FUNCTION__,
                          "encrypt the server CCS under the old server write state");
        _test_case.assert(pending_server_key == writer.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "activate the derived server write key at server CCS");
        _test_case.assert(0 == writer.get_recordno(from_server), __FUNCTION__, "reset the server record sequence at its CCS");
        binary_t duplicate_wire;
        _test_case.assert(errorcode_t::unexpected == ccs.write(from_client, duplicate_wire), __FUNCTION__, "reject a duplicate client CCS in one renegotiation");
    }

    {
        tls_session reader;
        return_t setup_ret = test_configure_tls12_renegotiation_ccs_session(reader);
        _test_case.test(setup_ret, __FUNCTION__, "derive the matching pending read key block");
        const binary_t pending_client_key = reader.get_tls_protection().get_secrets().get(tls_secret_t::client_key_renegotiation);
        const binary_t pending_server_key = reader.get_tls_protection().get_secrets().get(tls_secret_t::server_key_renegotiation);
        reader.set_recordno(from_client, 101);
        reader.set_recordno(from_server, 103);
        tls_record_change_cipher_spec ccs(&reader);
        size_t pos = 0;
        return_t ret = ccs.read(from_client, client_ccs_wire.data(), client_ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the client renegotiation CCS under the old client read state");
        _test_case.assert(client_ccs_wire.size() == pos, __FUNCTION__, "consume the encrypted client CCS");
        _test_case.assert(pending_client_key == reader.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "activate the derived client read key at client CCS");
        _test_case.assert(103 == reader.get_recordno(from_server), __FUNCTION__, "preserve the server read sequence until its CCS");

        reader.update_session_status(session_status_client_finished);
        pos = 0;
        ret = ccs.read(from_server, server_ccs_wire.data(), server_ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the server renegotiation CCS under the old server read state");
        _test_case.assert(server_ccs_wire.size() == pos, __FUNCTION__, "consume the encrypted server CCS");
        _test_case.assert(pending_server_key == reader.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "activate the derived server read key at server CCS");
        _test_case.assert(0 == reader.get_recordno(from_server), __FUNCTION__, "reset the server read sequence at its CCS");
    }
    {
        tls_session reader;
        return_t setup_ret = test_configure_tls12_renegotiation_ccs_session(reader);
        _test_case.test(setup_ret, __FUNCTION__, "prepare a renegotiation CCS receiver with active and pending keys");
        reader.get_tls_protection().set_cipher_suite(0);
        reader.get_session_info(from_client).reset_protection();
        const binary_t plaintext_ccs{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
        tls_record_change_cipher_spec ccs(&reader);
        size_t pos = 0;
        return_t ret = ccs.read(from_client, plaintext_ccs.data(), plaintext_ccs.size(), pos);
        _test_case.assert(errorcode_t::internal_error == ret, __FUNCTION__, "report an internal error when CCS has no negotiated cipher suite");
        _test_case.assert(1 == test_count_fatal_alert(reader, from_client, tls_alertdesc_t::internal_error), __FUNCTION__,
                          "queue fatal internal_error for missing CCS cipher-suite state");
        _test_case.assert(binary_t(16, 0x11) == reader.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "leave the active client key unchanged when CCS activation cannot proceed");
        _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "do not reset the client record sequence when CCS activation fails");
    }
}

static void test_tls12_ccs_sequence_reset() {
    // RFC 5246 §6.1: each directional connection state starts with sequence number zero.
    // Action: activate the client and server TLS 1.2 write/read states through CCS.
    // Expected: reset only the direction whose new protection state is activated.
    _test_case.begin("TLS 1.2 CCS resets directional record sequence numbers");

    const binary_t ccs_wire{0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

    {
        tls_session writer;
        test_configure_tls12_ccs_session(writer);
        writer.set_recordno(from_client, 17);
        writer.set_recordno(from_server, 29);

        tls_record_change_cipher_spec ccs(&writer);
        binary_t client_wire;
        return_t ret = ccs.write(from_client, client_wire);
        _test_case.test(ret, __FUNCTION__, "write the initial client CCS");
        _test_case.assert(ccs_wire == client_wire, __FUNCTION__, "serialize a plaintext TLS 1.2 CCS record");
        _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "reset the client write sequence at its CCS transition");
        _test_case.assert(29 == writer.get_recordno(from_server), __FUNCTION__, "preserve the independent server write sequence");
        _test_case.assert(writer.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate client write protection after CCS");
        _test_case.assert(0xc02f == writer.get_session_info(from_client).get_active_cipher_suite(), __FUNCTION__, "activate the client cipher suite at its CCS");
        _test_case.assert(0 == writer.get_session_info(from_server).get_active_cipher_suite(), __FUNCTION__, "leave the server cipher suite unchanged until its CCS");

        writer.update_session_status(session_status_client_finished);
        writer.set_recordno(from_server, 31);
        binary_t server_wire;
        ret = ccs.write(from_server, server_wire);
        _test_case.test(ret, __FUNCTION__, "write the initial server CCS after Client Finished");
        _test_case.assert(ccs_wire == server_wire, __FUNCTION__, "serialize the server CCS as plaintext");
        _test_case.assert(0 == writer.get_recordno(from_server), __FUNCTION__, "reset the server write sequence at its CCS transition");
        _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "preserve the already-reset client write sequence");
        _test_case.assert(0xc02f == writer.get_session_info(from_server).get_active_cipher_suite(), __FUNCTION__, "activate the server cipher suite at its CCS");
    }

    {
        tls_session reader;
        test_configure_tls12_ccs_session(reader);
        reader.set_recordno(from_client, 37);
        reader.set_recordno(from_server, 43);

        tls_record_change_cipher_spec ccs(&reader);
        size_t pos = 0;
        return_t ret = ccs.read(from_client, ccs_wire.data(), ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the initial client CCS");
        _test_case.assert(ccs_wire.size() == pos, __FUNCTION__, "consume the complete client CCS record");
        _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "reset the client read sequence at its CCS transition");
        _test_case.assert(43 == reader.get_recordno(from_server), __FUNCTION__, "preserve the independent server read sequence");
        _test_case.assert(reader.get_session_info(from_client).apply_protection(), __FUNCTION__, "activate client read protection after CCS");
        _test_case.assert(0xc02f == reader.get_session_info(from_client).get_active_cipher_suite(), __FUNCTION__, "activate the inbound client cipher suite at its CCS");

        reader.update_session_status(session_status_client_finished);
        pos = 0;
        ret = ccs.read(from_server, ccs_wire.data(), ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the initial server CCS after Client Finished");
        _test_case.assert(ccs_wire.size() == pos, __FUNCTION__, "consume the complete server CCS record");
        _test_case.assert(0 == reader.get_recordno(from_server), __FUNCTION__, "reset the server read sequence at its CCS transition");
        _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "preserve the already-reset client read sequence");
        _test_case.assert(0xc02f == reader.get_session_info(from_server).get_active_cipher_suite(), __FUNCTION__, "activate the inbound server cipher suite at its CCS");

        reader.set_recordno(from_client, 53);
        pos = 0;
        ret = ccs.read(from_client, ccs_wire.data(), ccs_wire.size(), pos);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject an unauthenticated duplicate client CCS under active protection");
        _test_case.assert(0 != reader.get_recordno(from_client), __FUNCTION__, "do not reset the sequence number on a rejected second CCS");
        _test_case.assert(1 == test_count_fatal_alerts(reader, from_client), __FUNCTION__,
                          "queue one fatal alert for a duplicate CCS that fails active-state authentication");
    }

    {
        tls_session writer;
        test_configure_tls12_ccs_session(writer);
        writer.get_keyvalue().set(session_tls12_ticket_resumed, 1);
        writer.set_recordno(from_client, 61);
        writer.set_recordno(from_server, 67);

        tls_record_change_cipher_spec ccs(&writer);
        binary_t server_wire;
        return_t ret = ccs.write(from_server, server_wire);
        _test_case.test(ret, __FUNCTION__, "write the server CCS first in an abbreviated TLS 1.2 handshake");
        _test_case.assert(ccs_wire == server_wire, __FUNCTION__, "serialize the abbreviated server CCS as plaintext");
        _test_case.assert(0 == writer.get_recordno(from_server), __FUNCTION__, "reset the abbreviated server write sequence");
        _test_case.assert(61 == writer.get_recordno(from_client), __FUNCTION__, "preserve the client write sequence until its CCS");

        writer.update_session_status(session_status_server_finished);
        binary_t client_wire;
        ret = ccs.write(from_client, client_wire);
        _test_case.test(ret, __FUNCTION__, "write the client CCS after Server Finished in an abbreviated handshake");
        _test_case.assert(ccs_wire == client_wire, __FUNCTION__, "serialize the abbreviated client CCS as plaintext");
        _test_case.assert(0 == writer.get_recordno(from_client), __FUNCTION__, "reset the abbreviated client write sequence");
        _test_case.assert(0 == writer.get_recordno(from_server), __FUNCTION__, "preserve the already-reset server write sequence");
    }

    {
        tls_session reader;
        test_configure_tls12_ccs_session(reader);
        reader.get_keyvalue().set(session_tls12_ticket_resumed, 1);
        reader.set_recordno(from_client, 71);
        reader.set_recordno(from_server, 73);

        tls_record_change_cipher_spec ccs(&reader);
        size_t pos = 0;
        return_t ret = ccs.read(from_server, ccs_wire.data(), ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the server CCS first in an abbreviated TLS 1.2 handshake");
        _test_case.assert(ccs_wire.size() == pos, __FUNCTION__, "consume the abbreviated server CCS record");
        _test_case.assert(0 == reader.get_recordno(from_server), __FUNCTION__, "reset the abbreviated server read sequence");
        _test_case.assert(71 == reader.get_recordno(from_client), __FUNCTION__, "preserve the client read sequence until its CCS");

        reader.update_session_status(session_status_server_finished);
        pos = 0;
        ret = ccs.read(from_client, ccs_wire.data(), ccs_wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "read the client CCS after Server Finished in an abbreviated handshake");
        _test_case.assert(ccs_wire.size() == pos, __FUNCTION__, "consume the abbreviated client CCS record");
        _test_case.assert(0 == reader.get_recordno(from_client), __FUNCTION__, "reset the abbreviated client read sequence");
        _test_case.assert(0 == reader.get_recordno(from_server), __FUNCTION__, "preserve the already-reset server read sequence");
    }
}

static void test_tls12_initial_secure_renegotiation_scsv() {
    _test_case.begin("TLS 1.2 ClientHello signals secure renegotiation with SCSV");

    tls_session client;
    client.get_tls_protection().set_tls_version(tls1_2);
    client.get_keyvalue().set(session_tls_version, tls1_2);
    tls_handshake_client_hello hello(&client);
    hello.add_ciphersuite(0xc02f);
    auto versions = new tls_extension_client_supported_versions(&hello);
    versions->add(tls1_2);
    hello.get_extensions().add(versions);

    binary_t wire;
    return_t ret = hello.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "serialize an initial TLS 1.2 ClientHello");
    if (errorcode_t::success == ret) {
        const size_t session_id_length_offset = 4 + 2 + 32;
        size_t cipher_suite_length_offset = session_id_length_offset + 1;
        if (wire.size() > session_id_length_offset) {
            cipher_suite_length_offset += wire[session_id_length_offset];
        }
        bool has_scsv =
            (wire.size() >= cipher_suite_length_offset + 6) && (wire[cipher_suite_length_offset + 4] == 0x00) && (wire[cipher_suite_length_offset + 5] == 0xff);
        uint16 cipher_suite_length =
            (wire.size() >= cipher_suite_length_offset + 2) ? static_cast<uint16>((wire[cipher_suite_length_offset] << 8) | wire[cipher_suite_length_offset + 1]) : 0;
        _test_case.assert(4 == cipher_suite_length, __FUNCTION__, "append one two-byte SCSV after the offered TLS 1.2 cipher suite");
        _test_case.assert(has_scsv, __FUNCTION__, "encode TLS_EMPTY_RENEGOTIATION_INFO_SCSV as 0x00ff");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__,
                          "remember that the client signaled secure renegotiation");

        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        tls_handshake_client_hello peer_hello(&server);
        size_t pos = 0;
        ret = peer_hello.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "parse the peer ClientHello carrying the SCSV");
        _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete ClientHello");
        _test_case.assert(1 == server.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__, "recognize the peer's secure-renegotiation signal");

        bool scsv_in_negotiation_list = false;
        server.get_tls_protection().get_protection_context().for_each_cipher_suites([&](uint16 offered, bool* stop) -> void {
            if (0x00ff == offered) {
                scsv_in_negotiation_list = true;
                *stop = true;
            }
        });
        _test_case.assert(false == scsv_in_negotiation_list, __FUNCTION__, "exclude the signaling value from cipher-suite negotiation");

        {
            tls_session server_hello_session;
            server_hello_session.get_tls_protection().set_tls_version(tls1_2);
            server_hello_session.get_keyvalue().set(session_tls_version, tls1_2);
            server_hello_session.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
            server_hello_session.update_session_status(session_status_client_hello);
            tls_handshake_server_hello server_hello(&server_hello_session);
            server_hello.set_version(tls1_2);
            ret = server_hello.set_cipher_suite(0xc02f);
            _test_case.test(ret, __FUNCTION__, "select a TLS 1.2 suite for the secure-renegotiation response");
            binary_t server_hello_wire;
            if (errorcode_t::success == ret) {
                ret = server_hello.write(from_server, server_hello_wire);
                _test_case.test(ret, __FUNCTION__, "write ServerHello after the peer signaled secure renegotiation");
                if (errorcode_t::success == ret) {
                    const binary_t renegotiation_info_wire{0xff, 0x01, 0x00, 0x01, 0x00};
                    bool has_renegotiation_info = (std::search(server_hello_wire.begin(), server_hello_wire.end(), renegotiation_info_wire.begin(),
                                                               renegotiation_info_wire.end()) != server_hello_wire.end());
                    _test_case.assert(has_renegotiation_info, __FUNCTION__, "echo an empty renegotiation_info extension in the initial ServerHello");
                    _test_case.assert(1 == server_hello_session.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                                      "record that secure renegotiation was established");

                    tls_session client_peer;
                    client_peer.get_tls_protection().set_tls_version(tls1_2);
                    client_peer.get_keyvalue().set(session_tls_version, tls1_2);
                    client_peer.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
                    client_peer.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
                    client_peer.update_session_status(session_status_client_hello);
                    tls_handshake_server_hello parsed_server_hello(&client_peer);
                    size_t client_pos = 0;
                    return_t client_ret = parsed_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), client_pos);
                    _test_case.test(client_ret, __FUNCTION__, "accept the empty renegotiation_info response after signaling support");
                    _test_case.assert(1 == client_peer.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                                      "record secure renegotiation on the client after ServerHello validation");

                    tls_session unsolicited_peer;
                    unsolicited_peer.get_tls_protection().set_tls_version(tls1_2);
                    unsolicited_peer.get_keyvalue().set(session_tls_version, tls1_2);
                    unsolicited_peer.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
                    unsolicited_peer.update_session_status(session_status_client_hello);
                    tls_handshake_server_hello unsolicited_server_hello(&unsolicited_peer);
                    size_t unsolicited_pos = 0;
                    client_ret = unsolicited_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), unsolicited_pos);
                    _test_case.assert(errorcode_t::handshake_failure == client_ret, __FUNCTION__, "reject renegotiation_info when the client did not signal support");
                    _test_case.assert(1 == test_count_fatal_alert(unsolicited_peer, from_server, tls_alertdesc_t::unsupported_extension), __FUNCTION__,
                                      "queue fatal unsupported_extension for an unsolicited response");
                }
            }
        }

        binary_t legacy_server_hello_wire;
        {
            tls_session legacy_server;
            legacy_server.get_tls_protection().set_tls_version(tls1_2);
            legacy_server.get_keyvalue().set(session_tls_version, tls1_2);
            legacy_server.update_session_status(session_status_client_hello);
            tls_handshake_server_hello legacy_server_hello(&legacy_server);
            legacy_server_hello.set_version(tls1_2);
            ret = legacy_server_hello.set_cipher_suite(0xc02f);
            _test_case.test(ret, __FUNCTION__, "select a TLS 1.2 suite without a secure-renegotiation offer");
            if (errorcode_t::success == ret) {
                ret = legacy_server_hello.write(from_server, legacy_server_hello_wire);
                _test_case.test(ret, __FUNCTION__, "write ServerHello without a secure-renegotiation offer");
                if (errorcode_t::success == ret) {
                    const binary_t renegotiation_info_wire{0xff, 0x01, 0x00, 0x01, 0x00};
                    bool has_renegotiation_info = (std::search(legacy_server_hello_wire.begin(), legacy_server_hello_wire.end(), renegotiation_info_wire.begin(),
                                                               renegotiation_info_wire.end()) != legacy_server_hello_wire.end());
                    _test_case.assert(false == has_renegotiation_info, __FUNCTION__, "do not send an unsolicited renegotiation_info extension");
                    _test_case.assert(0 == legacy_server.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                                      "leave secure renegotiation unestablished without a peer signal");
                }
            }
        }

        tls_session missing_response_peer;
        missing_response_peer.get_tls_protection().set_tls_version(tls1_2);
        missing_response_peer.get_keyvalue().set(session_tls_version, tls1_2);
        missing_response_peer.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
        missing_response_peer.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
        missing_response_peer.update_session_status(session_status_client_hello);
        tls_handshake_server_hello missing_response(&missing_response_peer);
        size_t missing_response_pos = 0;
        return_t missing_response_ret = missing_response.read(from_server, legacy_server_hello_wire.data(), legacy_server_hello_wire.size(), missing_response_pos);
        _test_case.assert(errorcode_t::handshake_failure == missing_response_ret, __FUNCTION__,
                          "reject an initial ServerHello that omits renegotiation_info after the client signaled support");
        _test_case.assert(0 == missing_response_peer.get_keyvalue().get(session_tls12_secure_renegotiation), __FUNCTION__,
                          "do not establish secure renegotiation when the server omits the required response");
        _test_case.assert(1 == test_count_fatal_alert(missing_response_peer, from_server, tls_alertdesc_t::handshake_failure), __FUNCTION__,
                          "queue one fatal handshake_failure for the missing initial response");
    }

    {
        tls_session tls13_client;
        tls13_client.get_tls_protection().set_tls_version(tls1_3);
        tls13_client.get_keyvalue().set(session_tls_version, tls1_3);
        tls_handshake_client_hello tls13_hello(&tls13_client);
        tls13_hello.add_ciphersuite(0x1301);
        auto tls13_versions = new tls_extension_client_supported_versions(&tls13_hello);
        tls13_versions->add(tls1_3);
        tls13_hello.get_extensions().add(tls13_versions);
        binary_t tls13_wire;
        ret = tls13_hello.write(from_client, tls13_wire);
        _test_case.test(ret, __FUNCTION__, "serialize a TLS 1.3-only ClientHello");
        if (errorcode_t::success == ret) {
            const size_t cipher_suite_length_offset = 4 + 2 + 32 + 1;
            uint16 cipher_suite_length = (tls13_wire.size() >= cipher_suite_length_offset + 2)
                                             ? static_cast<uint16>((tls13_wire[cipher_suite_length_offset] << 8) | tls13_wire[cipher_suite_length_offset + 1])
                                             : 0;
            _test_case.assert(2 == cipher_suite_length, __FUNCTION__, "do not append the TLS 1.2 renegotiation SCSV to a TLS 1.3-only offer");
            _test_case.assert(0 == tls13_client.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__,
                              "do not mark TLS 1.3 as secure-renegotiation capable");
        }
    }
}

static void test_tls12_hello_request_secure_renegotiation() {
    // RFC 5746: HelloRequest is not part of the handshake transcript.
    // A server may request renegotiation only after a secure TLS 1.2 handshake.
    _test_case.begin("TLS 1.2 HelloRequest starts secure renegotiation");

    const binary_t hello_request_wire{0x00, 0x00, 0x00, 0x00};

    {
        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        server.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        server.update_session_status(session_status_client_finished);
        server.update_session_status(session_status_server_finished);

        tls_handshake_builder builder;
        auto request = builder.set(tls_handshake_type_t::hello_request).set(&server).build();
        _test_case.assert(nullptr != request, __FUNCTION__, "construct the server HelloRequest");
        if (nullptr != request) {
            binary_t wire;
            return_t ret = request->write(from_server, wire);
            _test_case.test(ret, __FUNCTION__, "write HelloRequest after a secure TLS 1.2 handshake");
            _test_case.assert(hello_request_wire == wire, __FUNCTION__, "encode HelloRequest with an empty body");
            _test_case.assert(tls_flow_t::renegotiation == server.get_tls_protection().get_flow(), __FUNCTION__, "start the server-side renegotiation flow");
            request->release();
        }
    }

    {
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);

        tls_handshake_builder builder;
        auto request = builder.set(tls_handshake_type_t::hello_request).set(&client).build();
        _test_case.assert(nullptr != request, __FUNCTION__, "construct the client HelloRequest parser");
        if (nullptr != request) {
            size_t pos = 0;
            return_t ret = request->read(from_server, hello_request_wire.data(), hello_request_wire.size(), pos);
            _test_case.test(ret, __FUNCTION__, "accept the server HelloRequest after a secure TLS 1.2 handshake");
            _test_case.assert(hello_request_wire.size() == pos, __FUNCTION__, "consume the complete HelloRequest");
            _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__, "start the client-side renegotiation flow");
            request->release();
        }
    }

    {
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);

        tls_handshake_builder builder;
        auto request = builder.set(tls_handshake_type_t::hello_request).set(&client).build();
        _test_case.assert(nullptr != request, __FUNCTION__, "construct the disabled-policy HelloRequest parser");
        if (nullptr != request) {
            size_t pos = 0;
            return_t ret = request->read(from_server, hello_request_wire.data(), hello_request_wire.size(), pos);
            _test_case.test(ret, __FUNCTION__, "decline HelloRequest when secure renegotiation is not enabled");
            _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "keep the established flow when renegotiation is declined");
            size_t warning_count = 0;
            client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if ((tls_alertlevel_t::warning == level) && (tls_alertdesc_t::no_renegotiation == desc)) {
                    ++warning_count;
                }
            });
            _test_case.assert(1 == warning_count, __FUNCTION__, "queue one warning no_renegotiation alert");
            request->release();

            tls_session server;
            server.get_tls_protection().set_tls_version(tls1_2);
            server.get_tls_protection().set_flow(tls_flow_t::renegotiation);
            tls_record_alert warning(&client, tls_alertlevel_t::warning, tls_alertdesc_t::no_renegotiation);
            binary_t warning_wire;
            ret = warning.write(from_client, warning_wire);
            _test_case.test(ret, __FUNCTION__, "serialize the client's no_renegotiation warning");
            tls_record_alert peer_warning(&server);
            pos = 0;
            ret = peer_warning.read(from_client, warning_wire.data(), warning_wire.size(), pos);
            _test_case.test(ret, __FUNCTION__, "receive the client's no_renegotiation warning");
            _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), __FUNCTION__,
                              "restore the server's established flow after the client declines");
            const uint32 completed_status = session_status_client_finished | session_status_server_finished;
            _test_case.assert(completed_status == (server.get_session_status() & completed_status), __FUNCTION__,
                              "restore the completed-handshake status after the client declines");
            _test_case.assert(tls_handshake_type_t::finished == server.get_session_info(from_client).get_status(), __FUNCTION__,
                              "restore the client handshake cursor after the client declines");
        }
    }
}

static void test_tls12_renegotiation_policy_and_binding() {
    // TLS 1.2 renegotiation is policy-gated and requires the RFC 5746 binding.
    // Action: serialize and parse a post-handshake ClientHello with both gates enabled.
    // Expected: enter the renegotiation flow and carry the previous client Finished verify_data.
    _test_case.begin("TLS 1.2 renegotiation policy gate and binding validation");

    {
        const binary_t client_verifydata(12, 0x31);
        const binary_t server_verifydata(12, 0x42);
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
        const binary_t prior_alpn{0x02, 'h', '2'};
        client.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
        client.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1234);
        client.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 2345);
        client.get_keyvalue().set(session_tls12_ticket_resumed, 1);

        tls_handshake_client_hello hello(&client);
        hello.add_ciphersuite(0xc02f);
        auto versions = new tls_extension_client_supported_versions(&hello);
        versions->add(tls1_2);
        hello.get_extensions().add(versions);
        binary_t wire;
        return_t ret = hello.write(from_client, wire);
        _test_case.test(ret, __FUNCTION__, "write a secure renegotiation ClientHello when policy and RFC 5746 are enabled");
        _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__,
                          "enter the renegotiation flow before serializing the new ClientHello");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                          "retain active ALPN until the peer accepts renegotiation");
        _test_case.assert(1234 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the client record-size limit until the peer accepts renegotiation");
        _test_case.assert(2345 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the server record-size limit until the peer accepts renegotiation");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__,
                          "retain active resumption state until the peer accepts renegotiation");
        auto renegotiation_info = hello.get_extensions().get(tls_extension_type_t::renegotiation_info);
        _test_case.assert(nullptr != renegotiation_info, __FUNCTION__, "automatically include renegotiation_info in the renegotiation ClientHello");

        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        server.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        server.update_session_status(session_status_client_finished);
        server.update_session_status(session_status_server_finished);
        server.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
        server.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
        tls_handshake_client_hello peer_hello(&server);
        size_t pos = 0;
        ret = peer_hello.read(from_client, wire.data(), wire.size(), pos);
        _test_case.test(ret, __FUNCTION__, "accept the matching RFC 5746 binding on the peer");
        _test_case.assert(wire.size() == pos, __FUNCTION__, "consume the complete renegotiation ClientHello");
        _test_case.assert(tls_flow_t::renegotiation == server.get_tls_protection().get_flow(), __FUNCTION__, "enter the renegotiation flow on the receiving endpoint");
        _test_case.assert(1 == server.get_keyvalue().get(session_tls12_secure_renegotiation_offered), __FUNCTION__,
                          "recognize the renegotiation_info extension as the secure-renegotiation signal");

        {
            // A policy-disabled endpoint declines a valid peer renegotiation
            // with warning no_renegotiation and leaves the active connection intact.
            tls_session refusing_server;
            refusing_server.get_tls_protection().set_tls_version(tls1_2);
            refusing_server.get_tls_protection().set_cipher_suite(0xc02f);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x12));
            refusing_server.get_keyvalue().set(session_tls_version, tls1_2);
            refusing_server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
            refusing_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
            refusing_server.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
            refusing_server.update_session_status(session_status_client_finished);
            refusing_server.update_session_status(session_status_server_finished);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
            const binary_t prior_server_name{'e', 'x', 'a', 'm', 'p', 'l', 'e'};
            const binary_t prior_alpn{0x02, 'h', '2'};
            refusing_server.set_client_server_name(prior_server_name);
            refusing_server.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
            refusing_server.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 1234);
            refusing_server.set_recordno(from_client, 77);
            refusing_server.set_recordno(from_server, 79);

            tls_handshake_client_hello declined_hello(&refusing_server);
            size_t declined_pos = 0;
            return_t declined_ret = declined_hello.read(from_client, wire.data(), wire.size(), declined_pos);
            _test_case.test(declined_ret, __FUNCTION__, "decline a valid peer renegotiation when local policy is disabled");
            _test_case.assert(wire.size() == declined_pos, __FUNCTION__, "consume the declined ClientHello");
            _test_case.assert(tls_flow_t::one_rtt == refusing_server.get_tls_protection().get_flow(), __FUNCTION__,
                              "retain the established TLS flow after declining renegotiation");
            const uint32 completed_status = session_status_client_finished | session_status_server_finished;
            _test_case.assert(completed_status == (refusing_server.get_session_status() & completed_status), __FUNCTION__,
                              "preserve completed-handshake status after declining renegotiation");
            _test_case.assert(tls_handshake_type_t::finished == refusing_server.get_session_info(from_client).get_status(), __FUNCTION__,
                              "preserve the client handshake cursor after declining renegotiation");
            _test_case.assert(tls_handshake_type_t::finished == refusing_server.get_session_info(from_server).get_status(), __FUNCTION__,
                              "preserve the server handshake cursor after declining renegotiation");
            _test_case.assert(77 == refusing_server.get_recordno(from_client), __FUNCTION__, "preserve the client record sequence");
            _test_case.assert(79 == refusing_server.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence");
            _test_case.assert(binary_t(16, 0x11) == refusing_server.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                              "preserve the active client traffic key");
            _test_case.assert(binary_t(16, 0x12) == refusing_server.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                              "preserve the active server traffic key");
            _test_case.assert(prior_server_name == refusing_server.get_client_server_name(), __FUNCTION__, "preserve the active connection's server name");
            _test_case.assert(prior_alpn == refusing_server.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                              "preserve the active connection's negotiated ALPN");
            _test_case.assert(1234 == refusing_server.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                              "preserve the active connection's record_size_limit state");
            size_t warning_count = 0;
            refusing_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if ((tls_alertlevel_t::warning == level) && (tls_alertdesc_t::no_renegotiation == desc)) {
                    ++warning_count;
                }
            });
            _test_case.assert(1 == warning_count, __FUNCTION__, "queue one warning no_renegotiation alert");
            _test_case.assert(0 == test_count_fatal_alerts(refusing_server, from_client), __FUNCTION__, "do not terminate the active connection with a fatal alert");
        }

        // A peer must not be able to alter the previous client Finished value
        // while retaining an otherwise well-formed renegotiation_info extension.
        {
            binary_t bad_binding_wire = wire;
            binary_t client_binding_prefix{0xff, 0x01, 0x00, 0x0d, 0x0c};
            binary_append(client_binding_prefix, client_verifydata);
            auto binding = std::search(bad_binding_wire.begin(), bad_binding_wire.end(), client_binding_prefix.begin(), client_binding_prefix.end());
            _test_case.assert(binding != bad_binding_wire.end(), __FUNCTION__, "locate the ClientHello renegotiation_info binding");
            if (binding != bad_binding_wire.end()) {
                *(binding + client_binding_prefix.size() - 1) ^= 0x01;

                tls_session bad_server;
                bad_server.get_tls_protection().set_tls_version(tls1_2);
                bad_server.get_keyvalue().set(session_tls_version, tls1_2);
                bad_server.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
                bad_server.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
                bad_server.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                bad_server.update_session_status(session_status_client_finished);
                bad_server.update_session_status(session_status_server_finished);
                bad_server.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
                bad_server.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);

                tls_handshake_client_hello bad_peer(&bad_server);
                size_t bad_pos = 0;
                return_t bad_ret = bad_peer.read(from_client, bad_binding_wire.data(), bad_binding_wire.size(), bad_pos);
                _test_case.assert(errorcode_t::illegal_parameter == bad_ret, __FUNCTION__, "reject a ClientHello with a mismatched previous client Finished binding");
                _test_case.assert(1 == test_count_fatal_alert(bad_server, from_client, tls_alertdesc_t::illegal_parameter), __FUNCTION__,
                                  "queue fatal illegal_parameter for a mismatched ClientHello binding");
            }
        }

        tls_handshake_server_hello server_hello(&server);
        server_hello.set_version(tls1_2);
        ret = server_hello.set_cipher_suite(0xc02f);
        _test_case.test(ret, __FUNCTION__, "select the TLS 1.2 suite for the renegotiation ServerHello");
        binary_t server_hello_wire;
        if (errorcode_t::success == ret) {
            ret = server_hello.write(from_server, server_hello_wire);
            _test_case.test(ret, __FUNCTION__, "write ServerHello with the previous client and server Finished values");
        }
        if (errorcode_t::success == ret) {
            _test_case.assert(nullptr != server_hello.get_extensions().get(tls_extension_type_t::renegotiation_info), __FUNCTION__,
                              "include the ServerHello renegotiation_info extension");

            client.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
            client.get_tls_protection().set_flow(tls_flow_t::renegotiation);
            client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
            client.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
            client.update_session_status(session_status_client_hello);
            tls_handshake_server_hello peer_server_hello(&client);
            size_t server_pos = 0;
            ret = peer_server_hello.read(from_server, server_hello_wire.data(), server_hello_wire.size(), server_pos);
            _test_case.test(ret, __FUNCTION__, "validate the server's previous Finished verify_data binding");
            _test_case.assert(server_hello_wire.size() == server_pos, __FUNCTION__, "consume the complete renegotiation ServerHello");
            _test_case.assert(binary_t() == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                              "clear the previous ALPN after the peer accepts renegotiation without a new ALPN selection");
            _test_case.assert(0 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                              "clear the previous client record-size limit after ServerHello acceptance");
            _test_case.assert(0 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                              "clear the previous server record-size limit after ServerHello acceptance");
            _test_case.assert(0 == client.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__,
                              "reset the previous resumption mode for the accepted renegotiation");

            // Both Finished values are part of the ServerHello renegotiation_info
            // binding. A client must reject a peer that changes either value.
            {
                binary_t server_binding_prefix{0xff, 0x01, 0x00, 0x19, 0x18};
                binary_append(server_binding_prefix, client_verifydata);
                binary_append(server_binding_prefix, server_verifydata);
                const size_t binding_offsets[] = {5, 5 + client_verifydata.size()};
                const char* mismatch_messages[] = {
                    "reject ServerHello with mismatched previous client Finished binding",
                    "reject ServerHello with mismatched previous server Finished binding",
                };
                const char* alert_messages[] = {
                    "queue fatal illegal_parameter for mismatched previous client Finished binding",
                    "queue fatal illegal_parameter for mismatched previous server Finished binding",
                };
                for (size_t i = 0; i < sizeof(binding_offsets) / sizeof(binding_offsets[0]); ++i) {
                    binary_t bad_server_hello_wire = server_hello_wire;
                    auto binding = std::search(bad_server_hello_wire.begin(), bad_server_hello_wire.end(), server_binding_prefix.begin(), server_binding_prefix.end());
                    _test_case.assert(binding != bad_server_hello_wire.end(), __FUNCTION__, "locate the ServerHello renegotiation_info binding");
                    if (binding == bad_server_hello_wire.end()) {
                        continue;
                    }
                    *(binding + binding_offsets[i]) ^= 0x01;

                    tls_session bad_client;
                    bad_client.get_tls_protection().set_tls_version(tls1_2);
                    bad_client.get_tls_protection().get_protection_context().add_supported_version(tls1_2);
                    bad_client.get_tls_protection().set_flow(tls_flow_t::renegotiation);
                    bad_client.get_keyvalue().set(session_tls_version, tls1_2);
                    bad_client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
                    bad_client.get_keyvalue().set(session_tls12_secure_renegotiation_offered, 1);
                    bad_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
                    bad_client.update_session_status(session_status_client_finished);
                    bad_client.update_session_status(session_status_server_finished);
                    bad_client.get_tls_protection().get_secrets().assign(tls_secret_t::client_verifydata, client_verifydata);
                    bad_client.get_tls_protection().get_secrets().assign(tls_secret_t::server_verifydata, server_verifydata);
                    bad_client.update_session_status(session_status_client_hello);

                    tls_handshake_server_hello bad_peer_server_hello(&bad_client);
                    size_t bad_server_pos = 0;
                    return_t bad_server_ret = bad_peer_server_hello.read(from_server, bad_server_hello_wire.data(), bad_server_hello_wire.size(), bad_server_pos);
                    _test_case.assert(errorcode_t::illegal_parameter == bad_server_ret, __FUNCTION__, mismatch_messages[i]);
                    _test_case.assert(1 == test_count_fatal_alert(bad_client, from_server, tls_alertdesc_t::illegal_parameter), __FUNCTION__, alert_messages[i]);
                }
            }
        }
    }

    {
        tls_session renegotiating_client;
        renegotiating_client.get_tls_protection().set_tls_version(tls1_2);
        renegotiating_client.get_keyvalue().set(session_tls_version, tls1_2);
        renegotiating_client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        renegotiating_client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        renegotiating_client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        renegotiating_client.update_session_status(session_status_client_finished);
        renegotiating_client.update_session_status(session_status_server_finished);
        tls_handshake_client_hello invalid_writer(&renegotiating_client);
        invalid_writer.add_ciphersuite(0xc02f);
        invalid_writer.add_ciphersuite(0x00ff);
        binary_t invalid_wire;
        return_t invalid_ret = invalid_writer.write(from_client, invalid_wire);
        _test_case.assert(errorcode_t::bad_request == invalid_ret, __FUNCTION__, "refuse to serialize SCSV in a secure renegotiation ClientHello");
        _test_case.assert(invalid_wire.empty(), __FUNCTION__, "emit no ClientHello containing renegotiation SCSV");
        _test_case.assert(tls_flow_t::one_rtt == renegotiating_client.get_tls_protection().get_flow(), __FUNCTION__,
                          "preserve the established flow when rejecting an invalid local offer");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (renegotiating_client.get_session_status() & completed_status), __FUNCTION__,
                          "preserve the completed-handshake status when rejecting an invalid local offer");

        tls_session initial_client;
        initial_client.get_tls_protection().set_tls_version(tls1_2);
        initial_client.get_keyvalue().set(session_tls_version, tls1_2);
        tls_handshake_client_hello scsv_client_hello(&initial_client);
        scsv_client_hello.add_ciphersuite(0xc02f);
        scsv_client_hello.add_ciphersuite(0x00ff);
        auto versions = new tls_extension_client_supported_versions(&scsv_client_hello);
        versions->add(tls1_2);
        scsv_client_hello.get_extensions().add(versions);
        binary_t scsv_wire;
        invalid_ret = scsv_client_hello.write(from_client, scsv_wire);
        _test_case.test(invalid_ret, __FUNCTION__, "construct a ClientHello carrying the initial SCSV signal");
        if (errorcode_t::success == invalid_ret) {
            tls_session renegotiating_server;
            renegotiating_server.get_tls_protection().set_tls_version(tls1_2);
            renegotiating_server.get_tls_protection().set_flow(tls_flow_t::renegotiation);
            tls_handshake_client_hello invalid_peer(&renegotiating_server);
            size_t invalid_pos = 0;
            invalid_ret = invalid_peer.read(from_client, scsv_wire.data(), scsv_wire.size(), invalid_pos);
            _test_case.assert(errorcode_t::handshake_failure == invalid_ret, __FUNCTION__, "reject SCSV received in an established secure renegotiation");
            _test_case.assert(1 == test_count_fatal_alert(renegotiating_server, from_client, tls_alertdesc_t::handshake_failure), __FUNCTION__,
                              "queue fatal handshake_failure for renegotiation SCSV");
        }
    }

    {
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);
        client.set_recordno(from_client, 81);
        client.set_recordno(from_server, 83);
        const binary_t prior_server_name{'e', 'x', 'a', 'm', 'p', 'l', 'e'};
        const binary_t prior_alpn{0x02, 'h', '2'};
        client.set_client_server_name(prior_server_name);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
        client.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 1234);

        tls_handshake_client_hello hello(&client);
        binary_t wire;
        return_t ret = hello.write(from_client, wire);
        _test_case.assert(errorcode_t::negotiation_failure == ret, __FUNCTION__, "reject a locally initiated TLS 1.2 renegotiation");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no ClientHello for a prohibited renegotiation");
        _test_case.assert(0 == test_count_fatal_alerts(client, from_client), __FUNCTION__, "do not queue an alert for a locally rejected renegotiation attempt");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (client.get_session_status() & completed_status), __FUNCTION__,
                          "preserve completed-handshake status after local rejection");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_client).get_status(), __FUNCTION__,
                          "preserve the client handshake cursor after local rejection");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_server).get_status(), __FUNCTION__,
                          "preserve the server handshake cursor after local rejection");
        _test_case.assert(81 == client.get_recordno(from_client), __FUNCTION__, "preserve the client record sequence after local rejection");
        _test_case.assert(83 == client.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence after local rejection");
        _test_case.assert(prior_server_name == client.get_client_server_name(), __FUNCTION__, "preserve the active connection's server name");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                          "preserve the active connection's negotiated ALPN");
        _test_case.assert(1234 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "preserve the active connection's record_size_limit state");
        size_t local_alert_count = 0;
        client.get_alert(from_client, [&](tls_alertlevel_t, tls_alertdesc_t) -> void { ++local_alert_count; });
        _test_case.assert(0 == local_alert_count, __FUNCTION__, "do not queue any alert for a local policy rejection");
    }

    {
        // If a locally initiated renegotiation is declined by the peer, the
        // client must restore the still-active TLS 1.2 connection.
        const binary_t prior_server_name{'e', 'x', 'a', 'm', 'p', 'l', 'e'};
        const binary_t prior_alpn{0x02, 'h', '2'};
        tls_session client;
        client.get_tls_protection().set_tls_version(tls1_2);
        client.get_tls_protection().set_cipher_suite(0xc02f);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::client_key, binary_t(16, 0x11));
        client.get_tls_protection().get_secrets().assign(tls_secret_t::server_key, binary_t(16, 0x12));
        client.get_keyvalue().set(session_tls_version, tls1_2);
        client.get_keyvalue().set(session_conf_enable_tls12_renegotiation, 1);
        client.get_keyvalue().set(session_tls12_secure_renegotiation, 1);
        client.get_keyvalue().set(session_tls12_ticket_resumed, 1);
        client.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        client.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        client.update_session_status(session_status_client_finished);
        client.update_session_status(session_status_server_finished);
        client.set_recordno(from_client, 91);
        client.set_recordno(from_server, 93);
        client.set_client_server_name(prior_server_name);
        client.get_tls_protection().get_secrets().assign(tls_secret_t::alpn, prior_alpn);
        client.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1234);
        client.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 2345);

        tls_handshake_client_hello hello(&client);
        hello.add_ciphersuite(0xc02f);
        auto versions = new tls_extension_client_supported_versions(&hello);
        versions->add(tls1_2);
        hello.get_extensions().add(versions);
        binary_t client_hello_wire;
        return_t ret = hello.write(from_client, client_hello_wire);
        _test_case.test(ret, __FUNCTION__, "send a locally initiated secure renegotiation ClientHello");
        _test_case.assert(tls_flow_t::renegotiation == client.get_tls_protection().get_flow(), __FUNCTION__, "enter renegotiation while awaiting the peer's response");
        _test_case.assert(tls_handshake_type_t::client_hello == client.get_session_info(from_client).get_status(), __FUNCTION__,
                          "record the outstanding ClientHello while awaiting the peer's response");
        _test_case.assert(prior_server_name == client.get_client_server_name(), __FUNCTION__, "retain the active server name while awaiting renegotiation acceptance");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__,
                          "retain the active ALPN while awaiting renegotiation acceptance");
        _test_case.assert(1234 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the client record-size limit while awaiting renegotiation acceptance");
        _test_case.assert(2345 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the server record-size limit while awaiting renegotiation acceptance");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__,
                          "retain the active resumption state while awaiting renegotiation acceptance");

        tls_session server;
        server.get_tls_protection().set_tls_version(tls1_2);
        server.get_keyvalue().set(session_tls_version, tls1_2);
        tls_record_alert server_warning(&server, tls_alertlevel_t::warning, tls_alertdesc_t::no_renegotiation);
        binary_t alert_wire;
        ret = server_warning.write(from_server, alert_wire);
        _test_case.test(ret, __FUNCTION__, "serialize the peer's no_renegotiation warning");

        tls_record_alert client_warning(&client);
        size_t alert_pos = 0;
        ret = client_warning.read(from_server, alert_wire.data(), alert_wire.size(), alert_pos);
        _test_case.test(ret, __FUNCTION__, "receive the peer's no_renegotiation warning");
        _test_case.assert(alert_wire.size() == alert_pos, __FUNCTION__, "consume the no_renegotiation alert");
        _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), __FUNCTION__, "restore the established flow after the peer declines");
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        _test_case.assert(completed_status == (client.get_session_status() & completed_status), __FUNCTION__,
                          "restore completed-handshake status after the peer declines");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_client).get_status(), __FUNCTION__,
                          "restore the client handshake cursor after the peer declines");
        _test_case.assert(tls_handshake_type_t::finished == client.get_session_info(from_server).get_status(), __FUNCTION__,
                          "restore the server handshake cursor after the peer declines");
        _test_case.assert(91 == client.get_recordno(from_client), __FUNCTION__, "preserve the client record sequence after peer refusal");
        _test_case.assert(93 == client.get_recordno(from_server), __FUNCTION__, "preserve the server record sequence after peer refusal");
        _test_case.assert(binary_t(16, 0x11) == client.get_tls_protection().get_secrets().get(tls_secret_t::client_key), __FUNCTION__,
                          "preserve the active client traffic key after peer refusal");
        _test_case.assert(binary_t(16, 0x12) == client.get_tls_protection().get_secrets().get(tls_secret_t::server_key), __FUNCTION__,
                          "preserve the active server traffic key after peer refusal");
        _test_case.assert(prior_server_name == client.get_client_server_name(), __FUNCTION__, "preserve the active server name after peer refusal");
        _test_case.assert(prior_alpn == client.get_tls_protection().get_secrets().get(tls_secret_t::alpn), __FUNCTION__, "preserve the active ALPN after peer refusal");
        _test_case.assert(1234 == client.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "preserve the client record-size limit after peer refusal");
        _test_case.assert(2345 == client.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "preserve the server record-size limit after peer refusal");
        _test_case.assert(1 == client.get_keyvalue().get(session_tls12_ticket_resumed), __FUNCTION__, "preserve the active resumption state after peer refusal");
    }
}

static void test_tls12_cbc_mte_padding_validation() {
    // Scenario under test: TLS 1.2 CBC MtE validates the complete TLS padding field.
    // Action: authenticate a record whose first padding byte is wrong while its final 15 bytes look like valid EVP PKCS#7 padding.
    // Expected: perform MAC work, reject the malformed TLS padding, expose no plaintext, and queue one fatal bad_record_mac.
    _test_case.begin("TLS 1.2 CBC MtE validates all padding bytes");

    const binary_t content(16, 0x41);
    const binary_t iv(16, 0x42);
    const binary_t valid_padding(16, 0x0f);

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        binary_t wire;
        return_t ret = test_build_tls12_cbc_mte_record(reader, content, valid_padding, iv, wire);
        _test_case.test(ret, __FUNCTION__, "build a valid TLS CBC MtE record");

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.test(ret, __FUNCTION__, "accept a record with a complete valid TLS padding field");
        _test_case.assert(content == plaintext, __FUNCTION__, "recover the exact authenticated content");
    }

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        binary_t invalid_padding = valid_padding;
        invalid_padding[0] = 0x00;  // The final byte still says 16 padding bytes of value 0x0f.
        binary_t wire;
        return_t ret = test_build_tls12_cbc_mte_record(reader, content, invalid_padding, iv, wire);
        _test_case.test(ret, __FUNCTION__, "build an authenticated record with one malformed TLS padding byte");

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__,
                          "reject the malformed TLS padding even though EVP PKCS#7 would strip its final 15 bytes");
        _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext from a record with invalid padding");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::bad_record_mac);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue exactly one fatal bad_record_mac");
    }

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        // The final byte claims 15 padding bytes, but the preceding bytes retain 0x0f.
        // Build the MAC over 17 content bytes so only the TLS padding field is invalid.
        const binary_t content_with_terminal_mismatch(17, 0x41);
        binary_t invalid_terminal_padding(15, 0x0f);
        invalid_terminal_padding.back() = 0x0e;
        binary_t wire;
        return_t ret = test_build_tls12_cbc_mte_record(reader, content_with_terminal_mismatch, invalid_terminal_padding, iv, wire);
        _test_case.test(ret, __FUNCTION__, "build a record with a malformed final padding_length byte and valid MAC");

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject a final padding_length byte inconsistent with the preceding padding bytes");
        _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext when the final padding byte is malformed");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::bad_record_mac);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue one fatal bad_record_mac for a malformed final padding byte");
    }

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        const binary_t iv(16, 0x42);
        const binary_t partial_ciphertext(15, 0x73);
        binary_t wire{0x17, 0x03, 0x03, 0x00, 0x1f};  // 16-byte IV plus a non-block-aligned 15-byte ciphertext.
        wire.insert(wire.end(), iv.begin(), iv.end());
        wire.insert(wire.end(), partial_ciphertext.begin(), partial_ciphertext.end());

        binary_t plaintext;
        return_t ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject non-block-aligned CBC ciphertext as a structural error");
        _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext from a structurally invalid record");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::bad_record_mac);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "map a structural CBC failure to one fatal bad_record_mac");
    }

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        const binary_t short_raw(16, 0x33);  // One block is shorter than MAC plus the minimum TLS padding field.
        binary_t wire;
        return_t ret = test_build_tls12_cbc_mte_raw_record(reader, short_raw, iv, wire);
        _test_case.test(ret, __FUNCTION__, "build a block-aligned record shorter than the MAC and padding");

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject a record too short to contain a MAC and TLS padding");
        _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext from a short record");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::bad_record_mac);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue one fatal bad_record_mac for a short record");
    }

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        binary_t excessive_padding(16, 0xff);  // padding_length 255 exceeds the available plaintext.
        binary_t wire;
        return_t ret = test_build_tls12_cbc_mte_record(reader, content, excessive_padding, iv, wire);
        _test_case.test(ret, __FUNCTION__, "build a record with an excessive TLS padding length");

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject padding that extends before the available plaintext");
        _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext from an over-padded record");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::bad_record_mac);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue one fatal bad_record_mac for excessive padding");
    }

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        binary_t wire;
        return_t ret = test_build_tls12_cbc_mte_record(reader, content, valid_padding, iv, wire, true);
        _test_case.test(ret, __FUNCTION__, "build a record with valid padding and an invalid MAC");

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "reject a record with an invalid MAC");
        _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext from an unauthenticated record");
        size_t fatal_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::bad_record_mac);
        _test_case.assert(1 == fatal_count, __FUNCTION__, "queue one fatal bad_record_mac for an invalid MAC");
    }

    {
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);
        binary_t maximum_padding(256, 0xff);
        binary_t wire;
        return_t ret = test_build_tls12_cbc_mte_record(reader, content, maximum_padding, iv, wire);
        _test_case.test(ret, __FUNCTION__, "build a record with the maximum 256-byte TLS padding field");

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.test(ret, __FUNCTION__, "accept the maximum legal TLS padding field");
        _test_case.assert(content == plaintext, __FUNCTION__, "recover the exact content after extended TLS padding");
    }
}

static void test_tls12_cbc_mte_one_byte_padding_boundary() {
    // Scenario under test: TLS CBC MtE emits the required one-byte padding field without an extra PKCS#7 block.
    // Action: encrypt 15 bytes with AES-128-CBC and a 32-byte SHA-256 MAC, leaving exactly one padding byte.
    // Expected: wire fragment contains one IV block plus exactly three ciphertext blocks and round-trips with a peer.
    _test_case.begin("TLS 1.2 CBC MtE one-byte padding boundary");

    tls_session writer;
    tls_session reader;
    test_configure_tls12_cbc_mte_session(writer);
    test_configure_tls12_cbc_mte_session(reader);

    const binary_t content(15, 0x43);
    const binary_t additional{0x17, 0x03, 0x03, 0x00, 0x00};
    binary_t fragment;
    binary_t tag;
    return_t ret = writer.get_tls_protection().encrypt(&writer, from_client, content, fragment, additional, tag);
    _test_case.test(ret, __FUNCTION__, "encrypt a record whose TLS padding length is exactly one byte");
    _test_case.assert(tag.empty(), __FUNCTION__, "keep the MtE MAC nested inside the ciphertext");
    _test_case.assert(64 == fragment.size(), __FUNCTION__, "emit a 16-byte IV and exactly 48 bytes of CBC ciphertext");

    if (errorcode_t::success == ret) {
        const uint16 fragment_size = static_cast<uint16>(fragment.size());
        binary_t wire{0x17, 0x03, 0x03, static_cast<byte_t>(fragment_size >> 8), static_cast<byte_t>(fragment_size)};
        wire.insert(wire.end(), fragment.begin(), fragment.end());

        binary_t plaintext;
        ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
        _test_case.test(ret, __FUNCTION__, "decrypt the one-byte-padding boundary record");
        _test_case.assert(content == plaintext, __FUNCTION__, "preserve exact plaintext across the block boundary");
    }
}

static void test_tls13_aes_gcm_key_usage_boundaries(const char* function_name) {
    // Scenario under test: TLS 1.3 AES-GCM per-key record and plaintext-byte limits.
    // Action: exercise the AES-128-GCM record ceiling, AES-128-GCM byte ceiling, and AES-256-GCM record ceiling.
    // Expected: reserve the fatal-alert margin and reject application records beyond the configured usage boundary.
    constexpr uint64 aes_max_records = 23726566ULL;
    constexpr uint64 aes_max_plaintext = 388736063996ULL;
    const binary_t plaintext{'x', (byte_t)tls_content_type_t::application_data};
    {
        tls_session writer;
        tls_session reader;
        test_configure_tls13_inner_plaintext_session(writer);
        test_configure_tls13_inner_plaintext_session(reader);
        writer.set_recordno(from_client, aes_max_records - 3);
        reader.set_recordno(from_client, aes_max_records - 3);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.test(ret, function_name, "allow the final AES-GCM application record while reserving one alert slot");
        if (errorcode_t::success == ret) {
            uint64 writer_recordno = writer.get_recordno(from_client);
            _test_case.assert((aes_max_records - 2) == writer_recordno, function_name, "leave an alert record and one additional safety record unused");
            auto& writer_usage = writer.get_session_info(from_client).get_keyvalue();
            uint64 writer_usage_bytes = writer_usage.get(session_tls13_key_usage_bytes);
            _test_case.assert(plaintext.size() == writer_usage_bytes, function_name, "account the complete TLSInnerPlaintext bytes encrypted under the key");

            tls_records records;
            ret = records.read(&reader, from_client, wire);
            _test_case.test(ret, function_name, "receiver accepts a valid record at the sender's usage boundary");
            uint64 reader_recordno = reader.get_recordno(from_client);
            _test_case.assert((aes_max_records - 2) == reader_recordno, function_name, "receiver advances its sequence without enforcing sender usage limits");

            test_tls13_inner_plaintext_writer blocked(&writer);
            binary_t blocked_wire;
            ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
            _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), function_name, "do not emit a record beyond the AES-GCM usage limit");
            writer_recordno = writer.get_recordno(from_client);
            _test_case.assert((aes_max_records - 2) == writer_recordno, function_name, "do not advance the record number after limit rejection");

            test_tls13_inner_plaintext_writer blocked_again(&writer);
            binary_t blocked_again_wire;
            ret = blocked_again.write_inner_plaintext(from_client, plaintext, blocked_again_wire);
            _test_case.assert(errorcode_t::exceed == ret && blocked_again_wire.empty(), function_name, "keep the exhausted key from encrypting additional data");

            size_t fatal_count = test_count_fatal_alert(writer, from_client, tls_alertdesc_t::internal_error);
            _test_case.assert(1 == fatal_count, function_name, "queue one fatal internal_error when the key usage limit is reached");
            uint32 writer_status = writer.get_session_status();
            _test_case.assert((session_status_server_hello & writer_status) != 0, function_name, "preserve handshake state so the queued fatal alert can be sent");

            const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
            test_tls13_inner_plaintext_writer alert_record(&writer);
            binary_t alert_wire;
            ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
            _test_case.test(ret, function_name, "allow the reserved fatal Alert record while staying below the ceiling");
            writer_recordno = writer.get_recordno(from_client);
            _test_case.assert((aes_max_records - 1) == writer_recordno, function_name, "send the fatal Alert while remaining strictly below the record ceiling");
        }
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        auto& usage = writer.get_session_info(from_client).get_keyvalue();
        usage.set(session_tls13_key_usage_bytes, aes_max_plaintext - 6 - plaintext.size());

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.test(ret, function_name, "allow plaintext usage up to the reserved fatal-alert boundary");
        uint64 usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 6) == usage_bytes, function_name, "leave the fatal-alert reserve and a further safety margin");

        test_tls13_inner_plaintext_writer blocked(&writer);
        binary_t blocked_wire;
        ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
        _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), function_name, "reject the byte-limit crossing before encryption");
        usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 6) == usage_bytes, function_name, "do not account plaintext from a rejected encryption attempt");

        const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
        test_tls13_inner_plaintext_writer alert_record(&writer);
        binary_t alert_wire;
        ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
        _test_case.test(ret, function_name, "allow the fatal Alert to consume the reserved plaintext bytes");
        usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 3) == usage_bytes, function_name, "send the fatal Alert while remaining below the plaintext ceiling");
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_tls_protection().set_cipher_suite(0x1302);
        writer.set_recordno(from_client, aes_max_records - 2);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret && wire.empty(), function_name, "refuse AES-256-GCM encryption at its per-key record boundary");
    }
}

static void test_tls13_ccm_and_aes256_key_usage_boundaries(const char* function_name) {
    // Scenario under test: TLS 1.3 AES-CCM and AES-256-GCM per-key usage limits.
    // Action: exercise record-count and plaintext-byte ceilings for both AEAD families.
    // Expected: reject the first record or byte beyond each cipher suite's usage budget.
    constexpr uint64 aes_max_plaintext = 388736063996ULL;
    constexpr uint64 ccm_max_records = (1ULL << 21);
    constexpr uint64 ccm_max_plaintext = (1ULL << 35);
    const binary_t plaintext{'x', (byte_t)tls_content_type_t::application_data};
    {
        const uint16 ccm_suites[] = {0x1304, 0x1305};
        for (size_t i = 0; i < 2; ++i) {
            tls_session writer;
            test_configure_tls13_inner_plaintext_session(writer);
            writer.get_tls_protection().set_cipher_suite(ccm_suites[i]);
            writer.set_recordno(from_client, ccm_max_records - 2);

            test_tls13_inner_plaintext_writer record(&writer);
            binary_t wire;
            return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
            _test_case.assert(errorcode_t::exceed == ret && wire.empty(), function_name, "refuse AES-CCM encryption at its per-key record boundary");
        }
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_tls_protection().set_cipher_suite(0x1302);
        auto& usage = writer.get_session_info(from_client).get_keyvalue();
        usage.set(session_tls13_key_usage_bytes, aes_max_plaintext - 6 - plaintext.size());

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.test(ret, function_name, "allow AES-256-GCM plaintext usage up to its reserved-alert boundary");
        uint64 usage_bytes = usage.get(session_tls13_key_usage_bytes);
        _test_case.assert((aes_max_plaintext - 6) == usage_bytes, function_name, "apply the AES-256-GCM per-key plaintext-byte ceiling");

        test_tls13_inner_plaintext_writer blocked(&writer);
        binary_t blocked_wire;
        ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
        _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), function_name, "do not encrypt beyond the AES-256-GCM byte limit");
    }

    {
        const uint16 ccm_suites[] = {0x1304, 0x1305};
        for (size_t i = 0; i < 2; ++i) {
            tls_session writer;
            test_configure_tls13_inner_plaintext_session(writer);
            writer.get_tls_protection().set_cipher_suite(ccm_suites[i]);
            auto& usage = writer.get_session_info(from_client).get_keyvalue();
            usage.set(session_tls13_key_usage_bytes, ccm_max_plaintext - 6 - plaintext.size());

            test_tls13_inner_plaintext_writer record(&writer);
            binary_t wire;
            return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
            _test_case.test(ret, function_name, "allow AES-CCM plaintext usage up to its reserved-alert boundary");
            uint64 usage_bytes = usage.get(session_tls13_key_usage_bytes);
            _test_case.assert((ccm_max_plaintext - 6) == usage_bytes, function_name, "apply the AES-CCM per-key plaintext-byte ceiling");

            test_tls13_inner_plaintext_writer blocked(&writer);
            binary_t blocked_wire;
            ret = blocked.write_inner_plaintext(from_client, plaintext, blocked_wire);
            _test_case.assert(errorcode_t::exceed == ret && blocked_wire.empty(), function_name, "do not encrypt beyond the AES-CCM byte limit");
        }
    }
}

static void test_tls13_chacha_early_data_and_directional_usage_limits(const char* function_name) {
    // Scenario under test: TLS 1.3 ChaCha20, early-data, and directional key-usage limits.
    // Action: test sequence exhaustion, non-updatable 0-RTT exhaustion, and key-change counter resets.
    // Expected: reserve the fatal-alert margin, require closure for exhausted early-data keys, and reset only the changed direction.
    constexpr uint64 aes_max_records = 23726566ULL;
    const binary_t plaintext{'x', (byte_t)tls_content_type_t::application_data};
    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_tls_protection().set_cipher_suite(0x1303);
        writer.set_recordno(from_client, (~static_cast<uint64>(0)) - 2);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret && wire.empty(), function_name, "refuse application encryption before the 64-bit record sequence wraps");

        const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
        test_tls13_inner_plaintext_writer alert_record(&writer);
        binary_t alert_wire;
        ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
        _test_case.test(ret, function_name, "allow the reserved ChaCha20-Poly1305 Alert sequence without approaching wrap");
        uint64 writer_recordno = writer.get_recordno(from_client);
        _test_case.assert((~static_cast<uint64>(0)) - 1 == writer_recordno, function_name, "stop before the ChaCha20 sequence reaches its terminal value");
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        auto& protection = writer.get_tls_protection();
        protection.set_flow(tls_flow_t::zero_rtt);
        const binary_t key(16, 0x31);
        const binary_t iv(12, 0x42);
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, key);
        protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, iv);
        writer.reset_session_status();
        writer.update_session_status(session_status_client_hello);
        writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
        writer.get_session_info(from_client).begin_protection();
        writer.set_recordno(from_client, aes_max_records - 2);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        return_t ret = record.write_inner_plaintext(from_client, plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret && wire.empty(), function_name, "do not rely on KeyUpdate for non-updatable early data");

        const binary_t alert_plaintext{2, (byte_t)tls_alertdesc_t::internal_error, (byte_t)tls_content_type_t::alert};
        test_tls13_inner_plaintext_writer alert_record(&writer);
        binary_t alert_wire;
        ret = alert_record.write_inner_plaintext(from_client, alert_plaintext, alert_wire);
        _test_case.assert(errorcode_t::exceed == ret && alert_wire.empty(), function_name, "require transport closure when early-data key usage is exhausted");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        auto& client_usage = session.get_session_info(from_client).get_keyvalue();
        auto& server_usage = session.get_session_info(from_server).get_keyvalue();
        client_usage.set(session_tls13_key_usage_bytes, 99);
        server_usage.set(session_tls13_key_usage_bytes, 77);
        session.reset_recordno(from_client);
        uint64 reset_client_usage_bytes = client_usage.get(session_tls13_key_usage_bytes);
        uint64 unchanged_server_usage_bytes = server_usage.get(session_tls13_key_usage_bytes);
        _test_case.assert(0 == reset_client_usage_bytes, function_name, "reset byte accounting for the direction whose traffic key changed");
        _test_case.assert(77 == unchanged_server_usage_bytes, function_name, "preserve the opposite direction's independent key usage counter");
        session.reset_recordno(from_server);
        uint64 reset_server_usage_bytes = server_usage.get(session_tls13_key_usage_bytes);
        _test_case.assert(0 == reset_server_usage_bytes, function_name, "reset byte accounting when the opposite directional key changes");
    }
}

static void test_tls13_key_usage_limits() {
    // Scenario under test: TLS 1.3 per-key AEAD usage limits.
    // Action: check AES-GCM, AES-CCM, ChaCha20, early-data, and directional reset boundaries.
    // Expected: enforce record and plaintext-byte ceilings while preserving the fatal-alert reserve.
    _test_case.begin("TLS 1.3 per-key AEAD usage limits");

    test_tls13_aes_gcm_key_usage_boundaries(__FUNCTION__);
    test_tls13_ccm_and_aes256_key_usage_boundaries(__FUNCTION__);
    test_tls13_chacha_early_data_and_directional_usage_limits(__FUNCTION__);
}

static void test_tls13_inner_plaintext_padding_and_content_type() {
    // Scenario under test: TLS 1.3 TLSInnerPlaintext padding and content type.
    // Action: accept Application Data with multiple zero padding octets.
    // Expected: remove all padding and the inner content type.
    _test_case.begin("TLS 1.3 TLSInnerPlaintext padding and content type");

    {
        tls_session reader;
        tls_records records;
        const binary_t plaintext{'p', 'i', 'n', 'g', 0x00, 0x00, (byte_t)tls_content_type_t::application_data, 0x00, 0x00, 0x00};
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept Application Data with multiple zero padding octets");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            const binary_t expected{'p', 'i', 'n', 'g', 0x00, 0x00};
            _test_case.assert(expected == decoded->get_binary(), __FUNCTION__, "remove all padding and the inner content type");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        const binary_t plaintext{(byte_t)tls_content_type_t::application_data};
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept zero-length Application Data content");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "deliver empty Application Data content");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded empty Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        binary_t plaintext(16384, 0x41);
        plaintext.push_back((byte_t)tls_content_type_t::application_data);
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept maximum TLSInnerPlaintext application content at 2^14+1");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(16384 == decoded->get_binary().size(), __FUNCTION__, "deliver maximum application content");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded maximum Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        binary_t plaintext{(byte_t)tls_content_type_t::application_data};
        plaintext.insert(plaintext.end(), 16384, 0x00);
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept maximum TLSInnerPlaintext padding at 2^14+1");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(decoded->get_binary().empty(), __FUNCTION__, "strip maximum zero padding after empty content");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded maximum-padding Application Data record is available");
        }
    }

    {
        tls_session reader;
        tls_records records;
        const binary_t plaintext{(byte_t)tls_alertlevel_t::warning, (byte_t)tls_alertdesc_t::close_notify, (byte_t)tls_content_type_t::alert, 0x00, 0x00};
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept one Alert message followed by zero padding");
        _test_case.assert(0 != (reader.get_session_status() & session_status_client_close_notified), __FUNCTION__, "dispatch only the two-byte Alert content");
    }

    {
        tls_session handshake_writer;
        handshake_writer.get_tls_protection().set_tls_version(tls1_3);
        tls_handshake_certificate_request request(&handshake_writer);
        auto algorithms = new tls_extension_signature_algorithms(&request);
        algorithms->add(tls_sigscheme_t::rsa_pss_rsae_sha256);
        request.get_extensions().add(algorithms);

        binary_t handshake_message;
        return_t ret = request.write(from_server, handshake_message);
        _test_case.test(ret, __FUNCTION__, "construct a valid CertificateRequest Handshake message");
        if (errorcode_t::success != ret) {
            return;
        }

        binary_t plaintext = handshake_message;
        plaintext.push_back((byte_t)tls_content_type_t::handshake);
        plaintext.push_back(0x00);
        plaintext.push_back(0x00);

        tls_session reader;
        tls_records records;
        ret = test_read_tls13_inner_plaintext(plaintext, from_server, reader, records);
        _test_case.test(ret, __FUNCTION__, "accept a Handshake message followed by zero padding");
        if (errorcode_t::success == ret && records.size()) {
            auto decoded = (tls_record_application_data*)records.getat(0);
            _test_case.assert(1 == decoded->get_handshakes().size(), __FUNCTION__, "remove padding before Handshake parser dispatch");
        } else {
            _test_case.assert(false, __FUNCTION__, "decoded Handshake record is available");
        }
    }

    const auto reject = [](const char* label, const binary_t& plaintext, tls_alertdesc_t expected_alert = tls_alertdesc_t::unexpected_message) {
        tls_session reader;
        tls_records records;
        return_t ret = test_read_tls13_inner_plaintext(plaintext, from_client, reader, records);
        _test_case.assert(errorcode_t::unexpected == ret, __FUNCTION__, "%s: reject malformed TLSInnerPlaintext", label);
        uint64 recordno_after_read = reader.get_session_info(from_client).get_recordno();
        _test_case.assert(1 == recordno_after_read, __FUNCTION__, "%s: authenticate the record before rejecting its empty or malformed TLSInnerPlaintext", label);

        size_t fatal_alert_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        fatal_alert_count = test_collect_fatal_alerts(reader, from_client, fatal_alerts);
        _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{expected_alert}, __FUNCTION__, "%s: queue exactly one expected fatal alert",
                          label);
        _test_case.assert(0 == reader.get_session_status(), __FUNCTION__, "%s: reset session state", label);
    };

    reject("empty decrypted plaintext", binary_t());
    reject("all-zero decrypted plaintext", binary_t{0x00, 0x00, 0x00, 0x00});
    reject("unknown inner content type", binary_t{0x99}, tls_alertdesc_t::illegal_parameter);
    reject("protected ChangeCipherSpec content type", binary_t{0x14});
    reject("empty Alert content", binary_t{(byte_t)tls_content_type_t::alert});
    reject("truncated Alert content", binary_t{(byte_t)tls_alertlevel_t::warning, (byte_t)tls_content_type_t::alert});
    reject("coalesced Alert messages", binary_t{(byte_t)tls_alertlevel_t::warning, (byte_t)tls_alertdesc_t::close_notify, (byte_t)tls_alertlevel_t::warning,
                                                (byte_t)tls_alertdesc_t::close_notify, (byte_t)tls_content_type_t::alert});
    reject("empty Handshake content", binary_t{(byte_t)tls_content_type_t::handshake});
}

static void test_tls_record_size_limits() {
    // Action: Action: construct TLS records at and beyond the plaintext and ciphertext size ceilings.
    // Scenario under test: TLS record plaintext and ciphertext size limits.
    // Expected: allow TLS 1.3 plaintext header length at 2^14.
    _test_case.begin("TLS record plaintext and ciphertext size limits");

    // Inbound TLS 1.3: plaintext records are limited to 2^14; protected records to 2^14+256.
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls1_3, false, 16384, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.3 plaintext header length at 2^14");
        ret = test_read_tls_record_header_size(tls1_3, false, 16385, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.3 plaintext fragment above 2^14");
    }
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls1_3, true, 16640, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.3 ciphertext header length at 2^14+256");
        ret = test_read_tls_record_header_size(tls1_3, true, 16641, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.3 ciphertext fragment above 2^14+256");
        size_t fatal_alert_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::record_overflow);
        _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal record_overflow alert");
    }

    // Exercise the complete tls_records receive entry point. The oversized
    // TLSCiphertext length must be rejected from its header before body parsing.
    {
        tls_session session;
        tls_records records;
        return_t ret = test_read_tls_record_fragment_size(tls1_3, true, 16641, session, records);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject oversized TLS 1.3 ciphertext through tls_records::read");
        _test_case.assert(0 == records.size(), __FUNCTION__, "do not publish a record rejected by the receive path");

        size_t fatal_alert_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::record_overflow);
        _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal record_overflow alert through the receive path");
    }

    // Inbound TLS 1.2 retains its 2^14 plaintext and 2^14+2048 ciphertext limits.
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls1_2, false, 16384, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.2 plaintext header length at 2^14");
        ret = test_read_tls_record_header_size(tls1_2, false, 16385, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.2 plaintext fragment above 2^14");
    }
    {
        tls_session session;
        return_t ret = test_read_tls_record_header_size(tls1_2, true, 18432, session);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "allow TLS 1.2 ciphertext header length at 2^14+2048");
        ret = test_read_tls_record_header_size(tls1_2, true, 18433, session);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject TLS 1.2 ciphertext fragment above 2^14+2048");
    }

    // Exercise the normal do_write_header() path as well as the raw header helper.
    // A size-validation error must be returned to the caller, not silently discarded.
    return_t write_ret = test_write_tls_record_header_path(tls1_3, 16384);
    _test_case.assert(errorcode_t::success == write_ret, __FUNCTION__, "propagate TLS 1.3 plaintext boundary through record writer");
    write_ret = test_write_tls_record_header_path(tls1_3, 16385);
    _test_case.assert(errorcode_t::exceed == write_ret, __FUNCTION__, "propagate TLS 1.3 plaintext size rejection through record writer");
    write_ret = test_write_tls_record_header_path(tls1_2, 16384);
    _test_case.assert(errorcode_t::success == write_ret, __FUNCTION__, "propagate TLS 1.2 plaintext boundary through record writer");
    write_ret = test_write_tls_record_header_path(tls1_2, 16385);
    _test_case.assert(errorcode_t::exceed == write_ret, __FUNCTION__, "propagate TLS 1.2 plaintext size rejection through record writer");

    // Outbound record serialization uses the matching negotiated-version and protection-state limit.
    write_ret = test_write_tls_record_fragment_size(tls1_3, false, 16384);
    _test_case.assert(errorcode_t::success == write_ret, __FUNCTION__, "write TLS 1.3 plaintext fragment at 2^14");
    write_ret = test_write_tls_record_fragment_size(tls1_3, false, 16385);
    _test_case.assert(errorcode_t::exceed == write_ret, __FUNCTION__, "reject TLS 1.3 plaintext fragment above 2^14");
    write_ret = test_write_tls_record_fragment_size(tls1_3, true, 16640);
    _test_case.assert(errorcode_t::success == write_ret, __FUNCTION__, "write TLS 1.3 ciphertext fragment at 2^14+256");
    write_ret = test_write_tls_record_fragment_size(tls1_3, true, 16641);
    _test_case.assert(errorcode_t::exceed == write_ret, __FUNCTION__, "reject TLS 1.3 ciphertext fragment above 2^14+256");

    write_ret = test_write_tls_record_fragment_size(tls1_2, false, 16384);
    _test_case.assert(errorcode_t::success == write_ret, __FUNCTION__, "write TLS 1.2 plaintext fragment at 2^14");
    write_ret = test_write_tls_record_fragment_size(tls1_2, false, 16385);
    _test_case.assert(errorcode_t::exceed == write_ret, __FUNCTION__, "reject TLS 1.2 plaintext fragment above 2^14");
    write_ret = test_write_tls_record_fragment_size(tls1_2, true, 18432);
    _test_case.assert(errorcode_t::success == write_ret, __FUNCTION__, "write TLS 1.2 ciphertext fragment at 2^14+2048");
    write_ret = test_write_tls_record_fragment_size(tls1_2, true, 18433);
    _test_case.assert(errorcode_t::exceed == write_ret, __FUNCTION__, "reject TLS 1.2 ciphertext fragment above 2^14+2048");

    // DTLS 1.2 uses the same negotiated plaintext limit; oversized inbound records may be rejected with record_overflow.
    {
        tls_session session(session_type_t::dtls);
        session.get_tls_protection().set_tls_version(tls_version_t::dtls1_2);
        session.get_session_info(from_client).begin_protection();
        session.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        test_tls_record_size_probe record(&session);
        return_t ret = record.validate_plaintext_size(from_client, 64);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept DTLS 1.2 plaintext at negotiated receive limit");
        ret = record.validate_plaintext_size(from_client, 65);
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject DTLS 1.2 plaintext above negotiated receive limit");
        size_t overflow_alert_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::record_overflow);
        _test_case.assert(1 == overflow_alert_count, __FUNCTION__, "queue fatal record_overflow for oversized DTLS 1.2 plaintext");
    }

    // DTLS 1.3 carries TLSInnerPlaintext, including the inner content type, through dtls13_ciphertext.
    {
        class dtls13_size_probe : public dtls13_ciphertext {
           public:
            explicit dtls13_size_probe(tls_session* session) : dtls13_ciphertext(tls_content_type_t::application_data, session) {}
            return_t write_inner(tls_direction_t dir, const binary_t& plaintext, binary_t& record) { return do_write_header(dir, record, plaintext); }
        };
        tls_session session(session_type_t::dtls);
        session.get_tls_protection().set_tls_version(tls_version_t::dtls1_3);
        session.get_session_info(from_client).begin_protection();
        session.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        dtls13_size_probe record(&session);
        binary_t wire;
        return_t ret = record.write_inner(from_client, binary_t(65, 0x5a), wire);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject DTLS 1.3 TLSInnerPlaintext above peer receive limit before encryption");
        _test_case.assert(wire.empty(), __FUNCTION__, "emit no DTLS 1.3 bytes when record_size_limit is exceeded");
    }

    // TLS 1.2 has no record compression path in this implementation, so its encryption input is TLSPlaintext.
    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls1_2);
        binary_t plaintext(16385, 0x01);
        binary_t ciphertext;
        binary_t additional;
        binary_t tag;
        return_t ret = session.get_tls_protection().encrypt(&session, from_client, plaintext, ciphertext, additional, tag);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject TLS 1.2 plaintext above 2^14 before encryption");
    }

    // The encryption input is TLSInnerPlaintext in TLS 1.3, including type and padding.
    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        test_tls_record_size_probe record(&session);
        binary_t wire;
        binary_t inner_plaintext(16385, 0x01);
        return_t ret = record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "encrypt TLSInnerPlaintext at 2^14+1");
        inner_plaintext.push_back(0x01);
        wire.clear();
        ret = record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject TLSInnerPlaintext above 2^14+1");
    }
}

static void test_dtls_record_publisher_segment_boundary() {
    // Action: Action: publish DTLS records around the configured datagram segment boundary.
    // Scenario under test: DTLS record publisher segment boundary.
    // Expected: reject a record larger than the datagram segment target.
    _test_case.begin("DTLS record publisher segment boundary");

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        publisher.set_segment_size(1);

        tls_records records;
        records.add(tls_content_type_t::change_cipher_spec, &session);

        size_t callback_count = 0;
        return_t ret = records.write(&session, from_client, [&](tls_session*, binary_t&) { ++callback_count; });
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject a record larger than the datagram segment target");
        _test_case.assert(0 == callback_count, __FUNCTION__, "do not publish an empty or oversized datagram");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        publisher.set_segment_size(1);

        tls_records records;
        records.add(tls_content_type_t::change_cipher_spec, &session);

        size_t callback_count = 0;
        return_t ret = publisher.publish(records.getat(0), from_client, [&](tls_session*, binary_t&) { ++callback_count; });
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject an oversized record on the single-record callback path");
        _test_case.assert(0 == callback_count, __FUNCTION__, "do not publish an oversized single-record datagram");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        publisher.set_segment_size(14);  // DTLS 1.2 header (13) + ChangeCipherSpec (1)

        tls_records records;
        records.add(tls_content_type_t::change_cipher_spec, &session);

        size_t callback_count = 0;
        size_t datagram_size = 0;
        return_t ret = records.write(&session, from_client, [&](tls_session*, binary_t& bin) {
            ++callback_count;
            datagram_size = bin.size();
        });
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow a datagram exactly at the segment target");
        _test_case.assert(1 == callback_count && 14 == datagram_size, __FUNCTION__, "publish one exact-boundary DTLS datagram");
    }
}

static void test_dtls_record_publisher_pmtu_api() {
    // Action: Action: query PMTU and record-header expansion before and after protection.
    // Scenario under test: DTLS record publisher PMTU API.
    // Expected: report legacy DTLS record header expansion before protection.
    _test_case.begin("DTLS record publisher PMTU API");

    {
        tls_session session(session_type_t::dtls);
        auto& publisher = session.get_dtls_record_publisher();
        size_t expansion = 0;
        return_t ret = publisher.get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && sizeof(dtls_header) == expansion, __FUNCTION__, "report legacy DTLS record header expansion before protection");
        _test_case.assert(0 == publisher.get_pmtu_estimate(), __FUNCTION__, "report unknown PMTU estimate as zero");
        auto fragment_size = publisher.get_fragment_size();
        auto segment_size = publisher.get_max_size();
        publisher.set_pmtu_estimate(1500);
        _test_case.assert(1500 == publisher.get_pmtu_estimate(), __FUNCTION__, "expose the transport-provided PMTU estimate");
        _test_case.assert(fragment_size == publisher.get_fragment_size() && segment_size == publisher.get_max_size(), __FUNCTION__,
                          "do not change fragment or segment targets when PMTU estimate changes");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls1_2);
        protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && 37 == expansion, __FUNCTION__, "include DTLS 1.2 GCM explicit nonce, tag and record header");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls1_2);
        protection.set_cipher_suite(0xcca8);  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && 29 == expansion, __FUNCTION__, "include DTLS 1.2 ChaCha20-Poly1305 tag without an explicit nonce");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls1_3);
        protection.set_cipher_suite(0x1301);  // TLS_AES_128_GCM_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 120, expansion);
        _test_case.assert(errorcode_t::success == ret && 22 == expansion, __FUNCTION__, "include DTLS 1.3 inner content type, conservative unified header and tag");
    }
    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls1_3);
        protection.set_cipher_suite(0x1305);  // TLS_AES_128_CCM_8_SHA256
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 2, expansion);
        _test_case.assert(errorcode_t::success == ret && 19 == expansion, __FUNCTION__, "include DTLS 1.3 padding needed for a short CCM_8 ciphertext sample");
        ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 7, expansion);
        _test_case.assert(errorcode_t::success == ret && 14 == expansion, __FUNCTION__, "do not add DTLS 1.3 padding when the CCM_8 sample is exactly 16 bytes");
    }

    {
        tls_session session(session_type_t::dtls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_version_t::dtls1_2);
        protection.set_cipher_suite(0xc013);  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        session.get_session_info(from_client).begin_protection();

        size_t expansion = 0;
        return_t ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 32, expansion);
        _test_case.assert(errorcode_t::success == ret && 61 == expansion, __FUNCTION__, "calculate DTLS 1.2 CBC MAC-then-encrypt padding expansion");

        session.get_keyvalue().set(session_encrypt_then_mac, 1);
        ret = session.get_dtls_record_publisher().get_record_expansion(from_client, 32, expansion);
        _test_case.assert(errorcode_t::success == ret && 65 == expansion, __FUNCTION__, "calculate DTLS 1.2 CBC encrypt-then-MAC padding expansion");
    }
}

static void test_dtls13_plaintext_content_type_demux() {
    // Action: Action: create DTLS 1.3 plaintext records for each permitted content type and invalid types.
    // Scenario under test: DTLS 1.3 plaintext content-type demultiplexing.
    // Expected: allow plaintext alert, handshake, and ACK record builders.
    _test_case.begin("DTLS 1.3 plaintext content-type demultiplexing");

    const tls_content_type_t allowed[] = {
        tls_content_type_t::alert,
        tls_content_type_t::handshake,
        tls_content_type_t::ack,
    };
    tls_session session(session_type_t::dtls);
    session.get_tls_protection().set_tls_version(tls_version_t::dtls1_3);

    for (auto type : allowed) {
        tls_record_builder builder;
        auto record = builder.set(&session).set(type).build();
        _test_case.assert(nullptr != record, __FUNCTION__, "allow plaintext alert, handshake, and ACK record builders");
        if (record) {
            record->release();
        }
    }

    {
        tls_record_builder builder;
        auto record = builder.set(&session).set(static_cast<tls_content_type_t>(0x20)).build();
        _test_case.assert((nullptr != record) && (nullptr != dynamic_cast<dtls13_ciphertext*>(record)), __FUNCTION__,
                          "dispatch DTLS 1.3 unified-header values to the protected record parser");
        if (record) {
            record->release();
        }
    }

    {
        binary_t truncated_header{0x20};
        tls_records records;
        return_t ret = records.read(&session, from_server, truncated_header);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a truncated DTLS 1.3 unified header");
    }

    {
        tls_session legacy_session(session_type_t::dtls);
        legacy_session.get_tls_protection().set_tls_version(tls_version_t::dtls1_2);
        tls_record_builder builder;
        auto record = builder.set(&legacy_session).set(static_cast<tls_content_type_t>(0x20)).build();
        _test_case.assert((nullptr != record) && (nullptr == dynamic_cast<dtls13_ciphertext*>(record)), __FUNCTION__,
                          "do not dispatch reserved high-bit values to the DTLS 1.3 parser for DTLS 1.2");
        if (record) {
            record->release();
        }

        binary_t reserved_datagram{0x20, 0xfe, 0xfd,  // reserved unified-header range is not a DTLS 1.2 content type
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};
        tls_records records;
        return_t ret = records.read(&legacy_session, from_server, reserved_datagram);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject the DTLS 1.3 reserved unified-header range in DTLS 1.2");
    }

    // RFC 9147 §4.1: non-plaintext values must use the 001 unified-header prefix; RFC 9853 requires RRC to be protected.
    const uint8 forbidden[] = {
        static_cast<uint8>(tls_content_type_t::change_cipher_spec),
        static_cast<uint8>(tls_content_type_t::application_data),
        static_cast<uint8>(tls_content_type_t::heartbeat),
        static_cast<uint8>(tls_content_type_t::tls12_cid),
        static_cast<uint8>(tls_content_type_t::return_routability_check),
        0x1f,
        0x40,
        0xff,
    };
    for (auto type : forbidden) {
        binary_t datagram{
            type, 0xfe, 0xfc,                    // legacy record header: content type, version
            0x00, 0x00,                          // epoch
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // sequence number
            0x00, 0x01,                          // fragment length
            0x00                                 // one-byte body
        };
        tls_records records;
        return_t ret = records.read(&session, from_server, datagram);
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject plaintext content types other than alert, handshake, and ACK in DTLS 1.3");
    }
}

static void test_dtls13_minimum_ciphertext_sample() {
    // Action: Action: serialize short DTLS 1.3 ciphertext and inspect minimum sample padding.
    // Scenario under test: DTLS 1.3 minimum ciphertext sample and padding.
    // Expected: write a short DTLS 1.3 CCM_8 record with required padding.
    _test_case.begin("DTLS 1.3 minimum ciphertext sample and padding");

    class dtls13_padding_probe : public dtls13_ciphertext {
       public:
        explicit dtls13_padding_probe(tls_session* session) : dtls13_ciphertext(tls_content_type_t::alert, session) {}

        return_t write_inner(tls_direction_t dir, const binary_t& inner, binary_t& wire) { return do_write_header(dir, wire, inner); }

        return_t read_inner(tls_direction_t dir, const binary_t& wire, size_t start = 0) {
            size_t pos = start;
            return_t ret = do_read_header(dir, wire.data(), wire.size(), pos);
            if (errorcode_t::success == ret) {
                ret = do_read_body(dir, wire.data(), wire.size(), pos);
            }
            return ret;
        }
    };

    tls_session writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(writer);
    dtls13_padding_probe outgoing(&writer);

    binary_t inner;
    inner.push_back(static_cast<byte_t>(tls_alertlevel_t::fatal));
    inner.push_back(static_cast<byte_t>(tls_alertdesc_t::internal_error));
    inner.push_back(static_cast<byte_t>(tls_content_type_t::alert));

    binary_t wire;
    return_t ret = outgoing.write_inner(from_client, inner, wire);
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "write a short DTLS 1.3 CCM_8 record with required padding");
    _test_case.assert(20 == wire.size() && 16 == test_read_u16(wire, 2), __FUNCTION__, "pad ciphertext plus tag to a 16-byte header-protection sample");

    tls_session limited_writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(limited_writer);
    limited_writer.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 3);
    dtls13_padding_probe limited_outgoing(&limited_writer);
    binary_t limited_wire;
    ret = limited_outgoing.write_inner(from_client, inner, limited_wire);
    _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "apply the peer record_size_limit after required DTLS 1.3 padding");

    for (size_t content_size = 0; content_size < 8; ++content_size) {
        tls_session loop_writer(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(loop_writer);
        dtls13_padding_probe loop_outgoing(&loop_writer);
        binary_t loop_inner(content_size + 1, 0x55);
        loop_inner.back() = static_cast<byte_t>(tls_content_type_t::alert);
        binary_t loop_wire;
        ret = loop_outgoing.write_inner(from_client, loop_inner, loop_wire);
        _test_case.assert(errorcode_t::success == ret && 16 == test_read_u16(loop_wire, 2), __FUNCTION__,
                          "pad every CCM_8 inner plaintext that would produce a sample shorter than 16 bytes");
    }

    tls_session exact_writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(exact_writer);
    dtls13_padding_probe exact_outgoing(&exact_writer);
    binary_t exact_inner(8, 0x55);
    exact_inner.back() = static_cast<byte_t>(tls_content_type_t::alert);
    binary_t exact_wire;
    ret = exact_outgoing.write_inner(from_client, exact_inner, exact_wire);
    _test_case.assert(errorcode_t::success == ret && 20 == exact_wire.size() && 16 == test_read_u16(exact_wire, 2), __FUNCTION__,
                      "leave an exact 16-byte ciphertext sample unpadded");

    tls_session above_writer(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(above_writer);
    dtls13_padding_probe above_outgoing(&above_writer);
    binary_t above_inner(9, 0x55);
    above_inner.back() = static_cast<byte_t>(tls_content_type_t::alert);
    binary_t above_wire;
    ret = above_outgoing.write_inner(from_client, above_inner, above_wire);
    _test_case.assert(errorcode_t::success == ret && 21 == above_wire.size() && 17 == test_read_u16(above_wire, 2), __FUNCTION__,
                      "leave a ciphertext sample larger than 16 bytes unpadded");

    binary_t with_trailing{0xa1, 0xb2, 0xc3};
    binary_append(with_trailing, wire);
    binary_append(with_trailing, binary_t(16, 0x5a));

    tls_session reader(session_type_t::dtls);
    test_configure_dtls13_ccm8_session(reader);
    dtls13_padding_probe incoming(&reader);
    ret = incoming.read_inner(from_client, with_trailing, 3);
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "decrypt only the current record when trailing datagram bytes exist");

    size_t alert_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::internal_error);
    _test_case.assert(1 == alert_count, __FUNCTION__, "strip zero padding and recover the inner alert content type");

    binary_t invalid_fixed_bits = wire;
    invalid_fixed_bits[0] = 0xff;
    ret = incoming.read_inner(from_client, invalid_fixed_bits);
    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject a DTLS 1.3 unified header whose leading three bits are not 001");

    binary_t truncated_record = wire;
    truncated_record[2] = 0;
    truncated_record[3] = 17;
    ret = incoming.read_inner(from_client, truncated_record);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a declared DTLS 1.3 ciphertext length that extends beyond the datagram");

    // Heartbeat and RRC are optional and are not negotiated by this test profile.
    const uint8 unsupported_inner_types[] = {
        static_cast<uint8>(tls_content_type_t::change_cipher_spec),
        static_cast<uint8>(tls_content_type_t::heartbeat),
        static_cast<uint8>(tls_content_type_t::tls12_cid),
        static_cast<uint8>(tls_content_type_t::return_routability_check),
    };
    for (auto type : unsupported_inner_types) {
        tls_session invalid_writer(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(invalid_writer);
        dtls13_padding_probe invalid_outgoing(&invalid_writer);
        binary_t invalid_inner{type};
        binary_t invalid_wire;
        ret = invalid_outgoing.write_inner(from_client, invalid_inner, invalid_wire);

        tls_session invalid_reader(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(invalid_reader);
        dtls13_padding_probe invalid_incoming(&invalid_reader);
        if (errorcode_t::success == ret) {
            ret = invalid_incoming.read_inner(from_client, invalid_wire);
        }
        _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject unsupported authenticated DTLS 1.3 inner content types");
    }

    for (size_t sample_size = 0; sample_size < 16; ++sample_size) {
        binary_t malformed{0xa1, 0xb2, 0xc3};
        binary_append(malformed, binary_t(wire.begin(), wire.begin() + 4));
        malformed.resize(3 + 4 + sample_size, 0x5a);
        malformed[5] = static_cast<byte_t>((sample_size >> 8) & 0xff);
        malformed[6] = static_cast<byte_t>(sample_size & 0xff);
        binary_append(malformed, binary_t(16, 0x5a));

        tls_session short_reader(session_type_t::dtls);
        test_configure_dtls13_ccm8_session(short_reader);
        dtls13_padding_probe short_incoming(&short_reader);
        ret = short_incoming.read_inner(from_client, malformed, 3);
        _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject every ciphertext sample shorter than 16 bytes even when trailing datagram bytes exist");
    }
}

static void test_tls_record_size_limit_extension() {
    // Scenario under test: TLS record_size_limit extension negotiation and enforcement.
    // Action: serialize record_size_limit in ClientHello.
    // Expected: encode extension type and uint16 limit.
    _test_case.begin("TLS record_size_limit extension negotiation and enforcement");

    {
        tls_session session;
        tls_handshake_client_hello handshake(&session);
        tls_extension_record_size_limit extension(&handshake);
        extension.set_record_size_limit(1024);
        binary_t wire;
        return_t ret = extension.write(from_client, wire);
        _test_case.test(ret, __FUNCTION__, "serialize record_size_limit in ClientHello");
        _test_case.assert(binary_t({0x00, 0x1c, 0x00, 0x02, 0x04, 0x00}) == wire, __FUNCTION__, "encode extension type and uint16 limit");
        _test_case.assert(1024 == session.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the local receive limit for the advertised direction");

        tls_session peer_session;
        tls_handshake_client_hello peer_handshake(&peer_session);
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&peer_handshake, from_client, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "parse record_size_limit extension");
        if (parsed) {
            auto typed = (tls_extension_record_size_limit*)parsed;
            _test_case.assert(1024 == typed->get_record_size_limit(), __FUNCTION__, "recover advertised record size limit");
            parsed->release();
        }
        _test_case.assert(1024 == peer_session.get_session_info(from_client).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain the peer receive limit for the advertised direction");
    }

    {
        tls_session session;
        tls_handshake_client_hello handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x00, 0x3f};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_client, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject record_size_limit below 64");
        size_t illegal_parameter_count = test_count_fatal_alert(session, from_client, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue fatal illegal_parameter for limit below 64");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        tls_handshake_encrypted_extensions handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject unsolicited server record_size_limit response");
        size_t unsupported_extension_count = test_count_fatal_alert(session, from_server, tls_alertdesc_t::unsupported_extension);
        _test_case.assert(1 == unsupported_extension_count, __FUNCTION__, "queue fatal unsupported_extension when client did not offer record_size_limit");
    }

    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls1_2);
        tls_handshake_encrypted_extensions handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr == parsed, __FUNCTION__, "reject record_size_limit in TLS 1.2 EncryptedExtensions context");
        size_t illegal_parameter_count = test_count_fatal_alert(session, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "queue fatal illegal_parameter for invalid EncryptedExtensions context");
    }

    {
        tls_session session;
        session.get_tls_protection().set_tls_version(tls1_2);
        session.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1024);
        tls_handshake_server_hello handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "accept TLS 1.2 ServerHello response after client offer");
        if (parsed) {
            parsed->release();
        }
        _test_case.assert(1024 == session.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain server receive limit from TLS 1.2 ServerHello");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        session.get_session_info(from_client).get_keyvalue().set(session_record_size_limit, 1024);
        tls_handshake_encrypted_extensions handshake(&session);
        binary_t wire{0x00, 0x1c, 0x00, 0x02, 0x04, 0x00};
        size_t pos = 0;
        tls_extension* parsed = tls_extension::read(&handshake, from_server, wire.data(), wire.size(), pos);
        _test_case.assert(nullptr != parsed, __FUNCTION__, "accept EncryptedExtensions record_size_limit after client offer");
        if (parsed) {
            parsed->release();
        }
        _test_case.assert(1024 == session.get_session_info(from_server).get_keyvalue().get(session_record_size_limit), __FUNCTION__,
                          "retain server receive limit from EncryptedExtensions");
    }

    {
        tls_session session;
        test_configure_tls13_inner_plaintext_session(session);
        tls_handshake_encrypted_extensions handshake(&session);
        tls_extension_record_size_limit extension(&handshake);
        extension.set_record_size_limit(1024);
        binary_t wire;
        return_t ret = extension.write(from_server, wire);
        _test_case.assert(errorcode_t::invalid_parameter == ret, __FUNCTION__, "do not emit unsolicited server record_size_limit response");
    }

    {
        tls_session writer;
        test_configure_tls13_inner_plaintext_session(writer);
        writer.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        binary_t boundary_plaintext(64, 0x01);
        return_t ret = record.write_inner_plaintext(from_client, boundary_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "allow outbound TLSInnerPlaintext at negotiated receive limit");
        wire.clear();
        binary_t inner_plaintext(65, 0x01);
        ret = record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::exceed == ret, __FUNCTION__, "reject outbound TLSInnerPlaintext above peer receive limit");
    }

    {
        tls_session writer;
        tls_session reader;
        test_configure_tls13_inner_plaintext_session(writer);
        test_configure_tls13_inner_plaintext_session(reader);
        reader.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);

        test_tls13_inner_plaintext_writer record(&writer);
        binary_t wire;
        binary_t boundary_plaintext(64, 0x5a);
        boundary_plaintext.back() = (byte_t)tls_content_type_t::application_data;
        return_t ret = record.write_inner_plaintext(from_client, boundary_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "construct inbound TLSInnerPlaintext at local receive limit");
        tls_records boundary_records;
        if (errorcode_t::success == ret) {
            ret = boundary_records.read(&reader, from_client, wire);
        }
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept inbound TLSInnerPlaintext at local receive limit");

        tls_session oversized_writer;
        tls_session oversized_reader;
        test_configure_tls13_inner_plaintext_session(oversized_writer);
        test_configure_tls13_inner_plaintext_session(oversized_reader);
        oversized_reader.get_session_info(from_server).get_keyvalue().set(session_record_size_limit, 64);
        test_tls13_inner_plaintext_writer oversized_record(&oversized_writer);
        wire.clear();
        binary_t inner_plaintext(65, 0x01);
        ret = oversized_record.write_inner_plaintext(from_client, inner_plaintext, wire);
        _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "construct peer record above local receive limit");

        tls_records records;
        if (errorcode_t::success == ret) {
            ret = records.read(&oversized_reader, from_client, wire);
        }
        _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject inbound TLSInnerPlaintext above local receive limit");
        size_t record_overflow_count = test_count_fatal_alert(oversized_reader, from_client, tls_alertdesc_t::record_overflow);
        _test_case.assert(1 == record_overflow_count, __FUNCTION__, "queue fatal record_overflow for inbound negotiated-limit violation");
    }
}

static void test_tls13_rejects_truncated_aead_record_before_tag_extraction() {
    // Action: Action: feed protected TLS 1.3 records shorter than the AEAD authentication tag.
    // Scenario under test: TLS 1.3 rejects truncated AEAD records before extracting the tag.
    // Expected: return bad_data when the record is shorter than its AEAD tag.
    _test_case.begin("TLS 1.3 rejects truncated AEAD records before extracting the tag");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::one_rtt);
    protection.get_secrets().assign(tls_secret_t::handshake_client_key, binary_t(16, 0x41));
    protection.get_secrets().assign(tls_secret_t::handshake_client_iv, binary_t(12, 0x42));

    // The TLS header declares five body bytes; AES-GCM needs at least a
    // complete 16-byte authentication tag before decryption can be attempted.
    const binary_t truncated_record = {0x17, 0x03, 0x03, 0x00, 0x05, 0x70, 0x69, 0x6e, 0x67, 0x17};
    binary_t plaintext;
    return_t ret = protection.decrypt_aead(&session, from_client, truncated_record.data(), truncated_record.size(), 0, plaintext, protection_space_t::tls,
                                           decrypt_alert_policy_t::suppress);

    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "return bad_data when the record is shorter than its AEAD tag");
    _test_case.assert(plaintext.empty(), __FUNCTION__, "do not produce plaintext from a truncated record");
    uint64 recordno_after_truncated_record = session.get_session_info(from_client).get_recordno();
    _test_case.assert(0 == recordno_after_truncated_record, __FUNCTION__, "do not consume a record number when tag extraction is impossible");
    size_t fatal_alert_count = test_count_fatal_alerts(session, from_client);
    _test_case.assert(0 == fatal_alert_count, __FUNCTION__, "do not report an authentication failure before attempting AEAD");

    // An all-zero tag is not an authenticated empty TLSInnerPlaintext. The
    // record-layer integration test covers a valid tag over an empty plaintext;
    // this low-level trial-decrypt case remains an authentication failure.
    // Keep one encrypted byte so this case exercises an ordinary failed
    // AEAD authentication, independently of the empty-plaintext edge case.
    binary_t invalid_tag_record = {0x17, 0x03, 0x03, 0x00, 0x11, 0x70};
    invalid_tag_record.insert(invalid_tag_record.end(), 16, 0);
    ret = protection.decrypt_aead(&session, from_client, invalid_tag_record.data(), invalid_tag_record.size(), 0, plaintext, protection_space_t::tls,
                                  decrypt_alert_policy_t::suppress);
    _test_case.assert(errorcode_t::verification_failure == ret, __FUNCTION__, "propagate the AEAD authentication failure for an invalid TLS 1.3 tag");
    _test_case.assert(plaintext.empty(), __FUNCTION__, "do not expose plaintext when trial authentication fails");

    // The overload that receives AAD separately must validate the trailing tag
    // before extracting it from the record buffer.
    binary_t aad = {0x17, 0x03, 0x03, 0x00, 0x05};
    auto recordno_before_truncated_aad = session.get_session_info(from_client).get_recordno();
    ret = protection.decrypt(&session, from_client, truncated_record.data(), truncated_record.size(), 0, plaintext, aad);
    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject a record too short for separately supplied AAD and tag");
    uint64 recordno_after_truncated_aad = session.get_session_info(from_client).get_recordno();
    _test_case.assert(recordno_before_truncated_aad == recordno_after_truncated_aad, __FUNCTION__,
                      "do not consume a record number when separately supplied AAD leaves no room for the tag");

    // The explicit-AAD/tag overload must reject an inverted range before
    // forming stream + pos or computing size - pos.
    binary_t tag(16, 0);
    ret = protection.decrypt(&session, from_client, truncated_record.data(), 0, 1, plaintext, aad, tag);
    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject size smaller than pos in the explicit-tag overload");
}

static void test_tls12_rejects_truncated_aead_explicit_nonce() {
    // Action: Action: feed protected TLS 1.2 records shorter than the explicit nonce field.
    // Scenario under test: TLS 1.2 rejects truncated AEAD explicit nonces before reading them.
    // Expected: reject ciphertext shorter than the TLS 1.2 explicit nonce.
    _test_case.begin("TLS 1.2 rejects truncated AEAD explicit nonces before reading them");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_2);
    protection.set_cipher_suite(0xc02f);  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (supported)

    // TLS 1.2 AES-GCM carries an 8-byte explicit nonce before the encrypted
    // fragment. The AEAD tag is supplied separately by this overload.
    binary_t truncated_ciphertext(7, 0x5a);
    binary_t aad(13, 0);
    binary_t tag(16, 0);
    binary_t plaintext;
    return_t ret = protection.decrypt(&session, from_client, truncated_ciphertext.data(), truncated_ciphertext.size(), 0, plaintext, aad, tag);

    _test_case.assert(errorcode_t::bad_data == ret, __FUNCTION__, "reject ciphertext shorter than the TLS 1.2 explicit nonce");
    _test_case.assert(plaintext.empty(), __FUNCTION__, "do not produce plaintext from a truncated explicit nonce");
    uint64 recordno_after_truncated_nonce = session.get_session_info(from_client).get_recordno();
    _test_case.assert(0 == recordno_after_truncated_nonce, __FUNCTION__, "do not consume a record number when the explicit nonce is truncated");
}

static void test_tls13_early_data_limit_excludes_padding() {
    // Action: Action: compare padded TLSInnerPlaintext records with their application-data byte counts.
    // Scenario under test: the NewSessionTicket early-data limit counts
    // Application Data plaintext, excluding TLSInnerPlaintext type and padding.
    // Expected: padded records consume only their application content bytes.
    _test_case.begin("TLS 1.3 early-data limit excludes TLSInnerPlaintext padding");

    tls_session writer;
    tls_session reader;
    writer.set_type(session_type_t::tls);
    reader.set_type(session_type_t::tls);

    const binary_t key(16, 0x31);
    const binary_t iv(12, 0x42);
    auto& writer_protection = writer.get_tls_protection();
    writer_protection.set_tls_version(tls1_3);
    writer_protection.set_cipher_suite(0x1301);
    writer_protection.set_flow(tls_flow_t::zero_rtt);
    writer_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, key);
    writer_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, iv);
    // A client 0-RTT record is sent before ServerHello and uses the
    // client early traffic secret. Keep the global and client-direction
    // handshake state at ClientHello so key selection matches c_e_traffic.
    writer.update_session_status(session_status_client_hello);
    writer.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    writer.get_session_info(from_client).begin_protection();

    auto& reader_protection = reader.get_tls_protection();
    reader_protection.set_tls_version(tls1_3);
    reader_protection.set_cipher_suite(0x1301);
    reader_protection.set_flow(tls_flow_t::zero_rtt);
    reader_protection.get_secrets().assign(tls_secret_t::c_e_traffic_key, key);
    reader_protection.get_secrets().assign(tls_secret_t::c_e_traffic_iv, iv);
    reader.update_session_status(session_status_client_hello);
    reader.get_session_info(from_client).set_status(tls_handshake_type_t::client_hello);
    reader.get_session_info(from_client).begin_protection();

    auto& early_state = reader.get_session_info(from_server).get_keyvalue();
    early_state.set(session_early_data_offered, 1);
    early_state.set(session_early_data_accepted, 1);
    early_state.set(session_early_data_limit, 4);
    reader.get_keyvalue().set(session_server_psk_selected_identity, 0);

    test_tls13_inner_plaintext_writer record(&writer);
    const binary_t padded_plaintext{'p', 'i', 'n', 'g', (byte_t)tls_content_type_t::application_data, 0x00, 0x00, 0x00};
    binary_t wire;
    return_t ret = record.write_inner_plaintext(from_client, padded_plaintext, wire);
    _test_case.test(ret, __FUNCTION__, "construct an authenticated 0-RTT record with three padding octets");

    tls_records records;
    if (errorcode_t::success == ret) {
        ret = records.read(&reader, from_client, wire);
    }
    _test_case.test(ret, __FUNCTION__, "accept four bytes of early data with TLSInnerPlaintext padding");
    _test_case.assert(4 == early_state.get(session_early_data_received), __FUNCTION__, "count only Application Data plaintext, excluding content type and padding");
    if (errorcode_t::success == ret && records.size()) {
        auto decoded = static_cast<tls_record_application_data*>(records.getat(0));
        const binary_t expected{'p', 'i', 'n', 'g'};
        _test_case.assert(expected == decoded->get_binary(), __FUNCTION__, "deliver only the four application bytes");
    } else {
        _test_case.assert(false, __FUNCTION__, "deliver the authenticated padded early-data record");
    }

    const binary_t over_limit_plaintext{'x', (byte_t)tls_content_type_t::application_data, 0x00, 0x00};
    wire.clear();
    ret = record.write_inner_plaintext(from_client, over_limit_plaintext, wire);
    _test_case.test(ret, __FUNCTION__, "construct a subsequent early-data record beyond the ticket allowance");
    if (errorcode_t::success == ret) {
        ret = records.read(&reader, from_client, wire);
    }
    _test_case.assert(errorcode_t::overflow == ret, __FUNCTION__, "reject the first application byte beyond the cumulative ticket limit");
    _test_case.assert(4 == early_state.get(session_early_data_received), __FUNCTION__, "do not count application bytes from a rejected over-limit record");
    size_t fatal_alert_count = test_count_fatal_alert(reader, from_client, tls_alertdesc_t::unexpected_message);
    _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue one fatal unexpected_message for the ticket-limit violation");
}

static void test_tls12_cbc_mte_timing_distribution() {
    // Optional diagnostic only. Set HOTPLACE_TLS_MTE_TIMING to a sample count
    // (for example 5000) to compare equal-length valid/invalid padding pairs.
    const char* timing_option = std::getenv("HOTPLACE_TLS_MTE_TIMING");
    if ((nullptr == timing_option) || (0 == timing_option[0])) {
        return;
    }

    unsigned long requested_samples = std::strtoul(timing_option, nullptr, 10);
    if (0 == requested_samples) {
        requested_samples = 5000;
    }
    const size_t sample_count = static_cast<size_t>(std::min<unsigned long>(20000, std::max<unsigned long>(1000, requested_samples)));

    struct timing_case {
        size_t content_size;
        size_t padding_size;
        const char* label;
    };
    const timing_case cases[] = {
        {14, 2, "padding-2"},
        {16, 16, "padding-16"},
        {1, 31, "padding-31"},
        {16, 256, "padding-256"},
    };
    typedef std::chrono::nanoseconds::rep timing_value_t;

    _test_case.begin("TLS 1.2 CBC MtE optional timing distribution diagnostic");

    const binary_t aad{0, 0, 0, 0, 0, 0, 0, 0, 0x17, 0x03, 0x03};
    const binary_t iv(16, 0x42);
    for (const auto& item : cases) {
        tls_session fixture;
        test_configure_tls12_cbc_mte_session(fixture);
        const binary_t content(item.content_size, 0x41);
        const binary_t valid_padding(item.padding_size, static_cast<byte_t>(item.padding_size - 1));
        binary_t invalid_padding = valid_padding;
        invalid_padding[0] ^= 0x01;  // Keep the final padding_length byte unchanged.

        binary_t valid_wire;
        binary_t invalid_wire;
        return_t ret = test_build_tls12_cbc_mte_record(fixture, content, valid_padding, iv, valid_wire);
        if (errorcode_t::success == ret) {
            ret = test_build_tls12_cbc_mte_record(fixture, content, invalid_padding, iv, invalid_wire);
        }
        _test_case.test(ret, __FUNCTION__, "construct equal-length valid and malformed-padding records");
        if (errorcode_t::success != ret) {
            continue;
        }

        if ((valid_wire.size() != invalid_wire.size()) || (valid_wire.size() <= 21)) {
            _test_case.assert(false, __FUNCTION__, "keep both timing inputs at the same fixed ciphertext length");
            continue;
        }

        const binary_t enckey = fixture.get_tls_protection().get_secrets().get(tls_secret_t::client_key);
        const binary_t mackey = fixture.get_tls_protection().get_secrets().get(tls_secret_t::client_mac_key);
        const binary_t record_iv(valid_wire.begin() + 5, valid_wire.begin() + 21);
        const binary_t valid_ciphertext(valid_wire.begin() + 21, valid_wire.end());
        const binary_t invalid_ciphertext(invalid_wire.begin() + 21, invalid_wire.end());

        crypto_cbc_hmac cbc;
        cbc.set_enc(crypt_algorithm_t::aes128).set_mac(hash_algorithm_t::sha2_256).set_flag(tls_mac_then_encrypt);

        bool valid_results = true;
        bool invalid_results = true;
        auto run_once = [&](const binary_t& ciphertext, binary_t& plaintext) -> return_t { return cbc.decrypt(enckey, mackey, record_iv, aad, ciphertext, plaintext); };

        // Warm both paths before collecting samples.
        for (size_t i = 0; i < 128; ++i) {
            binary_t plaintext;
            if ((errorcode_t::success != run_once(valid_ciphertext, plaintext)) || (content != plaintext)) {
                valid_results = false;
            }
            plaintext.clear();
            if ((errorcode_t::verification_failure != run_once(invalid_ciphertext, plaintext)) || (false == plaintext.empty())) {
                invalid_results = false;
            }
        }

        std::vector<timing_value_t> valid_samples;
        std::vector<timing_value_t> invalid_samples;
        valid_samples.reserve(sample_count);
        invalid_samples.reserve(sample_count);

        auto measure = [&](const binary_t& ciphertext, return_t expected, std::vector<timing_value_t>& samples, bool& result_ok) -> void {
            binary_t plaintext;
            const auto start = std::chrono::steady_clock::now();
            return_t sample_ret = run_once(ciphertext, plaintext);
            const auto finish = std::chrono::steady_clock::now();
            samples.emplace_back(std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start).count());
            if (expected != sample_ret) {
                result_ok = false;
            }
            if ((errorcode_t::success == expected) && (content != plaintext)) {
                result_ok = false;
            }
            if ((errorcode_t::success != expected) && (false == plaintext.empty())) {
                result_ok = false;
            }
        };

        // Alternate order to reduce systematic drift between the two populations.
        for (size_t i = 0; i < sample_count; ++i) {
            if (0 == (i & 1)) {
                measure(valid_ciphertext, errorcode_t::success, valid_samples, valid_results);
                measure(invalid_ciphertext, errorcode_t::verification_failure, invalid_samples, invalid_results);
            } else {
                measure(invalid_ciphertext, errorcode_t::verification_failure, invalid_samples, invalid_results);
                measure(valid_ciphertext, errorcode_t::success, valid_samples, valid_results);
            }
        }

        std::sort(valid_samples.begin(), valid_samples.end());
        std::sort(invalid_samples.begin(), invalid_samples.end());
        const size_t median_index = sample_count / 2;
        const size_t p95_index = std::min(sample_count - 1, (sample_count * 95) / 100);
        long double valid_total = 0;
        long double invalid_total = 0;
        for (size_t i = 0; i < sample_count; ++i) {
            valid_total += valid_samples[i];
            invalid_total += invalid_samples[i];
        }
        const double valid_median = static_cast<double>(valid_samples[median_index]);
        const double invalid_median = static_cast<double>(invalid_samples[median_index]);
        const double median_ratio = (0.0 == valid_median) ? 0.0 : (invalid_median / valid_median);

        const double valid_mean = static_cast<double>(valid_total / sample_count);
        const double invalid_mean = static_cast<double>(invalid_total / sample_count);
        std::printf("TLS-MTE-TIMING case=%s samples=%lu valid_ns median=%lld p95=%lld mean=%.1f invalid_ns median=%lld p95=%lld mean=%.1f median_ratio=%.3f\n",
                    item.label, static_cast<unsigned long>(sample_count), static_cast<long long>(valid_samples[median_index]),
                    static_cast<long long>(valid_samples[p95_index]), valid_mean, static_cast<long long>(invalid_samples[median_index]),
                    static_cast<long long>(invalid_samples[p95_index]), invalid_mean, median_ratio);
        _test_case.assert(valid_results, __FUNCTION__, "valid-padding samples remain accepted with exact plaintext");
        _test_case.assert(invalid_results, __FUNCTION__, "invalid-padding samples remain rejected without plaintext");
    }

    // Compare the complete TLS protection wrapper while keeping both outcomes on
    // the same failure/alert path: malformed padding with a valid MAC versus
    // valid padding with an invalid MAC.
    {
        _test_case.begin("TLS 1.2 CBC MtE wrapper timing distribution diagnostic");
        tls_session reader;
        test_configure_tls12_cbc_mte_session(reader);

        const binary_t content(16, 0x41);
        const binary_t iv(16, 0x42);
        const binary_t valid_padding(16, 0x0f);
        binary_t invalid_padding = valid_padding;
        invalid_padding[0] ^= 0x01;

        bool wrapper_results = true;
        auto prepare_wire = [&](uint64 record_no, bool malformed_padding, bool corrupt_mac, binary_t& wire) -> return_t {
            const binary_t& padding = malformed_padding ? invalid_padding : valid_padding;
            return test_build_tls12_cbc_mte_record(reader, content, padding, iv, wire, corrupt_mac, record_no);
        };

        auto run_once = [&](const binary_t& wire, std::vector<timing_value_t>* samples) -> void {
            binary_t plaintext;
            const auto start = std::chrono::steady_clock::now();
            return_t sample_ret = reader.get_tls_protection().decrypt(&reader, from_client, wire.data(), wire.size(), 0, plaintext);
            const auto finish = std::chrono::steady_clock::now();
            if (nullptr != samples) {
                samples->emplace_back(std::chrono::duration_cast<std::chrono::nanoseconds>(finish - start).count());
            }
            if ((errorcode_t::verification_failure != sample_ret) || (false == plaintext.empty())) {
                wrapper_results = false;
            }

            size_t fatal_count = 0;
            reader.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
                if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::bad_record_mac == desc)) {
                    ++fatal_count;
                }
            });
            if (1 != fatal_count) {
                wrapper_results = false;
            }
        };

        // Warm both wrapper failure paths. Each call consumes one record number;
        // drain the alert outside the timed interval to avoid queue-growth bias.
        for (size_t i = 0; i < 128; ++i) {
            binary_t invalid_wire;
            binary_t bad_mac_wire;
            uint64 sequence = static_cast<uint64>(i) * 2;
            if ((errorcode_t::success != prepare_wire(sequence, true, false, invalid_wire)) ||
                (errorcode_t::success != prepare_wire(sequence + 1, false, true, bad_mac_wire))) {
                wrapper_results = false;
                break;
            }
            run_once(invalid_wire, nullptr);
            run_once(bad_mac_wire, nullptr);
        }

        std::vector<timing_value_t> invalid_padding_samples;
        std::vector<timing_value_t> invalid_mac_samples;
        invalid_padding_samples.reserve(sample_count);
        invalid_mac_samples.reserve(sample_count);

        if (wrapper_results) {
            for (size_t i = 0; i < sample_count; ++i) {
                binary_t first_wire;
                binary_t second_wire;
                const uint64 sequence = 256 + static_cast<uint64>(i) * 2;
                const bool invalid_first = (0 == (i & 1));
                return_t build_ret = errorcode_t::success;
                if (invalid_first) {
                    build_ret = prepare_wire(sequence, true, false, first_wire);
                    if (errorcode_t::success == build_ret) {
                        build_ret = prepare_wire(sequence + 1, false, true, second_wire);
                    }
                } else {
                    build_ret = prepare_wire(sequence, false, true, first_wire);
                    if (errorcode_t::success == build_ret) {
                        build_ret = prepare_wire(sequence + 1, true, false, second_wire);
                    }
                }
                if (errorcode_t::success != build_ret) {
                    wrapper_results = false;
                    break;
                }

                if (invalid_first) {
                    run_once(first_wire, &invalid_padding_samples);
                    run_once(second_wire, &invalid_mac_samples);
                } else {
                    run_once(first_wire, &invalid_mac_samples);
                    run_once(second_wire, &invalid_padding_samples);
                }
            }
        }

        _test_case.assert(wrapper_results, __FUNCTION__, "both wrapper paths return verification_failure, expose no plaintext, and queue one fatal bad_record_mac");
        if (wrapper_results && (sample_count == invalid_padding_samples.size()) && (sample_count == invalid_mac_samples.size())) {
            std::sort(invalid_padding_samples.begin(), invalid_padding_samples.end());
            std::sort(invalid_mac_samples.begin(), invalid_mac_samples.end());
            const size_t median_index = sample_count / 2;
            const size_t p95_index = std::min(sample_count - 1, (sample_count * 95) / 100);
            long double invalid_padding_total = 0;
            long double invalid_mac_total = 0;
            for (size_t i = 0; i < sample_count; ++i) {
                invalid_padding_total += invalid_padding_samples[i];
                invalid_mac_total += invalid_mac_samples[i];
            }
            const double invalid_padding_median = static_cast<double>(invalid_padding_samples[median_index]);
            const double invalid_mac_median = static_cast<double>(invalid_mac_samples[median_index]);
            const double median_ratio = (0.0 == invalid_mac_median) ? 0.0 : (invalid_padding_median / invalid_mac_median);
            std::printf(
                "TLS-MTE-WRAPPER-TIMING samples=%lu invalid_padding_valid_mac_ns median=%lld p95=%lld mean=%.1f valid_padding_invalid_mac_ns median=%lld p95=%lld "
                "mean=%.1f median_ratio=%.3f\n",
                static_cast<unsigned long>(sample_count), static_cast<long long>(invalid_padding_samples[median_index]),
                static_cast<long long>(invalid_padding_samples[p95_index]), static_cast<double>(invalid_padding_total / sample_count),
                static_cast<long long>(invalid_mac_samples[median_index]), static_cast<long long>(invalid_mac_samples[p95_index]),
                static_cast<double>(invalid_mac_total / sample_count), median_ratio);
        }
    }
}

static void test_tls12_directional_active_cipher_suite_state() {
    _test_case.begin("TLS 1.2 directional active cipher suite state");
    tls_session session;

    auto& client = session.get_session_info(from_client);
    auto& server = session.get_session_info(from_server);

    _test_case.assert(0 == client.get_active_cipher_suite(), __FUNCTION__, "client suite starts unset");
    _test_case.assert(0 == server.get_active_cipher_suite(), __FUNCTION__, "server suite starts unset");

    client.set_active_cipher_suite(0xc027);
    _test_case.assert(0xc027 == client.get_active_cipher_suite(), __FUNCTION__, "client suite is stored");
    _test_case.assert(0 == server.get_active_cipher_suite(), __FUNCTION__, "client suite does not change server direction");

    server.set_active_cipher_suite(0xc02f);
    _test_case.assert(0xc027 == client.get_active_cipher_suite(), __FUNCTION__, "server suite does not change client direction");
    _test_case.assert(0xc02f == server.get_active_cipher_suite(), __FUNCTION__, "server suite is stored independently");
}

void testcase_gpt_record() {
    test_tls12_directional_active_cipher_suite_state();
    test_tls12_ccs_sequence_reset();
    test_tls12_renegotiation_ccs_transition();
    test_tls12_initial_secure_renegotiation_scsv();
    test_tls12_hello_request_secure_renegotiation();
    test_tls12_renegotiation_policy_and_binding();
    test_tls13_rejects_truncated_aead_record_before_tag_extraction();
    test_tls12_rejects_truncated_aead_explicit_nonce();
    test_tls12_cbc_mte_padding_validation();
    test_tls12_cbc_mte_one_byte_padding_boundary();
    test_tls12_cbc_mte_timing_distribution();
    test_tls13_key_usage_limits();
    test_tls13_inner_plaintext_padding_and_content_type();
    test_tls13_early_data_limit_excludes_padding();
    test_tls_record_size_limits();
    test_dtls_record_publisher_segment_boundary();
    test_dtls_record_publisher_pmtu_api();
    test_dtls13_plaintext_content_type_demux();
    test_dtls13_minimum_ciphertext_sample();
    test_tls_record_size_limit_extension();
}
