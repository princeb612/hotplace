/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_psk_hrr_binder.cpp
 * @author GPT
 * @desc   TLS 1.3 PSK binder transcript and ClientHello2 integration after HelloRetryRequest.
 */

#include <algorithm>
#include <chrono>
#include <utility>

#include "testcase_gpt_common.hpp"

static void test_tls13_psk_binder_hrr_transcript() {
    // Scenario under test: TLS 1.3 ClientHello2 PSK binder transcript after HRR.
    // Action: reset the transcript before the HRR prefix.
    // Expected: resolve the TLS_AES_128_GCM_SHA256 cipher suite.
    _test_case.begin("TLS 1.3 ClientHello2 PSK binder transcript after HRR");

    tls_session session;
    session.set_type(session_type_t::tls);
    auto& protection = session.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::hello_retry_request);

    openssl_digest digest;
    binary_t client_hello1_hash(32, 0x11);
    binary_t synthetic_message_hash;
    synthetic_message_hash << uint8(tls_handshake_type_t::message_hash) << uint24_t(32) << client_hello1_hash;
    const binary_t hello_retry_request = {0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0xaa, 0xbb};
    binary_t transcript_prefix = synthetic_message_hash;
    transcript_prefix.insert(transcript_prefix.end(), hello_retry_request.begin(), hello_retry_request.end());

    return_t ret = protection.reset_transcript_hash(&session);
    _test_case.test(ret, __FUNCTION__, "reset the transcript before the HRR prefix");
    ret = protection.update_transcript_hash(&session, transcript_prefix.data(), transcript_prefix.size());
    _test_case.test(ret, __FUNCTION__, "seed the transcript with message_hash and HelloRetryRequest");
    // calc_context_hash rebuilds the binder transcript with the PSK hash from
    // this canonical prefix; the live transcript remains on the HRR suite hash.
    protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, transcript_prefix);

    // This buffer ends immediately before the binders vector length field.
    const binary_t truncated_client_hello2 = {0x01, 0x00, 0x00, 0x04, 0x03, 0x03, 0xcc, 0xdd};
    auto tlsadvisor = tls_advisor::get_instance();
    const tls_cipher_suite_t* suite = tlsadvisor->hintof_cipher_suite(0x1301);
    if (nullptr == suite) {
        _test_case.assert(false, __FUNCTION__, "resolve the TLS_AES_128_GCM_SHA256 cipher suite");
        return;
    }
    binary_t actual_binder_hash;
    ret = protection.calc_context_hash(&session, suite->mac, truncated_client_hello2.data(), truncated_client_hello2.size(), actual_binder_hash);
    _test_case.test(ret, __FUNCTION__, "calculate ClientHello2 binder hash using the existing HRR transcript");

    binary_t expected_transcript = transcript_prefix;
    expected_transcript.insert(expected_transcript.end(), truncated_client_hello2.begin(), truncated_client_hello2.end());
    binary_t expected_binder_hash;
    ret = digest.digest("sha256", expected_transcript, expected_binder_hash);
    _test_case.test(ret, __FUNCTION__, "calculate the expected message_hash, HRR, and truncated ClientHello2 digest");
    _test_case.assert(expected_binder_hash == actual_binder_hash, __FUNCTION__, "include the HRR transcript prefix in the ClientHello2 binder hash");

    const binary_t resumption_psk(32, 0x11);
    binary_t empty;
    binary_t empty_hash;
    ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "derive the empty transcript hash for the resumption binder key");
    protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    protection.get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    const binary_t expected_binder = base16_decode_rfc("9bf67dcb83f8988a0f1f92a9909855b2bfa508deb36f33e01e758f3cc56b4808");

    // Each component of the HRR binder transcript is independently
    // authenticated: the synthetic message_hash (ClientHello1), the HRR,
    // and the truncated ClientHello2. Mutating any one must change the
    // transcript hash and make the original binder fail verification.
    const std::array<size_t, 3> transcript_mutation_offsets = {
        static_cast<size_t>(sizeof(tls_handshake_t)),  // message_hash payload
        transcript_prefix.size() - 1,                  // HRR body
        truncated_client_hello2.size() - 1             // ClientHello2
    };
    for (size_t component = 0; component < transcript_mutation_offsets.size(); ++component) {
        binary_t mutated_prefix = transcript_prefix;
        binary_t mutated_client_hello2 = truncated_client_hello2;
        if (0 == component) {
            mutated_prefix[transcript_mutation_offsets[component]] ^= 0x01;
        } else if (1 == component) {
            mutated_prefix[transcript_mutation_offsets[component]] ^= 0x01;
        } else {
            mutated_client_hello2[transcript_mutation_offsets[component]] ^= 0x01;
        }

        protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, mutated_prefix);
        binary_t mutated_binder_hash;
        ret = protection.calc_context_hash(&session, suite->mac, mutated_client_hello2.data(), mutated_client_hello2.size(), mutated_binder_hash);
        _test_case.test(ret, __FUNCTION__, "recalculate the binder hash after mutating one HRR transcript component");
        _test_case.assert(mutated_binder_hash != expected_binder_hash, __FUNCTION__, "detect mutation of ClientHello1, HRR, or ClientHello2 in the binder transcript");

        protection.get_secrets().assign(tls_secret_t::hello_retry_request_transcript_prefix, transcript_prefix);
        if (errorcode_t::success == ret) {
            ret = protection.calc_psk(&session, mutated_binder_hash, expected_binder);
            _test_case.assert(errorcode_t::mismatch == ret, __FUNCTION__, "reject the original binder when any HRR transcript component changes");
        }
    }

    // Verify the binder itself against an independent known-answer value for
    // this synthetic message_hash || HRR || truncated ClientHello2 transcript.
    binary_t actual_binder;
    ret = protection.calc_psk_binder(&session, actual_binder_hash, actual_binder);
    _test_case.test(ret, __FUNCTION__, "calculate the ClientHello2 PSK binder after HRR");
    _test_case.assert(expected_binder == actual_binder, __FUNCTION__, "match the expected ClientHello2 binder after HRR");

    ret = protection.calc_psk(&session, actual_binder_hash, expected_binder);
    _test_case.test(ret, __FUNCTION__, "validate the ClientHello2 binder after HRR");
    const std::array<size_t, 3> modified_offsets = {0, expected_binder.size() / 2, expected_binder.size() - 1};
    for (size_t offset : modified_offsets) {
        binary_t modified_binder = expected_binder;
        modified_binder[offset] ^= 0x01;
        ret = protection.calc_psk(&session, actual_binder_hash, modified_binder);
        _test_case.assert(errorcode_t::mismatch == ret, __FUNCTION__, "reject a modified ClientHello2 binder at every tested offset");
    }

    auto transcript = protection.get_transcript_hash();
    binary_t preserved_transcript_hash;
    if (transcript) {
        transcript->digest(preserved_transcript_hash);
        transcript->release();
    }
    binary_t expected_prefix_hash;
    ret = digest.digest("sha256", transcript_prefix, expected_prefix_hash);
    _test_case.test(ret, __FUNCTION__, "calculate the expected HRR prefix digest");
    _test_case.assert(expected_prefix_hash == preserved_transcript_hash, __FUNCTION__, "leave the live transcript unchanged while calculating the binder hash");
}

using tls_session_keyvalue_hook_t = t_key_value<uint16, uint16>;

static void trace_tls_session_keyvalue_hook(const tls_session_keyvalue_hook_t::hook_event_t& event, void* parameter) {
    if (event.owner != parameter) {
        return;
    }
    if ((session_client_post_handshake_auth != event.key) && (session_client_psk_identity_count != event.key)) {
        return;
    }
    unsigned before = event.before_exists ? static_cast<unsigned>(*event.before_value) : 0;
    unsigned after = event.after_exists ? static_cast<unsigned>(*event.after_value) : 0;
    _logger->writeln("[tls-session-kv] owner=%p source=%p op=%u key=0x%04x before=(%u,%u) after=(%u,%u)", static_cast<const void*>(event.owner),
                     static_cast<const void*>(event.source), static_cast<unsigned>(event.operation), static_cast<unsigned>(event.key), event.before_exists ? 1u : 0u,
                     before, event.after_exists ? 1u : 0u, after);
}

static void test_tls13_post_hrr_zero_psk_fallback_handshake() {
    // Scenario: complete the post-HRR zero-PSK fallback handshake.
    // Action: perform ClientHello1, HRR, ClientHello2 and a final ServerHello that declines PSK.
    // Expected: both peers derive matching zero-PSK Early Secret and DHE handshake traffic secrets.
    _test_case.begin("TLS 1.3 post-HRR zero-PSK fallback handshake");
    auto tlsadvisor = tls_advisor::get_instance();

    constexpr uint32 ticket_age_add = 0x10203040;
    constexpr uint32 ticket_lifetime = 3600;
    const binary_t ticket = {0x11, 0x22, 0x33};
    const binary_t resumption_psk(32, 0x22);
    const binary_t hrr_random = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    return_t ret = errorcode_t::success;

    auto configure_resumption = [&](tls_session& session) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        session.get_keyvalue().set(session_handshake_finished, 1);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
        ticket_kv.set(session_ticket_lifetime, ticket_lifetime);
        ticket_kv.set(session_ticket_age_add, ticket_age_add);
        ticket_kv.set(session_ticket_timestamp, now_ms - 25);
        ticket_kv.set(session_ticket_max_early_data_size, 4096);
        protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket);
        protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    };

    // A server may decline PSK resumption in the final ServerHello after
    // HRR. The client must then use the zero-PSK early secret while preserving
    // the HRR transcript through ServerHello key-schedule processing.

    tls_session declined_psk_client;
    configure_resumption(declined_psk_client);
    declined_psk_client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    declined_psk_client.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);

    // Rebuild ClientHello1 and ClientHello2 through the client writers rather
    // than parsing their wire bytes into a fresh session. Parsing an outbound
    // ClientHello restores the public key-share bytes, but cannot recreate the
    // private key generated by the original client for the final DHE step.
    auto declined_clienthello1 = new tls_handshake_client_hello(&declined_psk_client);
    declined_clienthello1->add_ciphersuite(0x1301);
    auto declined_versions1 = new tls_extension_client_supported_versions(declined_clienthello1);
    declined_versions1->add(tls1_3);
    declined_clienthello1->get_extensions().add(declined_versions1);
    auto declined_groups1 = new tls_extension_supported_groups(declined_clienthello1);
    declined_groups1->add("x25519");
    declined_clienthello1->get_extensions().add(declined_groups1);
    auto declined_modes1 = new tls_extension_psk_key_exchange_modes(declined_clienthello1);
    declined_modes1->add(1);
    declined_clienthello1->get_extensions().add(declined_modes1);
    declined_clienthello1->get_extensions().add(new tls_extension_early_data(declined_clienthello1));
    declined_clienthello1->get_extensions().add(new tls_extension_client_psk(declined_clienthello1));
    tls_record_handshake declined_clienthello1_record(&declined_psk_client);
    declined_clienthello1_record << declined_clienthello1;
    binary_t declined_clienthello1_wire;
    ret = declined_clienthello1_record.write(from_client, declined_clienthello1_wire);
    _test_case.test(ret, __FUNCTION__, "serialize a separate ClientHello1 for the post-HRR PSK-decline path");
    if (errorcode_t::success != ret) {
        return;
    }

    // Run the decline scenario with both endpoints live. This ensures the
    // server and client derive the same post-HRR DHE secret and transcript,
    // rather than checking only the client's zero-PSK fallback in isolation.
    tls_session declined_psk_server;
    configure_resumption(declined_psk_server);
    declined_psk_server.get_keyvalue().set(session_conf_enforce_key_share_group, static_cast<uint16>(tlsadvisor->valueof_group("x25519")));
    tls_records declined_server_clienthello1_records;
    ret = declined_server_clienthello1_records.read(&declined_psk_server, from_client, declined_clienthello1_wire);
    _test_case.test(ret, __FUNCTION__, "server validates the independent ClientHello1 before declining PSK after HRR");
    if (errorcode_t::success != ret) {
        return;
    }

    auto declined_server_hrr = new tls_handshake_server_hello(&declined_psk_server);
    declined_server_hrr->set_random(hrr_random);
    ret = declined_server_hrr->set_cipher_suite(0x1301);
    _test_case.test(ret, __FUNCTION__, "select the TLS 1.3 suite for the independent decline-path HRR");
    if (errorcode_t::success != ret) {
        declined_server_hrr->release();
        return;
    }
    auto declined_server_hrr_versions = new tls_extension_server_supported_versions(declined_server_hrr);
    declined_server_hrr_versions->set(tls1_3);
    declined_server_hrr->get_extensions().add(declined_server_hrr_versions);
    auto declined_server_hrr_key_share = new tls_extension_server_key_share(declined_server_hrr);
    ret = declined_server_hrr_key_share->add_keyshare();
    _test_case.test(ret, __FUNCTION__, "select x25519 in the independent decline-path HRR");
    if (errorcode_t::success != ret) {
        declined_server_hrr->release();
        return;
    }
    declined_server_hrr->get_extensions().add(declined_server_hrr_key_share);
    tls_record_handshake declined_server_hrr_record(&declined_psk_server);
    declined_server_hrr_record << declined_server_hrr;
    binary_t declined_hrr_wire;
    ret = declined_server_hrr_record.write(from_server, declined_hrr_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the independent decline-path HRR");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records declined_hrr_records;
    ret = declined_hrr_records.read(&declined_psk_client, from_server, declined_hrr_wire);
    _test_case.test(ret, __FUNCTION__, "client processes the HRR generated by its matching decline-path server");
    if (errorcode_t::success != ret) {
        return;
    }

    auto declined_clienthello2 = new tls_handshake_client_hello(&declined_psk_client);
    declined_clienthello2->add_ciphersuite(0x1301);
    auto declined_versions2 = new tls_extension_client_supported_versions(declined_clienthello2);
    declined_versions2->add(tls1_3);
    declined_clienthello2->get_extensions().add(declined_versions2);
    auto declined_groups2 = new tls_extension_supported_groups(declined_clienthello2);
    declined_groups2->add("x25519");
    declined_clienthello2->get_extensions().add(declined_groups2);
    auto declined_key_share2 = new tls_extension_client_key_share(declined_clienthello2);
    declined_clienthello2->get_extensions().add(declined_key_share2);
    auto declined_modes2 = new tls_extension_psk_key_exchange_modes(declined_clienthello2);
    declined_modes2->add(1);
    declined_clienthello2->get_extensions().add(declined_modes2);
    declined_clienthello2->get_extensions().add(new tls_extension_client_psk(declined_clienthello2));
    uint16 declined_retry_group = t_narrow_cast(declined_psk_client.get_session_info(from_server).get_keyvalue().get(session_key_share_group));
    ret = declined_key_share2->add(static_cast<tls_group_t>(declined_retry_group));
    _test_case.test(ret, __FUNCTION__, "generate the independent ClientHello2 key share for the PSK-decline path");
    if (errorcode_t::success != ret) {
        return;
    }
    declined_key_share2->clear();
    tls_record_handshake declined_clienthello2_record(&declined_psk_client);
    declined_clienthello2_record << declined_clienthello2;
    binary_t declined_clienthello2_wire;
    ret = declined_clienthello2_record.write(from_client, declined_clienthello2_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with its own private key-share state");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records declined_server_clienthello2_records;
    ret = declined_server_clienthello2_records.read(&declined_psk_server, from_client, declined_clienthello2_wire);
    _test_case.test(ret, __FUNCTION__, "server validates ClientHello2 and its binder before declining PSK resumption");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(declined_psk_server.get_early_data_ticket().identity.empty(), __FUNCTION__,
                      "do not retain early-data ticket metadata after HRR, because ClientHello2 cannot offer early_data");
    _test_case.assert(0x1301 == declined_psk_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                      "retain the provisional ticket cipher suite until the final ServerHello decision");

    auto declined_server_hello = new tls_handshake_server_hello(&declined_psk_server);
    ret = declined_server_hello->set_cipher_suite(0x1301);
    _test_case.test(ret, __FUNCTION__, "select TLS_AES_128_GCM_SHA256 for the post-HRR full handshake");
    if (errorcode_t::success != ret) {
        declined_server_hello->release();
        return;
    }
    auto declined_server_versions = new tls_extension_server_supported_versions(declined_server_hello);
    declined_server_versions->set(tls1_3);
    declined_server_hello->get_extensions().add(declined_server_versions);
    auto declined_server_key_share = new tls_extension_server_key_share(declined_server_hello);
    ret = declined_server_key_share->add_keyshare();
    _test_case.test(ret, __FUNCTION__, "create the server DHE share for the post-HRR non-PSK handshake");
    if (errorcode_t::success != ret) {
        declined_server_hello->release();
        return;
    }
    declined_server_hello->get_extensions().add(declined_server_key_share);
    _test_case.assert(nullptr == declined_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), __FUNCTION__,
                      "omit pre_shared_key from the final post-HRR ServerHello");
    tls_record_handshake declined_server_hello_record(&declined_psk_server);
    declined_server_hello_record << declined_server_hello;
    binary_t declined_server_hello_wire;
    ret = declined_server_hello_record.write(from_server, declined_server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "derive and serialize the server's post-HRR non-PSK key schedule");
    if (errorcode_t::success != ret) {
        return;
    }

    auto& declined_server_protection = declined_psk_server.get_tls_protection();
    const binary_t& declined_server_early_secret = declined_server_protection.get_secrets().get(tls_secret_t::early_secret);
    binary_t expected_zero_psk_early_secret;
    ret = declined_server_protection.calc_resumption_early_secret(binary_t(32, 0), expected_zero_psk_early_secret);
    _test_case.test(ret, __FUNCTION__, "derive the expected zero-PSK Early Secret for the post-HRR full handshake");
    if (errorcode_t::success == ret) {
        _test_case.assert(expected_zero_psk_early_secret == declined_server_early_secret, __FUNCTION__,
                          "use the RFC 8446 zero-PSK Early Secret after HRR when the final ServerHello declines PSK");
    }
    _test_case.assert(declined_server_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                      "clear the server's rejected ticket PSK after the post-HRR ServerHello");
    _test_case.assert(0xffff == declined_psk_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "clear the server's provisional PSK identity after the post-HRR decline");
    _test_case.assert(declined_psk_server.get_early_data_ticket().identity.empty(), __FUNCTION__,
                      "clear the server's provisional early-data ticket after the final PSK decline");
    _test_case.assert(0 == declined_psk_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                      "clear the server's provisional ticket cipher suite after the final PSK decline");
    _test_case.assert(0 == declined_psk_server.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                      "clear the server's provisional early-data allowance after the final PSK decline");
    _test_case.assert(false == declined_server_protection.get_secrets().get(tls_secret_t::shared_secret).empty(), __FUNCTION__,
                      "use the ClientHello2 DHE share rather than an empty or PSK-only input after HRR");
    _test_case.assert(tls_flow_t::one_rtt == declined_server_protection.get_flow(), __FUNCTION__,
                      "leave HRR transcript flow only after deriving the final non-PSK handshake keys");

    tls_records declined_server_hello_records;
    ret = declined_server_hello_records.read(&declined_psk_client, from_server, declined_server_hello_wire);
    _test_case.test(ret, __FUNCTION__, "client accepts the matching server's post-HRR ServerHello that declines PSK");
    if (errorcode_t::success == ret) {
        auto& declined_client_protection = declined_psk_client.get_tls_protection();
        _test_case.assert(tls_flow_t::one_rtt == declined_client_protection.get_flow(), __FUNCTION__,
                          "switch the client to one_rtt after deriving the post-HRR non-PSK keys");
        _test_case.assert(0xffff == declined_psk_client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                          "retain the no-selected-identity sentinel after the post-HRR decline");
        _test_case.assert(declined_psk_client.get_early_data_ticket().identity.empty(), __FUNCTION__,
                          "clear the client's provisional early-data ticket after the final PSK decline");
        _test_case.assert(0 == declined_psk_client.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                          "clear the client's provisional ticket cipher suite after the final PSK decline");
        _test_case.assert(0 == declined_psk_client.get_session_info(from_server).get_keyvalue().get(session_early_data_limit), __FUNCTION__,
                          "clear the client's provisional early-data allowance after the final PSK decline");
        _test_case.assert(declined_client_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                          "discard the client's rejected ticket PSK after the post-HRR ServerHello");
        _test_case.assert(declined_server_early_secret == declined_client_protection.get_secrets().get(tls_secret_t::early_secret), __FUNCTION__,
                          "derive the same zero-PSK Early Secret on both endpoints after HRR");
        _test_case.assert(
            declined_server_protection.get_secrets().get(tls_secret_t::shared_secret) == declined_client_protection.get_secrets().get(tls_secret_t::shared_secret),
            __FUNCTION__, "derive matching DHE shared secrets after the post-HRR PSK decline");
        _test_case.assert(declined_server_protection.get_secrets().get(tls_secret_t::handshake) == declined_client_protection.get_secrets().get(tls_secret_t::handshake),
                          __FUNCTION__, "derive matching handshake secrets from the HRR transcript and DHE input");
        _test_case.assert(
            declined_server_protection.get_secrets().get(tls_secret_t::c_hs_traffic) == declined_client_protection.get_secrets().get(tls_secret_t::c_hs_traffic),
            __FUNCTION__, "derive matching client handshake traffic secrets after the post-HRR decline");
        _test_case.assert(
            declined_server_protection.get_secrets().get(tls_secret_t::s_hs_traffic) == declined_client_protection.get_secrets().get(tls_secret_t::s_hs_traffic),
            __FUNCTION__, "derive matching server handshake traffic secrets after the post-HRR decline");
    }
}

template <typename ConfigureResumption>
static void test_tls13_second_hrr_rejected(const binary_t& client_hello1_wire, const binary_t& hrr_wire, const binary_t& client_hello2_wire,
                                           ConfigureResumption configure_resumption) {
    // Scenario: reject a second HelloRetryRequest after ClientHello2.
    // Action: process ClientHello1, the first HRR and ClientHello2, then inject another HRR.
    // Expected: reject the second HRR with one fatal unexpected_message.
    _test_case.begin("TLS 1.3 rejects a second HelloRetryRequest after ClientHello2");
    return_t ret = errorcode_t::success;
    // Rebuild the complete retry exchange in an independent client and ensure
    // a second HRR is rejected after ClientHello2 has restored the client cursor.
    tls_session second_hrr_client;
    configure_resumption(second_hrr_client);
    tls_records second_hrr_clienthello1_records;
    ret = second_hrr_clienthello1_records.read(&second_hrr_client, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "prepare an independent client for the second-HRR rejection test");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records second_hrr_first_retry_records;
    ret = second_hrr_first_retry_records.read(&second_hrr_client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "process the first HelloRetryRequest in the independent client");
    if (errorcode_t::success != ret) {
        return;
    }
    tls_records second_hrr_clienthello2_records;
    ret = second_hrr_clienthello2_records.read(&second_hrr_client, from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "process ClientHello2 before injecting a second HelloRetryRequest");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_handshake_type_t::client_hello == second_hrr_client.get_session_info(from_client).get_status(), __FUNCTION__,
                      "position the client handshake cursor at ClientHello2 before the second HRR");
    tls_records second_hrr_records;
    ret = second_hrr_records.read(&second_hrr_client, from_server, hrr_wire);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a second HelloRetryRequest in the same connection");
    size_t second_hrr_unexpected_message_count = test_count_fatal_alert(second_hrr_client, from_server, tls_alertdesc_t::unexpected_message);
    _test_case.assert(1 == second_hrr_unexpected_message_count, __FUNCTION__, "report fatal unexpected_message for a second HelloRetryRequest");
}

static void test_tls13_hrr_transcript_hash_switch() {
    // Scenario: verify transcript-hash reset when the HRR-selected cipher suite changes.
    // Action: initialize a provisional SHA-256 transcript, then select the SHA-384 HRR suite.
    // Expected: reinitialize the transcript hash using only post-selection bytes and SHA-384.
    _test_case.begin("TLS 1.3 HRR resets the transcript hash when the selected suite changes");
    return_t ret = errorcode_t::success;
    // The provisional PSK suite can differ from the suite selected in HRR.
    // Verify that changing suites discards any lazily-created transcript hash
    // so the synthetic message_hash is computed with the negotiated suite hash.
    tls_session suite_hash_switch_session;
    suite_hash_switch_session.set_type(session_type_t::tls);
    auto& suite_hash_switch_protection = suite_hash_switch_session.get_tls_protection();
    suite_hash_switch_protection.set_cipher_suite(0x1301);
    const binary_t sample_handshake_message = {0x01, 0x00, 0x00, 0x00};
    ret = suite_hash_switch_protection.update_transcript_hash(&suite_hash_switch_session, sample_handshake_message.data(), sample_handshake_message.size());
    _test_case.test(ret, __FUNCTION__, "initialize a provisional SHA-256 transcript hash");
    if (errorcode_t::success == ret) {
        suite_hash_switch_protection.set_cipher_suite(0x1302);
        ret = suite_hash_switch_protection.update_transcript_hash(&suite_hash_switch_session, sample_handshake_message.data(), sample_handshake_message.size());
        _test_case.test(ret, __FUNCTION__, "reinitialize the transcript hash after selecting the SHA-384 HRR suite");
        if (errorcode_t::success == ret) {
            auto suite_hash = suite_hash_switch_protection.get_transcript_hash();
            binary_t actual_suite_hash;
            if (suite_hash) {
                suite_hash->digest(actual_suite_hash);
                suite_hash->release();
            }
            openssl_digest independent_suite_digest;
            binary_t expected_suite_hash;
            ret = independent_suite_digest.digest("sha384", sample_handshake_message, expected_suite_hash);
            _test_case.test(ret, __FUNCTION__, "independently calculate the negotiated SHA-384 transcript hash");
            if (errorcode_t::success == ret) {
                _test_case.assert(48 == actual_suite_hash.size(), __FUNCTION__, "replace the provisional SHA-256 transcript hash with SHA-384");
                _test_case.assert(expected_suite_hash == actual_suite_hash, __FUNCTION__, "hash only post-selection transcript bytes with the negotiated suite hash");
            }
        }
    }
}

template <typename ConfigureResumption>
static void test_tls13_hrr_rejects_out_of_range_selected_identity(const binary_t& client_hello1_wire, const binary_t& hrr_wire, const binary_t& client_hello2_wire,
                                                                  const binary_t& selected_server_hello_wire, const binary_t& hrr_random,
                                                                  ConfigureResumption configure_resumption) {
    // Scenario: reject an out-of-range selected_identity after a real HRR exchange.
    // Action: replay ClientHello1, HRR and ClientHello2 on independent sessions before injecting an invalid selection.
    // Expected: reject the invalid ServerHello with fatal illegal_parameter and preserve failure cleanup.
    _test_case.begin("TLS 1.3 rejects an out-of-range selected_identity after HRR");
    return_t ret = errorcode_t::success;
    auto tlsadvisor = tls_advisor::get_instance();
    // Rebuild the same ClientHello1-HRR-ClientHello2 state in an independent
    // client session. The successful ServerHello above advances the original
    // client's handshake cursor to ServerHello, so reusing it would correctly
    // trigger unexpected_message before selected_identity can be validated.
    tls_session invalid_selected_client;
    configure_resumption(invalid_selected_client);

    tls_records invalid_clienthello1_records;
    ret = invalid_clienthello1_records.read(&invalid_selected_client, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "replay ClientHello1 for the independent selected_identity test session");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records invalid_hrr_records;
    ret = invalid_hrr_records.read(&invalid_selected_client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "replay HelloRetryRequest for the independent selected_identity test session");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records invalid_clienthello2_records;
    ret = invalid_clienthello2_records.read(&invalid_selected_client, from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "replay ClientHello2 for the independent selected_identity test session");
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(tls_handshake_type_t::client_hello == invalid_selected_client.get_session_info(from_client).get_status(), __FUNCTION__,
                      "keep the peer handshake cursor at ClientHello2 before parsing ServerHello");
    _test_case.assert(1 == invalid_selected_client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                      "retain the single PSK identity offered in ClientHello2");

    binary_t invalid_selected_server_hello_wire = selected_server_hello_wire;
    invalid_selected_server_hello_wire.back() = 0x01;
    // The source is a complete TLS record, so parse it through the record
    // layer. Calling the handshake parser directly would incorrectly feed
    // the five-byte TLS record header as the handshake message header.
    tls_records invalid_selected_server_hello_records;
    ret = invalid_selected_server_hello_records.read(&invalid_selected_client, from_server, invalid_selected_server_hello_wire);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject selected_identity one when the real post-HRR ClientHello2 offered only one identity");
    std::set<tls_alertdesc_t> selected_identity_alerts;
    size_t selected_identity_alert_count = test_collect_fatal_alerts(invalid_selected_client, from_server, selected_identity_alerts);
    _test_case.assert(1 == selected_identity_alert_count, __FUNCTION__, "queue exactly one fatal alert for an out-of-range post-HRR selected_identity");
    _test_case.assert(selected_identity_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__,
                      "report fatal illegal_parameter, not unexpected_message, for an out-of-range post-HRR selected_identity");
    auto& invalid_selected_secrets = invalid_selected_client.get_tls_protection().get_secrets();
    _test_case.assert(invalid_selected_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                      "clear the provisional PSK Early Secret after invalid ServerHello selected_identity");
    _test_case.assert(invalid_selected_secrets.get(tls_secret_t::resumption_binder_key).empty(), __FUNCTION__,
                      "clear the provisional PSK binder key after invalid ServerHello selected_identity");
    _test_case.assert(0 == invalid_selected_client.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                      "clear the provisional ticket cipher suite after invalid ServerHello selected_identity");
    _test_case.assert(0xffff == invalid_selected_client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "leave no selected identity after invalid ServerHello selected_identity");
    _test_case.assert(0xffff == invalid_selected_client.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__,
                      "leave no selected key-exchange mode after invalid ServerHello selected_identity");
    _test_case.assert(invalid_selected_client.get_early_data_ticket().identity.empty(), __FUNCTION__,
                      "clear the provisional early-data ticket after invalid ServerHello selected_identity");
    _test_case.assert(invalid_selected_client.get_offered_resumption_tickets().empty(), __FUNCTION__,
                      "discard the offered-ticket snapshot after invalid ServerHello selected_identity");

    binary_t tampered = client_hello2_wire;
    tampered.back() ^= 0x01;
    tls_session rejecting_server;
    configure_resumption(rejecting_server);
    rejecting_server.get_keyvalue().set(session_conf_enforce_key_share_group, static_cast<uint16>(tlsadvisor->valueof_group("x25519")));
    tls_records rejecting_clienthello1_records;
    ret = rejecting_clienthello1_records.read(&rejecting_server, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "prepare a separate server with the same ClientHello1 transcript");
    if (errorcode_t::success != ret) {
        return;
    }

    // Reproduce the HRR on the rejecting server so its transcript is identical.
    auto rejecting_server_hello = new tls_handshake_server_hello(&rejecting_server);
    rejecting_server_hello->set_random(hrr_random);
    ret = rejecting_server_hello->set_cipher_suite(0x1301);
    if (errorcode_t::success != ret) {
        rejecting_server_hello->release();
        return;
    }
    auto rejecting_versions = new tls_extension_server_supported_versions(rejecting_server_hello);
    rejecting_versions->set(tls1_3);
    rejecting_server_hello->get_extensions().add(rejecting_versions);
    auto rejecting_key_share = new tls_extension_server_key_share(rejecting_server_hello);
    ret = rejecting_key_share->add_keyshare();
    if (errorcode_t::success != ret) {
        rejecting_server_hello->release();
        return;
    }
    rejecting_server_hello->get_extensions().add(rejecting_key_share);
    tls_record_handshake rejecting_hrr_record(&rejecting_server);
    rejecting_hrr_record << rejecting_server_hello;
    binary_t rejecting_hrr_wire;
    ret = rejecting_hrr_record.write(from_server, rejecting_hrr_wire);
    _test_case.test(ret, __FUNCTION__, "recreate HRR before checking a modified ClientHello2 binder");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records rejecting_clienthello2_records;
    ret = rejecting_clienthello2_records.read(&rejecting_server, from_client, tampered);
    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a ClientHello2 with a modified PSK binder");

    size_t decrypt_error_count = test_count_fatal_alert(rejecting_server, from_client, tls_alertdesc_t::decrypt_error);
    _test_case.assert(1 == decrypt_error_count, __FUNCTION__, "report decrypt_error for a modified ClientHello2 binder");
    auto& rejecting_secrets = rejecting_server.get_tls_protection().get_secrets();
    _test_case.assert(rejecting_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                      "clear the provisional PSK Early Secret after ClientHello2 binder failure");
    _test_case.assert(rejecting_secrets.get(tls_secret_t::resumption_binder_key).empty(), __FUNCTION__,
                      "clear the provisional PSK binder key after ClientHello2 binder failure");
    _test_case.assert(rejecting_secrets.get(tls_secret_t::resumption_finished_key).empty(), __FUNCTION__,
                      "clear the provisional PSK Finished key after ClientHello2 binder failure");
    _test_case.assert(0 == rejecting_server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                      "clear the provisional ticket cipher suite after ClientHello2 binder failure");
    _test_case.assert(0xffff == rejecting_server.get_keyvalue().get(session_server_psk_key_exchange_mode), __FUNCTION__,
                      "leave the PSK key-exchange mode unselected after ClientHello2 binder failure");
    _test_case.assert(rejecting_server.get_early_data_ticket().identity.empty(), __FUNCTION__,
                      "clear the provisional early-data ticket after ClientHello2 binder failure");
}

template <typename PrepareRetryServer, typename ConfigureResumption>
static void test_tls13_hrr_rejects_changed_psk_modes(const binary_t& client_hello1_wire, PrepareRetryServer prepare_retry_server,
                                                     ConfigureResumption configure_resumption) {
    // Scenario: TLS 1.3 rejects changed psk_key_exchange_modes in ClientHello2 after HRR.
    // Action: construct a correctly rebound ClientHello2 that changes psk_dhe_ke to psk_ke.
    // Expected: reject the changed mode with one fatal illegal_parameter.
    _test_case.begin("TLS 1.3 rejects changed psk_key_exchange_modes in ClientHello2 after HRR");
    return_t ret = errorcode_t::success;
    // psk_key_exchange_modes is not a permitted ClientHello2 change. Build a
    // correctly rebound ClientHello2 with a changed mode so the server reaches
    // the continuity check rather than failing binder verification first.
    tls_session changed_mode_server;
    binary_t changed_mode_hrr;
    ret = prepare_retry_server(changed_mode_server, changed_mode_hrr);
    _test_case.test(ret, __FUNCTION__, "prepare an independent server for the ClientHello2 PSK mode consistency check");
    if (errorcode_t::success == ret) {
        tls_session changed_mode_client;
        configure_resumption(changed_mode_client);
        tls_records changed_mode_clienthello1_records;
        ret = changed_mode_clienthello1_records.read(&changed_mode_client, from_client, client_hello1_wire);
        _test_case.test(ret, __FUNCTION__, "restore the client state before constructing a changed-mode ClientHello2");
        if (errorcode_t::success == ret) {
            tls_records changed_mode_hrr_records;
            ret = changed_mode_hrr_records.read(&changed_mode_client, from_server, changed_mode_hrr);
            _test_case.test(ret, __FUNCTION__, "process the matching HRR before constructing a changed-mode ClientHello2");
        }
        if (errorcode_t::success == ret) {
            tls_handshake_client_hello modes_template(&changed_mode_client);
            tls_extension_psk_key_exchange_modes expected_modes(&modes_template);
            expected_modes.add(0);  // deliberately change psk_dhe_ke to psk_ke
            binary_t expected_modes_wire;
            ret = expected_modes.write(from_client, expected_modes_wire);
            _test_case.test(ret, __FUNCTION__, "encode the deliberately changed PSK mode offer");
            if (errorcode_t::success == ret) {
                // Bypass only the local client-side guard in this negative
                // server test; the actual ClientHello1 on the wire still
                // contains psk_dhe_ke.
                changed_mode_client.get_tls_protection().get_secrets().assign(tls_secret_t::client_hello_psk_modes, expected_modes_wire);

                auto changed_mode_clienthello2 = new tls_handshake_client_hello(&changed_mode_client);
                changed_mode_clienthello2->add_ciphersuite(0x1301);
                auto changed_mode_versions = new tls_extension_client_supported_versions(changed_mode_clienthello2);
                changed_mode_versions->add(tls1_3);
                changed_mode_clienthello2->get_extensions().add(changed_mode_versions);
                auto changed_mode_groups = new tls_extension_supported_groups(changed_mode_clienthello2);
                changed_mode_groups->add("x25519");
                changed_mode_clienthello2->get_extensions().add(changed_mode_groups);
                auto changed_mode_key_share = new tls_extension_client_key_share(changed_mode_clienthello2);
                changed_mode_clienthello2->get_extensions().add(changed_mode_key_share);
                auto changed_mode_modes = new tls_extension_psk_key_exchange_modes(changed_mode_clienthello2);
                changed_mode_modes->add(0);
                changed_mode_clienthello2->get_extensions().add(changed_mode_modes);
                auto changed_mode_psk = new tls_extension_client_psk(changed_mode_clienthello2);
                changed_mode_clienthello2->get_extensions().add(changed_mode_psk);

                tls_record_handshake changed_mode_record(&changed_mode_client);
                changed_mode_record << changed_mode_clienthello2;
                binary_t changed_mode_clienthello2_wire;
                ret = changed_mode_record.write(from_client, changed_mode_clienthello2_wire);
                _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with a recomputed binder and changed PSK mode");
                if (errorcode_t::success == ret) {
                    tls_records changed_mode_records;
                    ret = changed_mode_records.read(&changed_mode_server, from_client, changed_mode_clienthello2_wire);
                    _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject ClientHello2 when psk_key_exchange_modes changes after HRR");
                    size_t illegal_parameter_count = test_count_fatal_alert(changed_mode_server, from_client, tls_alertdesc_t::illegal_parameter);
                    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report fatal illegal_parameter for a changed ClientHello2 PSK mode offer");
                }
            }
        }
    }
}

template <typename PrepareRetryServer>
static void test_tls13_hrr_rejects_changed_psk_identity(const binary_t& client_hello2_wire, PrepareRetryServer prepare_retry_server) {
    // Scenario: TLS 1.3 rejects a changed PSK identity in ClientHello2 after HRR.
    // Action: mutate the first PSK identity while preserving the remaining ClientHello2 wire structure.
    // Expected: reject the changed identity with one fatal illegal_parameter.
    _test_case.begin("TLS 1.3 rejects a changed PSK identity in ClientHello2 after HRR");
    return_t ret = errorcode_t::success;
    // ClientHello2 may update ticket ages and binders, and remove PSKs that
    // are incompatible with the HRR suite. It must not substitute an identity.
    tls_session changed_identity_server;
    binary_t changed_identity_hrr;
    ret = prepare_retry_server(changed_identity_server, changed_identity_hrr);
    _test_case.test(ret, __FUNCTION__, "prepare an independent server for the ClientHello2 identity consistency check");
    if (errorcode_t::success == ret) {
        binary_t changed_identity_clienthello2 = client_hello2_wire;
        size_t psk_body_pos = 0;
        size_t psk_body_size = 0;
        bool found_psk =
            test_find_client_hello_extension(changed_identity_clienthello2, static_cast<uint16>(tls_extension_type_t::pre_shared_key), psk_body_pos, psk_body_size);
        _test_case.assert(found_psk && (psk_body_size >= 8), __FUNCTION__, "locate the ClientHello2 PSK identities vector");
        if (found_psk && (psk_body_size >= 8)) {
            uint16 identity_len = test_read_u16(changed_identity_clienthello2, psk_body_pos + 2);
            _test_case.assert((identity_len > 0) && (psk_body_size >= static_cast<size_t>(identity_len) + 8), __FUNCTION__,
                              "validate the first ClientHello2 PSK identity boundary");
            if ((identity_len > 0) && (psk_body_size >= static_cast<size_t>(identity_len) + 8)) {
                changed_identity_clienthello2[psk_body_pos + 4] ^= 0x80;
                tls_records changed_identity_records;
                ret = changed_identity_records.read(&changed_identity_server, from_client, changed_identity_clienthello2);
                _test_case.assert(errorcode_t::success != ret, __FUNCTION__, "reject a ClientHello2 that substitutes a PSK identity");
                size_t illegal_parameter_count = test_count_fatal_alert(changed_identity_server, from_client, tls_alertdesc_t::illegal_parameter);
                _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report fatal illegal_parameter for a changed ClientHello2 PSK identity");
            }
        }
    }
}

template <typename PrepareRetryServer>
static void test_tls13_hrr_early_data_discard_budget(const binary_t& client_hello2_wire, const binary_t& in_flight_early_data_record,
                                                     PrepareRetryServer prepare_retry_server) {
    // Scenario: TLS 1.3 HRR enforces the in-flight early-data discard budget.
    // Action: prepare an independent HRR server, consume the boundary record, then exceed the discard budget after ClientHello2.
    // Expected: reject the excess record with overflow and one fatal unexpected_message.
    _test_case.begin("TLS 1.3 HRR enforces the in-flight early-data discard budget");
    return_t ret = errorcode_t::success;
    // Keep the fatal skip-budget case isolated: overflow deliberately resets
    // the handshake status, so it must not run on the live session that will
    // continue to compose the final post-HRR ServerHello.
    tls_session over_limit_server;
    // Configure the discard budget before ClientHello1 is parsed. The TLS
    // session applies this setting to the per-connection early-data state
    // during ClientHello processing; setting it after HRR is too late.
    // The first 16-byte record reaches the exact boundary; the following
    // one-byte record must exceed it.
    over_limit_server.set_early_data_discard_limit(16);
    binary_t over_limit_hrr;
    ret = prepare_retry_server(over_limit_server, over_limit_hrr);
    _test_case.test(ret, __FUNCTION__, "prepare an independent server for the post-ClientHello2 early-data skip-limit test");
    if (errorcode_t::success == ret) {
        _test_case.assert(1 == over_limit_server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered_initial), __FUNCTION__,
                          "derive the isolated server's initial early_data state from ClientHello1");

        tls_records over_limit_before_clienthello2_records;
        ret = over_limit_before_clienthello2_records.read(&over_limit_server, from_client, in_flight_early_data_record);
        _test_case.test(ret, __FUNCTION__, "consume the first in-flight early-data record on the isolated server");
        if (errorcode_t::success == ret) {
            tls_records over_limit_clienthello2_records;
            ret = over_limit_clienthello2_records.read(&over_limit_server, from_client, client_hello2_wire);
            _test_case.test(ret, __FUNCTION__, "accept ClientHello2 before testing the isolated skip limit");
        }
        if (errorcode_t::success == ret) {
            binary_t over_limit_early_data_record{0x17, 0x03, 0x03, 0x00, 0x01, 0xaa};
            tls_records over_limit_after_clienthello2_records;
            return_t over_limit_ret = over_limit_after_clienthello2_records.read(&over_limit_server, from_client, over_limit_early_data_record);
            _test_case.assert(errorcode_t::overflow == over_limit_ret, __FUNCTION__, "enforce the same HRR skip budget for records arriving after ClientHello2");
            size_t hrr_skip_alert_count = test_count_fatal_alert(over_limit_server, from_client, tls_alertdesc_t::unexpected_message);
            _test_case.assert(1 == hrr_skip_alert_count, __FUNCTION__, "raise one fatal unexpected_message when late HRR early data exceeds the skip budget");
        }
    }
}

static void test_tls13_hrr_validates_clienthello2_binder(const char* function_name, tls_session& server, tls_session& client, const binary_t& client_hello1_wire,
                                                         const binary_t& client_hello2_wire, const binary_t& hrr_wire, const binary_t& in_flight_early_data_record,
                                                         binary_t& selected_server_hello_wire) {
    // Scenario under test: server validates the ClientHello2 PSK binder against the live HRR transcript.
    // Action: process ClientHello2, account for late in-flight early data, and independently reconstruct the binder transcript.
    // Expected: match client and server binder hashes to the RFC 8446 message_hash(ClientHello1), HRR, and truncated ClientHello2 transcript.
    return_t ret = errorcode_t::success;
    tls_records server_clienthello2_records;
    ret = server_clienthello2_records.read(&server, from_client, client_hello2_wire);
    _test_case.test(ret, function_name, "server validates ClientHello2 binder against its live HRR transcript");
    if (errorcode_t::success == ret) {
        const auto& early_state = server.get_session_info(from_server).get_keyvalue();
        _test_case.assert(0 == early_state.get(session_early_data_offered), function_name, "record that ClientHello2 did not re-offer early_data");
        _test_case.assert(1 == early_state.get(session_early_data_offered_initial), function_name, "retain ClientHello1 early-data state for late in-flight records");
        _test_case.assert(16 == early_state.get(session_early_data_discarded), function_name, "preserve the pre-ClientHello2 rejected-data skip count");
        _test_case.assert(32 == early_state.get(session_early_data_discard_limit), function_name, "preserve the configured HRR rejected-data skip budget");
        tls_records early_data_after_clienthello2_records;
        return_t late_early_data_ret = early_data_after_clienthello2_records.read(&server, from_client, in_flight_early_data_record);
        _test_case.test(late_early_data_ret, function_name, "skip a late ClientHello1 early-data record after ClientHello2");
        _test_case.assert(1 == early_data_after_clienthello2_records.size(), function_name, "consume the late in-flight early-data record");
        _test_case.assert(32 == early_state.get(session_early_data_discarded), function_name, "keep the HRR skip count cumulative across ClientHello2");
        _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_identity_count), function_name, "refresh the server's PSK identity count from ClientHello2");
        _test_case.assert(tls_flow_t::hello_retry_request == server.get_tls_protection().get_flow(), function_name,
                          "preserve the HRR transcript flow after accepting the ClientHello2 PSK");
        _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_selected_identity), function_name, "retain selected_identity zero for the final ServerHello");
        const binary_t& client_binder_hash = client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
        const binary_t& server_binder_hash = server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_binder_hash);
        _test_case.assert(!client_binder_hash.empty() && client_binder_hash == server_binder_hash, function_name,
                          "client and server derive the same binder transcript hash from the real HRR exchange");

        // Independently reconstruct the RFC 8446 HRR binder transcript from
        // the captured TLS records. This avoids relying only on client/server
        // agreement, which could hide a shared truncation-offset defect.
        constexpr size_t tls_record_header_size = 5;
        size_t actual_psk_body_pos = 0;
        size_t actual_psk_body_size = 0;
        bool actual_psk_found =
            test_find_client_hello_extension(client_hello2_wire, static_cast<uint16>(tls_extension_type_t::pre_shared_key), actual_psk_body_pos, actual_psk_body_size);
        bool actual_wire_valid = (client_hello1_wire.size() > tls_record_header_size + 4) && (hrr_wire.size() > tls_record_header_size + 4) &&
                                 (client_hello2_wire.size() > tls_record_header_size + 4) && (0x01 == client_hello1_wire[tls_record_header_size]) &&
                                 (0x02 == hrr_wire[tls_record_header_size]) && (0x01 == client_hello2_wire[tls_record_header_size]) && actual_psk_found &&
                                 (actual_psk_body_size >= 4);
        size_t actual_binder_list_offset = 0;
        if (actual_wire_valid) {
            uint16 actual_identities_length = test_read_u16(client_hello2_wire, actual_psk_body_pos);
            actual_binder_list_offset = actual_psk_body_pos + sizeof(uint16) + actual_identities_length;
            actual_wire_valid =
                (actual_binder_list_offset + sizeof(uint16) <= actual_psk_body_pos + actual_psk_body_size) && (actual_binder_list_offset <= client_hello2_wire.size());
        }
        _test_case.assert(actual_wire_valid, function_name, "locate the exact ClientHello2 binder truncation boundary in the captured wire message");
        if (actual_wire_valid) {
            binary_t client_hello1_handshake(client_hello1_wire.begin() + tls_record_header_size, client_hello1_wire.end());
            binary_t client_hello1_hash;
            openssl_digest independent_digest;
            ret = independent_digest.digest("sha256", client_hello1_handshake, client_hello1_hash);
            _test_case.test(ret, function_name, "independently hash the complete ClientHello1 handshake message");
            if (errorcode_t::success == ret) {
                binary_t expected_hrr_transcript;
                expected_hrr_transcript << uint8(tls_handshake_type_t::message_hash) << uint24_t(static_cast<uint32>(client_hello1_hash.size())) << client_hello1_hash;
                expected_hrr_transcript.insert(expected_hrr_transcript.end(), hrr_wire.begin() + tls_record_header_size, hrr_wire.end());
                expected_hrr_transcript.insert(expected_hrr_transcript.end(), client_hello2_wire.begin() + tls_record_header_size,
                                               client_hello2_wire.begin() + actual_binder_list_offset);
                binary_t independent_binder_hash;
                ret = independent_digest.digest("sha256", expected_hrr_transcript, independent_binder_hash);
                _test_case.test(ret, function_name, "independently hash message_hash(ClientHello1), HRR, and truncated ClientHello2");
                if (errorcode_t::success == ret) {
                    _test_case.assert(independent_binder_hash == client_binder_hash, function_name,
                                      "match the independently reconstructed HRR binder transcript against the client value");
                    _test_case.assert(independent_binder_hash == server_binder_hash, function_name,
                                      "match the independently reconstructed HRR binder transcript against the server value");

                    // RFC 9846 permits the PSK-associated hash to differ from
                    // the HRR-selected suite hash. The synthetic message_hash
                    // above remains SHA-256, but the outer binder transcript
                    // must be re-hashed with the PSK hash (SHA-384 here).
                    binary_t expected_psk_hash_binder_transcript_hash;
                    ret = independent_digest.digest("sha384", expected_hrr_transcript, expected_psk_hash_binder_transcript_hash);
                    _test_case.test(ret, function_name, "independently hash the HRR binder transcript with the PSK-associated SHA-384 hash");
                    if (errorcode_t::success == ret) {
                        binary_t calculated_psk_hash_binder_transcript_hash;
                        ret =
                            client.get_tls_protection().calc_context_hash(&client, hash_algorithm_t::sha2_384, client_hello2_wire.data() + tls_record_header_size,
                                                                          actual_binder_list_offset - tls_record_header_size, calculated_psk_hash_binder_transcript_hash);
                        _test_case.test(ret, function_name, "calculate the HRR binder transcript with a PSK hash different from the negotiated SHA-256 hash");
                        if (errorcode_t::success == ret) {
                            _test_case.assert(48 == calculated_psk_hash_binder_transcript_hash.size(), function_name,
                                              "produce a SHA-384-sized binder transcript hash when the PSK hash differs from the HRR hash");
                            _test_case.assert(expected_psk_hash_binder_transcript_hash == calculated_psk_hash_binder_transcript_hash, function_name,
                                              "use SHA-256 only inside synthetic message_hash and SHA-384 for the outer binder transcript");

                            binary_t server_psk_hash_binder_transcript_hash;
                            ret =
                                server.get_tls_protection().calc_context_hash(&server, hash_algorithm_t::sha2_384, client_hello2_wire.data() + tls_record_header_size,
                                                                              actual_binder_list_offset - tls_record_header_size, server_psk_hash_binder_transcript_hash);
                            _test_case.test(ret, function_name, "calculate the same distinct-hash HRR binder transcript on the server");
                            if (errorcode_t::success == ret) {
                                _test_case.assert(expected_psk_hash_binder_transcript_hash == server_psk_hash_binder_transcript_hash, function_name,
                                                  "match the independently reconstructed SHA-384 transcript on the server");
                            }
                        }
                    }
                }
            }
        }
    }
}

static void test_tls13_hrr_completes_selected_psk_finished_flight(const char* function_name, tls_session& server, tls_session& client, const binary_t& client_hello1_wire,
                                                                  const binary_t& client_hello2_wire, const binary_t& hrr_wire,
                                                                  const binary_t& in_flight_early_data_record, binary_t& selected_server_hello_wire) {
    // Scenario under test: selected post-HRR PSK establishes the 1-RTT key schedule and completes Finished.
    // Action: compose and parse ServerHello, exchange EncryptedExtensions, then verify Server Finished and Client Finished.
    // Expected: preserve selected PSK identity zero, reject post-HRR early_data, and derive matching application and resumption secrets.
    return_t ret = errorcode_t::success;
    // Exercise the final ServerHello while the resumption session marker is
    // still set. HRR nevertheless forbids 0-RTT, so the final PSK selection
    // must use the one_rtt flow while retaining the selected PSK early secret.
    server.get_keyvalue().set(session_handshake_finished, 1);
    client.get_keyvalue().set(session_handshake_finished, 1);

    // Complete the real HRR path through the production ServerHello composer.
    // This verifies that the server carries the selected PSK identity from
    // ClientHello2 into the final ServerHello rather than relying on a
    // hand-assembled extension vector.
    tls_handshake* selected_server_hello = nullptr;
    ret = tls_composer::construct_server_hello(&selected_server_hello, &server, nullptr);
    _test_case.test(ret, function_name, "construct the final post-HRR ServerHello through the TLS composer");
    if ((errorcode_t::success != ret) || (nullptr == selected_server_hello)) {
        return;
    }

    auto selected_server_versions = selected_server_hello->get_extensions().get(tls_extension_type_t::supported_versions);
    auto selected_server_key_share = selected_server_hello->get_extensions().get(tls_extension_type_t::key_share);
    auto selected_server_psk = selected_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key);
    _test_case.assert(nullptr != selected_server_versions, function_name, "include supported_versions in the final post-HRR ServerHello");
    _test_case.assert(nullptr != selected_server_key_share, function_name, "include the requested key_share in the final post-HRR ServerHello");
    _test_case.assert(nullptr != selected_server_psk, function_name, "include pre_shared_key after accepting the ClientHello2 PSK");
    _test_case.assert(1 == server.get_keyvalue().get(session_server_psk_key_exchange_mode), function_name,
                      "prefer psk_dhe_ke after HRR when ClientHello2 supplies the requested key share");
    if ((nullptr == selected_server_versions) || (nullptr == selected_server_key_share) || (nullptr == selected_server_psk)) {
        selected_server_hello->release();
        return;
    }

    auto selected_server_psk_extension = static_cast<tls_extension_server_psk*>(selected_server_psk);
    _test_case.assert(0 == selected_server_psk_extension->get_selected_identity(), function_name, "serialize selected_identity zero retained from ClientHello2");
    tls_record_handshake selected_server_hello_record(&server);
    selected_server_hello_record << selected_server_hello;
    ret = selected_server_hello_record.write(from_server, selected_server_hello_wire);
    _test_case.test(ret, function_name, "serialize the composer-built post-HRR ServerHello in a plaintext Handshake record");
    // tls_record_handshake takes ownership through operator<<; do not release
    // selected_server_hello here or the record container will release it twice.
    if (errorcode_t::success != ret) {
        return;
    }

    binary_t server_shared_secret = server.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
    _test_case.assert(!server_shared_secret.empty(), function_name, "derive the server-side shared secret from the negotiated ClientHello2 key_share");

    tls_records selected_server_hello_records;
    ret = selected_server_hello_records.read(&client, from_server, selected_server_hello_wire);
    _test_case.test(ret, function_name, "client accepts the production-composed post-HRR ServerHello selecting identity zero through the record reader");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::one_rtt == server.get_tls_protection().get_flow(), function_name,
                          "keep the post-HRR PSK handshake in one_rtt even when the resumption session marker is set");
        _test_case.assert(tls_flow_t::one_rtt == client.get_tls_protection().get_flow(), function_name, "retain one_rtt flow on the client while a PSK is selected");
        _test_case.assert(1 == client.get_keyvalue().get(session_server_psk_key_exchange_mode), function_name,
                          "record psk_dhe_ke on the client after the post-HRR ServerHello");
    }
    if (errorcode_t::success == ret) {
        _test_case.assert(1 == selected_server_hello_records.size(), function_name, "consume exactly one complete post-HRR ServerHello record");
        _test_case.assert(tls1_3 == client.get_tls_protection().get_tls_version(), function_name, "retain TLS 1.3 after accepting the post-HRR PSK selection");
        binary_t client_shared_secret = client.get_tls_protection().get_secrets().get(tls_secret_t::shared_secret);
        _test_case.assert(!client_shared_secret.empty(), function_name, "derive the client-side shared secret from the ServerHello key_share");
        _test_case.assert(server_shared_secret == client_shared_secret, function_name, "derive matching DHE shared secrets after HRR PSK resumption");
        const binary_t& server_early_secret = server.get_tls_protection().get_secrets().get(tls_secret_t::early_secret);
        const binary_t& server_resumption_early = server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early);
        const binary_t& client_early_secret = client.get_tls_protection().get_secrets().get(tls_secret_t::early_secret);
        const binary_t& client_resumption_early = client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early);
        _test_case.assert(!server_resumption_early.empty() && server_early_secret == server_resumption_early, function_name,
                          "use the selected PSK early secret for the server handshake even when the post-HRR flow is one_rtt");
        _test_case.assert(!client_resumption_early.empty() && client_early_secret == client_resumption_early, function_name,
                          "use the selected PSK early secret for the client handshake even when the post-HRR flow is one_rtt");
        _test_case.assert(server_early_secret == client_early_secret, function_name, "derive the same PSK-based Early Secret on both peers after HRR");
        _test_case.assert(
            server.get_tls_protection().get_secrets().get(tls_secret_t::c_hs_traffic) == client.get_tls_protection().get_secrets().get(tls_secret_t::c_hs_traffic),
            function_name, "derive matching client handshake traffic secrets for HRR PSK resumption");
        _test_case.assert(
            server.get_tls_protection().get_secrets().get(tls_secret_t::s_hs_traffic) == client.get_tls_protection().get_secrets().get(tls_secret_t::s_hs_traffic),
            function_name, "derive matching server handshake traffic secrets for HRR PSK resumption");

        // HRR rejects 0-RTT without discarding the selected PSK used by the
        // 1-RTT handshake. A post-HRR EncryptedExtensions early_data
        // indication must therefore remain ineligible.
        tls_handshake_encrypted_extensions post_hrr_encrypted_extensions(&server);
        auto post_hrr_early_data = new tls_extension_early_data(&post_hrr_encrypted_extensions);
        post_hrr_encrypted_extensions.get_extensions().add(post_hrr_early_data);
        binary_t post_hrr_early_data_wire;
        return_t post_hrr_early_data_ret = post_hrr_early_data->write(from_server, post_hrr_early_data_wire);
        _test_case.assert(errorcode_t::invalid_parameter == post_hrr_early_data_ret, function_name,
                          "reject EncryptedExtensions early_data after HRR even while retaining the selected PSK");
        _test_case.assert(post_hrr_early_data_wire.empty(), function_name, "emit no post-HRR early_data extension bytes");
        _test_case.assert(0 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_accepted), function_name,
                          "leave 0-RTT unaccepted after the post-HRR PSK selection");
        _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                          "retain selected_identity zero after rejecting post-HRR early_data");
        _test_case.assert(server_early_secret == server.get_tls_protection().get_secrets().get(tls_secret_t::early_secret), function_name,
                          "preserve the selected PSK Early Secret for the 1-RTT key schedule");
    }

    // Complete the mandatory EncryptedExtensions flight before Finished.
    // The empty extension vector is valid here: the preceding direct extension
    // write above only checks that HRR rejects early_data; it is not a handshake
    // message and must not stand in for the actual EncryptedExtensions record.
    tls_record_application_data post_hrr_encrypted_extensions_record(&server);
    post_hrr_encrypted_extensions_record << new tls_handshake_encrypted_extensions(&server);
    binary_t post_hrr_encrypted_extensions_record_wire;
    ret = post_hrr_encrypted_extensions_record.write(from_server, post_hrr_encrypted_extensions_record_wire);
    _test_case.test(ret, function_name, "write EncryptedExtensions under the server handshake traffic key");
    if (errorcode_t::success == ret) {
        tls_records post_hrr_encrypted_extensions_records;
        ret = post_hrr_encrypted_extensions_records.read(&client, from_server, post_hrr_encrypted_extensions_record_wire);
        _test_case.test(ret, function_name, "read EncryptedExtensions under the server handshake traffic key");
    }
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(0 != (server.get_session_status() & session_status_encrypted_extensions), function_name, "record the server's EncryptedExtensions before Finished");
    _test_case.assert(0 != (client.get_session_status() & session_status_encrypted_extensions), function_name, "record the client's EncryptedExtensions before Finished");
    _test_case.assert(0 == (server.get_session_status() & session_status_server_cert_verified), function_name,
                      "do not invent certificate verification state for a PSK-authenticated handshake");
    _test_case.assert(0 == (client.get_session_status() & session_status_server_cert_verified), function_name,
                      "do not invent certificate verification state on the PSK client");

    // Complete both Finished messages on the selected-PSK HRR path. This
    // verifies that the post-HRR handshake traffic secrets authenticate the
    // transcript and transition independently into application/resumption
    // secrets.
    tls_record_application_data post_hrr_server_finished(&server);
    post_hrr_server_finished << new tls_handshake_finished(&server);
    binary_t post_hrr_server_finished_wire;
    ret = post_hrr_server_finished.write(from_server, post_hrr_server_finished_wire);
    _test_case.test(ret, function_name, "write Server Finished after HRR PSK selection");
    if (errorcode_t::success == ret) {
        tls_records post_hrr_server_finished_records;
        ret = post_hrr_server_finished_records.read(&client, from_server, post_hrr_server_finished_wire);
        _test_case.test(ret, function_name, "verify Server Finished against the post-HRR PSK handshake transcript");
    }
    if (errorcode_t::success == ret) {
        auto& server_secrets = server.get_tls_protection().get_secrets();
        auto& client_secrets = client.get_tls_protection().get_secrets();
        _test_case.assert(0 != (server.get_session_status() & session_status_server_finished), function_name, "record the server Finished after HRR PSK resumption");
        _test_case.assert(0 != (client.get_session_status() & session_status_server_finished), function_name, "verify and record the server Finished on the client");
        _test_case.assert(
            !server_secrets.get(tls_secret_t::s_ap_traffic).empty() && server_secrets.get(tls_secret_t::s_ap_traffic) == client_secrets.get(tls_secret_t::s_ap_traffic),
            function_name, "derive matching server application traffic secrets from the HRR PSK transcript");
        _test_case.assert(
            !server_secrets.get(tls_secret_t::c_ap_traffic).empty() && server_secrets.get(tls_secret_t::c_ap_traffic) == client_secrets.get(tls_secret_t::c_ap_traffic),
            function_name, "derive matching client application traffic secrets from the HRR PSK transcript");

        tls_record_application_data post_hrr_client_finished(&client);
        post_hrr_client_finished << new tls_handshake_finished(&client);
        binary_t post_hrr_client_finished_wire;
        ret = post_hrr_client_finished.write(from_client, post_hrr_client_finished_wire);
        _test_case.test(ret, function_name, "write Client Finished after the verified post-HRR Server Finished");
        if (errorcode_t::success == ret) {
            tls_records post_hrr_client_finished_records;
            ret = post_hrr_client_finished_records.read(&server, from_client, post_hrr_client_finished_wire);
            _test_case.test(ret, function_name, "verify Client Finished against the complete post-HRR transcript");
        }
        if (errorcode_t::success == ret) {
            _test_case.assert(0 != (server.get_session_status() & session_status_client_finished), function_name, "record the client Finished after HRR PSK resumption");
            _test_case.assert(0 != (client.get_session_status() & session_status_client_finished), function_name,
                              "record the locally generated client Finished after HRR PSK resumption");
            _test_case.assert(
                !server_secrets.get(tls_secret_t::res_master).empty() && server_secrets.get(tls_secret_t::res_master) == client_secrets.get(tls_secret_t::res_master),
                function_name, "derive matching resumption master secrets after the post-HRR client Finished");
        }
    }
}

static void test_tls13_hrr_selects_psk_and_completes_finished(tls_session& server, tls_session& client, const binary_t& client_hello1_wire,
                                                              const binary_t& client_hello2_wire, const binary_t& hrr_wire, const binary_t& in_flight_early_data_record,
                                                              binary_t& selected_server_hello_wire) {
    // Scenario under test: TLS 1.3 HRR selects PSK identity zero and completes both Finished messages.
    // Action: validate ClientHello2, compose and process the selected-PSK ServerHello, then exchange EncryptedExtensions and Finished.
    // Expected: both peers retain identity zero and derive matching handshake, application, and resumption secrets.
    _test_case.begin("TLS 1.3 HRR selects PSK identity zero and completes both Finished messages");

    test_tls13_hrr_validates_clienthello2_binder(__FUNCTION__, server, client, client_hello1_wire, client_hello2_wire, hrr_wire, in_flight_early_data_record,
                                                 selected_server_hello_wire);
    test_tls13_hrr_completes_selected_psk_finished_flight(__FUNCTION__, server, client, client_hello1_wire, client_hello2_wire, hrr_wire, in_flight_early_data_record,
                                                          selected_server_hello_wire);
}

template <typename PrepareRetryServer, typename ConfigureResumption>
static void test_tls13_hrr_psk_decline_after_binder(const binary_t& client_hello1_wire, PrepareRetryServer prepare_retry_server,
                                                    ConfigureResumption configure_resumption) {
    // Scenario: TLS 1.3 server declines PSK after validating the ClientHello2 binder.
    // Action: complete the real HRR exchange, validate ClientHello2, and send a final ServerHello without pre_shared_key.
    // Expected: derive matching zero-PSK Early Secrets while preserving the full HRR transcript.
    _test_case.begin("TLS 1.3 server declines PSK after validating the ClientHello2 binder");
    return_t ret = errorcode_t::success;
    // A valid ClientHello2 binder does not force the server to resume.
    // Exercise the final post-HRR ServerHello that declines PSK and verify
    // that the HRR transcript is retained while the key schedule uses a
    // zero-PSK Early Secret.
    {
        tls_session decline_hrr_server;
        binary_t decline_hrr_wire;
        ret = prepare_retry_server(decline_hrr_server, decline_hrr_wire);
        _test_case.test(ret, __FUNCTION__, "prepare an independent server through ClientHello1 and HRR for the PSK-decline path");
        tls_session decline_hrr_client;
        configure_resumption(decline_hrr_client);
        if (errorcode_t::success == ret) {
            tls_records decline_client_clienthello1_records;
            ret = decline_client_clienthello1_records.read(&decline_hrr_client, from_client, client_hello1_wire);
            _test_case.test(ret, __FUNCTION__, "restore a dedicated client from ClientHello1 for the PSK-decline path");
        }
        if (errorcode_t::success == ret) {
            tls_records decline_client_hrr_records;
            ret = decline_client_hrr_records.read(&decline_hrr_client, from_server, decline_hrr_wire);
            _test_case.test(ret, __FUNCTION__, "process the matching HRR on the dedicated PSK-decline client");
        }

        // Generate a fresh ClientHello2 on this client so its private key
        // remains paired with the public key_share sent to the independent
        // server. Keep the main client untouched for the production-composer
        // PSK-selection path below.
        binary_t decline_clienthello2_wire;
        if (errorcode_t::success == ret) {
            auto decline_clienthello2 = new tls_handshake_client_hello(&decline_hrr_client);
            decline_clienthello2->add_ciphersuite(0x1301);
            auto decline_versions = new tls_extension_client_supported_versions(decline_clienthello2);
            decline_versions->add(tls1_3);
            decline_clienthello2->get_extensions().add(decline_versions);
            auto decline_groups = new tls_extension_supported_groups(decline_clienthello2);
            decline_groups->add("x25519");
            decline_clienthello2->get_extensions().add(decline_groups);
            auto decline_key_share = new tls_extension_client_key_share(decline_clienthello2);
            decline_clienthello2->get_extensions().add(decline_key_share);
            auto decline_modes = new tls_extension_psk_key_exchange_modes(decline_clienthello2);
            decline_modes->add(0);  // psk_ke
            decline_modes->add(1);  // psk_dhe_ke
            decline_clienthello2->get_extensions().add(decline_modes);
            auto decline_psk = new tls_extension_client_psk(decline_clienthello2);
            decline_clienthello2->get_extensions().add(decline_psk);

            uint16 retry_group = t_narrow_cast(decline_hrr_client.get_session_info(from_server).get_keyvalue().get(session_key_share_group));
            ret = decline_key_share->add(static_cast<tls_group_t>(retry_group));
            _test_case.test(ret, __FUNCTION__, "generate a dedicated ClientHello2 key share for the PSK-decline client");
            if (errorcode_t::success == ret) {
                decline_key_share->clear();
                tls_record_handshake decline_clienthello2_record(&decline_hrr_client);
                decline_clienthello2_record << decline_clienthello2;
                ret = decline_clienthello2_record.write(from_client, decline_clienthello2_wire);
                _test_case.test(ret, __FUNCTION__, "serialize the dedicated ClientHello2 with its own private key state");
            }
        }
        if (errorcode_t::success == ret) {
            tls_records decline_server_clienthello2_records;
            ret = decline_server_clienthello2_records.read(&decline_hrr_server, from_client, decline_clienthello2_wire);
            _test_case.test(ret, __FUNCTION__, "validate the dedicated ClientHello2 binder before declining PSK in the final ServerHello");
        }

        if (errorcode_t::success == ret) {
            _test_case.assert(tls_flow_t::hello_retry_request == decline_hrr_server.get_tls_protection().get_flow(), __FUNCTION__,
                              "retain the server's HRR transcript state after ClientHello2");
            _test_case.assert(tls_flow_t::hello_retry_request == decline_hrr_client.get_tls_protection().get_flow(), __FUNCTION__,
                              "retain the client's HRR transcript state after ClientHello2");
            _test_case.assert(0 == decline_hrr_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                              "recognize the valid ClientHello2 PSK candidate before the final server decision");

            auto decline_server_hello = new tls_handshake_server_hello(&decline_hrr_server);
            ret = decline_server_hello->set_cipher_suite(0x1301);
            _test_case.test(ret, __FUNCTION__, "select the HRR-negotiated TLS 1.3 cipher suite for a full handshake");
            if (errorcode_t::success == ret) {
                auto decline_versions = new tls_extension_server_supported_versions(decline_server_hello);
                decline_versions->set(tls1_3);
                decline_server_hello->get_extensions().add(decline_versions);
                auto decline_key_share = new tls_extension_server_key_share(decline_server_hello);
                ret = decline_key_share->add_keyshare();
                _test_case.test(ret, __FUNCTION__, "create the server key share requested by ClientHello2");
                if (errorcode_t::success == ret) {
                    decline_server_hello->get_extensions().add(decline_key_share);
                    _test_case.assert(nullptr == decline_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), __FUNCTION__,
                                      "omit pre_shared_key from the final post-HRR ServerHello");

                    tls_record_handshake decline_server_hello_record(&decline_hrr_server);
                    decline_server_hello_record << decline_server_hello;
                    binary_t decline_server_hello_wire;
                    ret = decline_server_hello_record.write(from_server, decline_server_hello_wire);
                    _test_case.test(ret, __FUNCTION__, "serialize the final post-HRR ServerHello without selecting PSK");
                    if (errorcode_t::success == ret) {
                        auto& server_protection = decline_hrr_server.get_tls_protection();
                        auto& server_secrets = server_protection.get_secrets();
                        _test_case.assert(tls_flow_t::one_rtt == server_protection.get_flow(), __FUNCTION__,
                                          "leave the HRR transcript flow after calculating the non-PSK handshake");
                        _test_case.assert(0xffff == decline_hrr_server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                          "clear the provisional PSK identity when the final post-HRR ServerHello declines it");
                        _test_case.assert(server_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                          "discard the verified resumption PSK before the post-HRR full-handshake key schedule");

                        binary_t expected_zero_psk_early_secret;
                        ret = server_protection.calc_resumption_early_secret(binary_t(32, 0), expected_zero_psk_early_secret);
                        _test_case.test(ret, __FUNCTION__, "derive the independent zero-PSK Early Secret for the post-HRR full handshake");
                        if (errorcode_t::success == ret) {
                            _test_case.assert(expected_zero_psk_early_secret == server_secrets.get(tls_secret_t::early_secret), __FUNCTION__,
                                              "use the zero-PSK Early Secret after HRR instead of the rejected ticket PSK");
                        }

                        tls_records decline_client_serverhello_records;
                        ret = decline_client_serverhello_records.read(&decline_hrr_client, from_server, decline_server_hello_wire);
                        _test_case.test(ret, __FUNCTION__, "accept the final post-HRR ServerHello that declines PSK");
                        if (errorcode_t::success == ret) {
                            auto& client_protection = decline_hrr_client.get_tls_protection();
                            auto& client_secrets = client_protection.get_secrets();
                            _test_case.assert(tls_flow_t::one_rtt == client_protection.get_flow(), __FUNCTION__,
                                              "leave the HRR transcript flow on the client after the non-PSK ServerHello");
                            _test_case.assert(0xffff == decline_hrr_client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                              "retain the no-selected-identity sentinel on the client");
                            _test_case.assert(client_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                                              "discard the client's cached PSK after the final post-HRR ServerHello declines it");
                            _test_case.assert(expected_zero_psk_early_secret == client_secrets.get(tls_secret_t::early_secret), __FUNCTION__,
                                              "derive the same zero-PSK Early Secret on the client");
                            _test_case.assert(server_secrets.get(tls_secret_t::shared_secret) == client_secrets.get(tls_secret_t::shared_secret), __FUNCTION__,
                                              "derive matching DHE shared secrets for the post-HRR full handshake");
                            _test_case.assert(server_secrets.get(tls_secret_t::c_hs_traffic) == client_secrets.get(tls_secret_t::c_hs_traffic), __FUNCTION__,
                                              "derive matching client handshake traffic secrets after the PSK decline");
                            _test_case.assert(server_secrets.get(tls_secret_t::s_hs_traffic) == client_secrets.get(tls_secret_t::s_hs_traffic), __FUNCTION__,
                                              "derive matching server handshake traffic secrets after the PSK decline");

                            // Reconstruct the complete RFC transcript independently:
                            // message_hash(ClientHello1) || HRR || ClientHello2 || ServerHello.
                            binary_t client_hello1_handshake(client_hello1_wire.begin() + 5, client_hello1_wire.end());
                            binary_t client_hello1_hash;
                            openssl_digest independent_digest;
                            ret = independent_digest.digest("sha256", client_hello1_handshake, client_hello1_hash);
                            _test_case.test(ret, __FUNCTION__, "independently hash ClientHello1 for the post-HRR transcript");
                            if (errorcode_t::success == ret) {
                                binary_t expected_transcript;
                                expected_transcript << uint8(tls_handshake_type_t::message_hash) << uint24_t(static_cast<uint32>(client_hello1_hash.size()))
                                                    << client_hello1_hash;
                                expected_transcript.insert(expected_transcript.end(), decline_hrr_wire.begin() + 5, decline_hrr_wire.end());
                                expected_transcript.insert(expected_transcript.end(), decline_clienthello2_wire.begin() + 5, decline_clienthello2_wire.end());
                                expected_transcript.insert(expected_transcript.end(), decline_server_hello_wire.begin() + 5, decline_server_hello_wire.end());

                                binary_t expected_transcript_hash;
                                ret = independent_digest.digest("sha256", expected_transcript, expected_transcript_hash);
                                _test_case.test(ret, __FUNCTION__, "independently hash message_hash, HRR, ClientHello2, and the non-PSK ServerHello");
                                if (errorcode_t::success == ret) {
                                    auto server_transcript = server_protection.get_transcript_hash();
                                    auto client_transcript = client_protection.get_transcript_hash();
                                    binary_t server_transcript_hash;
                                    binary_t client_transcript_hash;
                                    if (server_transcript) {
                                        ret = server_transcript->digest(server_transcript_hash);
                                        server_transcript->release();
                                    } else {
                                        ret = errorcode_t::not_found;
                                    }
                                    _test_case.test(ret, __FUNCTION__, "read the server's post-HRR transcript hash");
                                    if (errorcode_t::success == ret && client_transcript) {
                                        ret = client_transcript->digest(client_transcript_hash);
                                        client_transcript->release();
                                    } else if (errorcode_t::success == ret) {
                                        ret = errorcode_t::not_found;
                                    }
                                    _test_case.test(ret, __FUNCTION__, "read the client's post-HRR transcript hash");
                                    if (errorcode_t::success == ret) {
                                        _test_case.assert(expected_transcript_hash == server_transcript_hash, __FUNCTION__,
                                                          "preserve the complete RFC HRR transcript on the server after PSK decline");
                                        _test_case.assert(expected_transcript_hash == client_transcript_hash, __FUNCTION__,
                                                          "preserve the complete RFC HRR transcript on the client after PSK decline");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Ownership is transferred to decline_server_hello_record by operator<<.
        }
    }
}

template <typename ConfigureResumption>
static void test_tls13_hrr_declines_unoffered_cached_psk(const char* function_name, ConfigureResumption configure_resumption) {
    // Scenario under test: a final non-PSK ServerHello discards an unused cached PSK.
    // Action: keep a cached PSK without offering it in ClientHello, then process a full-handshake ServerHello.
    // Expected: clear the cached PSK only when the final non-PSK key schedule is established.
    // A final ServerHello without pre_shared_key must discard a cached PSK
    // even when the client did not offer that PSK and remains in one_rtt.
    {
        tls_session ordinary_client;
        configure_resumption(ordinary_client);
        ordinary_client.get_tls_protection().set_flow(tls_flow_t::one_rtt);

        auto ordinary_client_hello = new tls_handshake_client_hello(&ordinary_client);
        ordinary_client_hello->add_ciphersuite(0x1301);
        auto ordinary_versions = new tls_extension_client_supported_versions(ordinary_client_hello);
        ordinary_versions->add(tls1_3);
        ordinary_client_hello->get_extensions().add(ordinary_versions);
        auto ordinary_groups = new tls_extension_supported_groups(ordinary_client_hello);
        ordinary_groups->add("x25519");
        ordinary_client_hello->get_extensions().add(ordinary_groups);
        auto ordinary_key_share = new tls_extension_client_key_share(ordinary_client_hello);
        ordinary_client_hello->get_extensions().add(ordinary_key_share);

        auto ordinary_tlsadvisor = tls_advisor::get_instance();
        return_t ordinary_ret = ordinary_key_share->add(static_cast<tls_group_t>(ordinary_tlsadvisor->valueof_group("x25519")));
        _test_case.test(ordinary_ret, function_name, "generate an ordinary ClientHello key share without offering PSK or early_data");
        if (errorcode_t::success == ordinary_ret) {
            tls_record_handshake ordinary_client_hello_record(&ordinary_client);
            ordinary_client_hello_record << ordinary_client_hello;
            binary_t ordinary_client_hello_wire;
            ordinary_ret = ordinary_client_hello_record.write(from_client, ordinary_client_hello_wire);
            _test_case.test(ordinary_ret, function_name, "serialize an ordinary ClientHello while retaining an unused cached PSK");
            if (errorcode_t::success == ordinary_ret) {
                tls_session ordinary_server;
                configure_resumption(ordinary_server);
                tls_records ordinary_client_hello_records;
                ordinary_ret = ordinary_client_hello_records.read(&ordinary_server, from_client, ordinary_client_hello_wire);
                _test_case.test(ordinary_ret, function_name, "process an ordinary ClientHello that does not offer PSK");
                if (errorcode_t::success == ordinary_ret) {
                    _test_case.assert(tls_flow_t::one_rtt == ordinary_client.get_tls_protection().get_flow(), function_name,
                                      "keep the client in one_rtt when its ClientHello does not offer PSK");
                    _test_case.assert(false == ordinary_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                                      "retain the unused cached PSK until the final ServerHello establishes the non-PSK key schedule");

                    tls_handshake* ordinary_server_hello = nullptr;
                    ordinary_ret = tls_composer::construct_server_hello(&ordinary_server_hello, &ordinary_server, nullptr);
                    _test_case.test(ordinary_ret, function_name, "construct a full-handshake ServerHello without PSK");
                    if ((errorcode_t::success == ordinary_ret) && (nullptr != ordinary_server_hello)) {
                        _test_case.assert(nullptr == ordinary_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), function_name,
                                          "omit pre_shared_key from the final ServerHello");
                        binary_t ordinary_server_hello_wire;
                        ordinary_ret = ordinary_server_hello->write(from_server, ordinary_server_hello_wire);
                        _test_case.test(ordinary_ret, function_name, "serialize the ordinary full-handshake ServerHello");
                        // Direct handshake serialization bypasses the record-layer
                        // post-write hook that drains deferred ServerHello work.
                        ordinary_server.run_scheduled(from_server);
                        if (errorcode_t::success == ordinary_ret) {
                            _test_case.assert(ordinary_server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                                              "clear the server's unused cached PSK when calculating the non-PSK key schedule");
                        }
                        ordinary_server_hello->release();
                        if (errorcode_t::success == ordinary_ret) {
                            tls_handshake_server_hello ordinary_server_hello_reader(&ordinary_client);
                            size_t ordinary_server_hello_pos = 0;
                            ordinary_ret = ordinary_server_hello_reader.read(from_server, ordinary_server_hello_wire.data(), ordinary_server_hello_wire.size(),
                                                                             ordinary_server_hello_pos);
                            _test_case.test(ordinary_ret, function_name, "accept the ordinary ServerHello without PSK");
                            if (errorcode_t::success == ordinary_ret) {
                                _test_case.assert(tls_flow_t::one_rtt == ordinary_client.get_tls_protection().get_flow(), function_name,
                                                  "preserve one_rtt after the ordinary ServerHello");
                                _test_case.assert(0xffff == ordinary_client.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                                                  "retain the no-selected-identity sentinel for the full handshake");
                                _test_case.assert(ordinary_client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                                                  "clear the unused cached PSK when the final ServerHello declines resumption");
                                _test_case.assert(false == ordinary_client.get_tls_protection().get_secrets().get(tls_secret_t::early_secret).empty(), function_name,
                                                  "derive the zero-PSK early secret for the ordinary full handshake");
                            }
                        }
                    } else if (errorcode_t::success == ordinary_ret) {
                        _test_case.assert(false, function_name, "construct a non-null full-handshake ServerHello without PSK");
                    }
                }
            }
        }
    }
}

template <typename ConfigureResumption>
static void test_tls13_hrr_declines_verified_psk_candidate(const char* function_name, ConfigureResumption configure_resumption) {
    // Scenario under test: the server may validate a PSK binder but decline the candidate in its final ServerHello.
    // Action: validate a PSK and early_data offer, then send a DHE ServerHello without pre_shared_key.
    // Expected: discard the provisional PSK, clear the selected identity and early-data state, and derive the zero-PSK Early Secret.
    // The server may validate an offered PSK binder and still choose a
    // certificate-authenticated full handshake. Binder validation identifies
    // a usable PSK candidate; it is not the final ServerHello PSK selection.
    // The final ServerHello without pre_shared_key must therefore discard it
    // before the non-PSK key schedule runs.
    {
        tls_session decline_client;
        configure_resumption(decline_client);
        decline_client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
        decline_client.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);

        auto decline_client_hello = new tls_handshake_client_hello(&decline_client);
        decline_client_hello->add_ciphersuite(0x1301);
        auto decline_versions = new tls_extension_client_supported_versions(decline_client_hello);
        decline_versions->add(tls1_3);
        decline_client_hello->get_extensions().add(decline_versions);
        auto decline_groups = new tls_extension_supported_groups(decline_client_hello);
        decline_groups->add("x25519");
        decline_client_hello->get_extensions().add(decline_groups);
        auto decline_key_share = new tls_extension_client_key_share(decline_client_hello);
        decline_client_hello->get_extensions().add(decline_key_share);
        auto decline_tlsadvisor = tls_advisor::get_instance();
        return_t decline_ret = decline_key_share->add(static_cast<tls_group_t>(decline_tlsadvisor->valueof_group("x25519")));
        _test_case.test(decline_ret, function_name, "generate a DHE key share for a PSK offer that the server will decline");
        if (errorcode_t::success == decline_ret) {
            auto decline_modes = new tls_extension_psk_key_exchange_modes(decline_client_hello);
            decline_modes->add(1);  // psk_dhe_ke
            decline_client_hello->get_extensions().add(decline_modes);
            decline_client_hello->get_extensions().add(new tls_extension_early_data(decline_client_hello));
            decline_client_hello->get_extensions().add(new tls_extension_client_psk(decline_client_hello));

            tls_record_handshake decline_client_hello_record(&decline_client);
            decline_client_hello_record << decline_client_hello;
            binary_t decline_client_hello_wire;
            decline_ret = decline_client_hello_record.write(from_client, decline_client_hello_wire);
            _test_case.test(decline_ret, function_name, "serialize a valid PSK offer with a binder and DHE key share");
            if (errorcode_t::success == decline_ret) {
                tls_session decline_server;
                configure_resumption(decline_server);
                tls_records decline_client_hello_records;
                decline_ret = decline_client_hello_records.read(&decline_server, from_client, decline_client_hello_wire);
                _test_case.test(decline_ret, function_name, "verify the offered PSK binder before choosing a full handshake");
                if (errorcode_t::success == decline_ret) {
                    auto& decline_server_protection = decline_server.get_tls_protection();
                    const binary_t provisional_psk_early_secret = decline_server_protection.get_secrets().get(tls_secret_t::resumption_early);
                    auto& decline_early_state = decline_server.get_session_info(from_server).get_keyvalue();
                    _test_case.assert(1 == decline_early_state.get(session_early_data_offered), function_name,
                                      "record the ClientHello early_data offer while validating the PSK binder");
                    _test_case.assert(0 == decline_early_state.get(session_early_data_accepted), function_name,
                                      "do not accept early data before EncryptedExtensions confirms it");
                    _test_case.assert(0 == decline_early_state.get(session_early_data_limit), function_name,
                                      "do not grant an early-data allowance without a matching ticket-store entry");
                    _test_case.assert(0 == decline_server.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                                      "record the verified PSK candidate identity before final ServerHello selection");
                    _test_case.assert(false == provisional_psk_early_secret.empty(), function_name, "retain the verified PSK provisionally before ServerHello selection");

                    auto decline_server_hello = new tls_handshake_server_hello(&decline_server);
                    decline_ret = decline_server_hello->set_cipher_suite(0x1301);
                    _test_case.test(decline_ret, function_name, "select the TLS 1.3 suite for the non-PSK ServerHello");
                    if (errorcode_t::success == decline_ret) {
                        auto decline_server_versions = new tls_extension_server_supported_versions(decline_server_hello);
                        decline_server_versions->set(tls1_3);
                        decline_server_hello->get_extensions().add(decline_server_versions);
                        auto decline_server_key_share = new tls_extension_server_key_share(decline_server_hello);
                        decline_ret = decline_server_key_share->add_keyshare();
                        _test_case.test(decline_ret, function_name, "create the server DHE share for the full handshake");
                        if (errorcode_t::success == decline_ret) {
                            decline_server_hello->get_extensions().add(decline_server_key_share);
                            _test_case.assert(nullptr == decline_server_hello->get_extensions().get(tls_extension_type_t::pre_shared_key), function_name,
                                              "omit pre_shared_key from the final ServerHello to decline resumption");
                            tls_record_handshake decline_server_hello_record(&decline_server);
                            decline_server_hello_record << decline_server_hello;
                            binary_t decline_server_hello_wire;
                            decline_ret = decline_server_hello_record.write(from_server, decline_server_hello_wire);
                            _test_case.test(decline_ret, function_name, "serialize a final ServerHello that declines the verified PSK");
                            if (errorcode_t::success == decline_ret) {
                                _test_case.assert(0xffff == decline_server.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                                                  "clear the provisional PSK identity when the server declines resumption");
                                _test_case.assert(0xffff == decline_server.get_keyvalue().get(session_server_psk_key_exchange_mode), function_name,
                                                  "clear the provisional PSK exchange mode when the server declines resumption");
                                _test_case.assert(tls_flow_t::one_rtt == decline_server_protection.get_flow(), function_name,
                                                  "leave the zero_rtt candidate flow when the server declines PSK resumption");
                                _test_case.assert(0 == decline_early_state.get(session_early_data_accepted), function_name,
                                                  "keep early data unaccepted when the server declines PSK resumption");
                                _test_case.assert(decline_server_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                                                  "discard the verified ticket PSK before deriving the non-PSK key schedule");
                                const binary_t& server_early_secret = decline_server_protection.get_secrets().get(tls_secret_t::early_secret);
                                _test_case.assert(false == server_early_secret.empty(), function_name, "derive the non-PSK Early Secret for the declined resumption");

                                // RFC 8446 §7.1: without a selected PSK, use
                                // a Hash.length zero PSK in HKDF-Extract(0, 0).
                                // TLS_AES_128_GCM_SHA256 uses a 32-byte hash.
                                binary_t expected_non_psk_early_secret;
                                decline_ret = decline_server_protection.calc_resumption_early_secret(binary_t(32, 0), expected_non_psk_early_secret);
                                _test_case.test(decline_ret, function_name, "derive the RFC 8446 zero-PSK Early Secret independently");
                                if (errorcode_t::success == decline_ret) {
                                    _test_case.assert(expected_non_psk_early_secret == server_early_secret, function_name,
                                                      "match the RFC 8446 zero-PSK Early Secret rather than merely matching the peer");
                                }
                                _test_case.assert(server_early_secret != provisional_psk_early_secret, function_name,
                                                  "do not use the verified but rejected PSK as the Early Secret input");

                                tls_records decline_server_hello_records;
                                decline_ret = decline_server_hello_records.read(&decline_client, from_server, decline_server_hello_wire);
                                _test_case.test(decline_ret, function_name, "client accepts the server's non-PSK ServerHello record");
                                if (errorcode_t::success == decline_ret) {
                                    auto& decline_client_protection = decline_client.get_tls_protection();
                                    _test_case.assert(0xffff == decline_client.get_keyvalue().get(session_server_psk_selected_identity), function_name,
                                                      "client retains the no-selected-identity sentinel");
                                    _test_case.assert(tls_flow_t::one_rtt == decline_client_protection.get_flow(), function_name,
                                                      "leave the zero_rtt candidate flow after receiving the non-PSK ServerHello");
                                    _test_case.assert(decline_client_protection.get_secrets().get(tls_secret_t::resumption_early).empty(), function_name,
                                                      "client discards the rejected ticket PSK");
                                    _test_case.assert(server_early_secret == decline_client_protection.get_secrets().get(tls_secret_t::early_secret), function_name,
                                                      "client and server derive the same non-PSK Early Secret");
                                }
                            }
                        }
                    }
                    // Ownership is transferred to decline_server_hello_record
                    // by operator<<; do not release the shared handshake here.
                }
            }
        }
    }
}

static void test_tls13_hrr_rejects_invalid_early_data_acceptance(const char* function_name) {
    // Scenario under test: client rejects EncryptedExtensions early_data when selected_identity is not zero.
    // Action: parse an EncryptedExtensions early_data acceptance with selected_identity one.
    // Expected: queue fatal illegal_parameter, clear the provisional ticket, and disable 0-RTT protection.
    // A malformed server acceptance of 0-RTT must not leave the client
    // direction protected with early-data keys after the fatal alert.
    {
        tls_session invalid_early_data_client;
        invalid_early_data_client.set_type(session_type_t::tls);
        auto& invalid_early_data_protection = invalid_early_data_client.get_tls_protection();
        invalid_early_data_protection.set_tls_version(tls1_3);
        invalid_early_data_protection.set_cipher_suite(0x1301);
        invalid_early_data_protection.set_flow(tls_flow_t::zero_rtt);
        invalid_early_data_client.get_keyvalue().set(session_server_psk_selected_identity, 1);
        invalid_early_data_client.get_keyvalue().set(session_server_psk_key_exchange_mode, 0);
        invalid_early_data_client.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1301);
        auto& invalid_early_state = invalid_early_data_client.get_session_info(from_server).get_keyvalue();
        invalid_early_state.set(session_early_data_offered, 1);
        invalid_early_state.set(session_early_data_limit, 4096);
        tls_resumption_ticket invalid_early_ticket;
        invalid_early_ticket.identity = {0xaa};
        invalid_early_ticket.version = static_cast<uint16>(tls1_3);
        invalid_early_ticket.cipher_suite = 0x1301;
        invalid_early_ticket.max_early_data_size = 4096;
        invalid_early_data_client.set_early_data_ticket(invalid_early_ticket);
        invalid_early_data_client.get_session_info(from_client).begin_protection();

        tls_handshake_encrypted_extensions invalid_early_extensions(&invalid_early_data_client);
        const binary_t invalid_early_extensions_wire = {0x08, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x2a, 0x00, 0x00};
        size_t invalid_early_extensions_pos = 0;
        return_t invalid_early_extensions_ret =
            invalid_early_extensions.read(from_server, invalid_early_extensions_wire.data(), invalid_early_extensions_wire.size(), invalid_early_extensions_pos);
        _test_case.assert(errorcode_t::handshake_failure == invalid_early_extensions_ret, function_name,
                          "reject EncryptedExtensions early_data when the server did not select identity zero");
        size_t invalid_early_extensions_alert_count = test_count_fatal_alert(invalid_early_data_client, from_server, tls_alertdesc_t::illegal_parameter);
        _test_case.assert(1 == invalid_early_extensions_alert_count, function_name,
                          "report fatal illegal_parameter for an invalid EncryptedExtensions early_data acceptance");
        _test_case.assert(tls_flow_t::one_rtt == invalid_early_data_protection.get_flow(), function_name,
                          "leave zero_rtt after rejecting an invalid EncryptedExtensions early_data acceptance");
        _test_case.assert(0 == invalid_early_state.get(session_early_data_limit), function_name, "clear the early-data allowance after rejecting the server acceptance");
        _test_case.assert(0 == invalid_early_state.get(session_early_data_accepted), function_name, "keep early data unaccepted after rejecting the server acceptance");
        _test_case.assert(invalid_early_data_client.get_early_data_ticket().identity.empty(), function_name,
                          "clear the provisional early-data ticket after rejecting the server acceptance");
        _test_case.assert(false == invalid_early_data_client.get_session_info(from_client).apply_protection(), function_name,
                          "disable early-data record protection after rejecting the server acceptance");
    }
}

static void test_tls13_clienthello2_psk_binder_hrr_roundtrip() {
    // Scenario under test: TLS 1.3 ClientHello1-HRR-ClientHello2 PSK binder integration.
    // Action: initialize a provisional SHA-256 transcript hash.
    // Expected: replace the provisional SHA-256 transcript hash with SHA-384.
    _test_case.begin("TLS 1.3 ClientHello1-HRR-ClientHello2 PSK binder integration");

    constexpr uint32 ticket_age_add = 0x10203040;
    constexpr uint32 ticket_lifetime = 3600;
    const binary_t ticket = {0x11, 0x22, 0x33};
    const binary_t resumption_psk(32, 0x22);
    const binary_t hrr_random = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

    return_t ret = errorcode_t::success;

    test_tls13_hrr_transcript_hash_switch();

    auto configure_resumption = [&](tls_session& session) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        // Model a cached session whose original handshake completed. After
        // HRR, ServerHello processing uses this flag to restore the resumption
        // flow instead of treating ClientHello2 as a fresh full handshake.
        session.get_keyvalue().set(session_handshake_finished, 1);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);

        uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        auto& ticket_kv = session.get_session_info(from_server).get_keyvalue();
        ticket_kv.set(session_ticket_lifetime, ticket_lifetime);
        ticket_kv.set(session_ticket_age_add, ticket_age_add);
        ticket_kv.set(session_ticket_timestamp, now_ms - 25);
        ticket_kv.set(session_ticket_max_early_data_size, 4096);
        protection.get_secrets().assign(tls_secret_t::new_session_ticket, ticket);
        protection.get_secrets().assign(tls_secret_t::resumption_early, resumption_psk);
    };

    test_tls13_hrr_declines_unoffered_cached_psk(__FUNCTION__, configure_resumption);
    test_tls13_hrr_declines_verified_psk_candidate(__FUNCTION__, configure_resumption);

    tls_session client;
    configure_resumption(client);
    client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);
    client.get_session_info(from_server).get_keyvalue().set(session_early_data_limit, 4096);

    // ClientHello1 offers the group but deliberately omits its key share,
    // forcing the server to select the group through a real HelloRetryRequest.
    auto client_hello1 = new tls_handshake_client_hello(&client);
    client_hello1->add_ciphersuite(0x1301);

    auto supported_versions1 = new tls_extension_client_supported_versions(client_hello1);
    supported_versions1->add(tls1_3);
    client_hello1->get_extensions().add(supported_versions1);

    auto supported_groups1 = new tls_extension_supported_groups(client_hello1);
    supported_groups1->add("x25519");
    client_hello1->get_extensions().add(supported_groups1);

    auto psk_modes1 = new tls_extension_psk_key_exchange_modes(client_hello1);
    psk_modes1->add(0);  // psk_ke
    psk_modes1->add(1);  // psk_dhe_ke
    client_hello1->get_extensions().add(psk_modes1);

    client_hello1->get_extensions().add(new tls_extension_early_data(client_hello1));

    auto psk1 = new tls_extension_client_psk(client_hello1);
    client_hello1->get_extensions().add(psk1);

    tls_record_handshake client_hello1_record(&client);
    client_hello1_record << client_hello1;
    binary_t client_hello1_wire;
    ret = client_hello1_record.write(from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "serialize PSK ClientHello1 without a key share");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the PSK identity count from ClientHello1");

    tls_session server;
    configure_resumption(server);
    // Observe the two ClientHello-derived status values on this exact server
    // session. The callback filters by owner and key, so unrelated session maps
    // and unrelated key-value activity remain silent.
    server.get_keyvalue().set_hook(trace_tls_session_keyvalue_hook, &server.get_keyvalue());
    server.set_early_data_discard_limit(32);
    // ClientHello1 intentionally has no key_share, so the server must
    // explicitly select an offered group when constructing the HRR.
    auto tlsadvisor = tls_advisor::get_instance();
    server.get_keyvalue().set(session_conf_enforce_key_share_group, static_cast<uint16>(tlsadvisor->valueof_group("x25519")));
    tls_records server_clienthello1_records;
    ret = server_clienthello1_records.read(&server, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "server validates the ClientHello1 PSK binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the PSK identity count received in ClientHello1");
    _test_case.assert(1 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered_initial), __FUNCTION__,
                      "record the actual ClientHello1 early_data offer on the server");
    _test_case.assert(1 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "retain the current early_data offer while processing ClientHello1");

    // Build and serialize a genuine HRR-form ServerHello. The server key_share
    // extension emits only selected_group because ClientHello1 had no share.
    auto server_hello = new tls_handshake_server_hello(&server);
    server_hello->set_random(hrr_random);
    ret = server_hello->set_cipher_suite(0x1301);
    _test_case.test(ret, __FUNCTION__, "select the TLS 1.3 cipher suite for HRR");
    if (errorcode_t::success != ret) {
        server_hello->release();
        return;
    }

    auto supported_versions2 = new tls_extension_server_supported_versions(server_hello);
    supported_versions2->set(tls1_3);
    server_hello->get_extensions().add(supported_versions2);

    auto server_key_share = new tls_extension_server_key_share(server_hello);
    ret = server_key_share->add_keyshare();
    _test_case.test(ret, __FUNCTION__, "select x25519 for the retry");
    if (errorcode_t::success != ret) {
        server_hello->release();
        return;
    }
    server_hello->get_extensions().add(server_key_share);

    tls_record_handshake server_hello_record(&server);
    server_hello_record << server_hello;
    binary_t hrr_wire;
    ret = server_hello_record.write(from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "serialize HelloRetryRequest from the live ClientHello1 state");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_flow_t::hello_retry_request == server.get_tls_protection().get_flow(), __FUNCTION__,
                      "server enters the HRR flow after processing ClientHello1");

    tls_records client_hrr_records;
    ret = client_hrr_records.read(&client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "client processes the actual HelloRetryRequest message");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_flow_t::hello_retry_request == client.get_tls_protection().get_flow(), __FUNCTION__, "client enters the HRR flow after receiving the retry");
    _test_case.assert(false == client.get_session_info(from_client).apply_protection(), __FUNCTION__,
                      "disable client-to-server early-data record protection after accepting HRR");

    // The server learned the initial offer from the serialized ClientHello1;
    // retain that state while skipping records already in flight after HRR.
    binary_t in_flight_early_data_record{0x17, 0x03, 0x03, 0x00, 0x10};
    in_flight_early_data_record.insert(in_flight_early_data_record.end(), 16, 0xaa);
    tls_records early_data_before_clienthello2_records;
    ret = early_data_before_clienthello2_records.read(&server, from_client, in_flight_early_data_record);
    _test_case.test(ret, __FUNCTION__, "skip an in-flight ClientHello1 early-data record after HRR and before ClientHello2");
    _test_case.assert(16 == server.get_session_info(from_server).get_keyvalue().get(session_early_data_discarded), __FUNCTION__,
                      "count pre-ClientHello2 rejected ciphertext against the configured HRR skip budget");

    // ClientHello2 carries the requested key share and a binder over the
    // transcript produced by processing the real ClientHello1 and HRR messages.
    auto client_hello2 = new tls_handshake_client_hello(&client);
    client_hello2->add_ciphersuite(0x1301);

    auto supported_versions3 = new tls_extension_client_supported_versions(client_hello2);
    supported_versions3->add(tls1_3);
    client_hello2->get_extensions().add(supported_versions3);

    auto supported_groups2 = new tls_extension_supported_groups(client_hello2);
    supported_groups2->add("x25519");
    client_hello2->get_extensions().add(supported_groups2);

    auto client_key_share = new tls_extension_client_key_share(client_hello2);
    client_hello2->get_extensions().add(client_key_share);

    auto psk_modes2 = new tls_extension_psk_key_exchange_modes(client_hello2);
    psk_modes2->add(0);  // psk_ke
    psk_modes2->add(1);  // psk_dhe_ke
    client_hello2->get_extensions().add(psk_modes2);

    // Even if the caller attempts to carry early_data into ClientHello2, the
    // writer must suppress it after HRR.
    client_hello2->get_extensions().add(new tls_extension_early_data(client_hello2));

    auto psk2 = new tls_extension_client_psk(client_hello2);
    client_hello2->get_extensions().add(psk2);

    // Probe the HRR-selected group separately so a key-generation failure
    // is distinguishable from the subsequent ClientHello2 binder serialization.
    uint16 retry_group = t_narrow_cast(client.get_session_info(from_server).get_keyvalue().get(session_key_share_group));
    _test_case.assert(static_cast<uint16>(tlsadvisor->valueof_group("x25519")) == retry_group, __FUNCTION__, "retain the HRR-selected x25519 group on the client");
    ret = client_key_share->add(static_cast<tls_group_t>(retry_group));
    _test_case.test(ret, __FUNCTION__, "generate the ClientHello2 key share for the HRR-selected group");
    if (errorcode_t::success != ret) {
        return;
    }
    client_key_share->clear();

    tls_record_handshake client_hello2_record(&client);
    client_hello2_record << client_hello2;
    binary_t client_hello2_wire;
    ret = client_hello2_record.write(from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 with the selected key share and HRR binder");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(1 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "refresh the PSK identity count from ClientHello2 after HRR");

    auto prepare_retry_server = [&](tls_session& retry_server, binary_t& retry_wire) -> return_t {
        configure_resumption(retry_server);
        retry_server.get_keyvalue().set(session_conf_enforce_key_share_group, static_cast<uint16>(tlsadvisor->valueof_group("x25519")));
        tls_records initial_clienthello_records;
        return_t prepare_ret = initial_clienthello_records.read(&retry_server, from_client, client_hello1_wire);
        if (errorcode_t::success != prepare_ret) {
            return prepare_ret;
        }

        auto retry_hello = new tls_handshake_server_hello(&retry_server);
        retry_hello->set_random(hrr_random);
        prepare_ret = retry_hello->set_cipher_suite(0x1301);
        if (errorcode_t::success != prepare_ret) {
            retry_hello->release();
            return prepare_ret;
        }
        auto retry_versions = new tls_extension_server_supported_versions(retry_hello);
        retry_versions->set(tls1_3);
        retry_hello->get_extensions().add(retry_versions);
        auto retry_key_share = new tls_extension_server_key_share(retry_hello);
        prepare_ret = retry_key_share->add_keyshare();
        if (errorcode_t::success != prepare_ret) {
            retry_hello->release();
            return prepare_ret;
        }
        retry_hello->get_extensions().add(retry_key_share);
        tls_record_handshake retry_record(&retry_server);
        retry_record << retry_hello;
        return retry_record.write(from_server, retry_wire);
    };

    test_tls13_hrr_early_data_discard_budget(client_hello2_wire, in_flight_early_data_record, prepare_retry_server);

    size_t client_hello2_early_data_pos = 0;
    size_t client_hello2_early_data_size = 0;
    bool client_hello2_has_early_data = test_find_client_hello_extension(client_hello2_wire, 0x002a, client_hello2_early_data_pos, client_hello2_early_data_size);
    _test_case.assert(false == client_hello2_has_early_data, __FUNCTION__, "omit early_data from ClientHello2 after HRR");
    _test_case.assert(0 == client.get_session_info(from_server).get_keyvalue().get(session_early_data_offered), __FUNCTION__,
                      "do not mark early data as offered when its ClientHello2 extension is suppressed");

    test_tls13_hrr_rejects_changed_psk_identity(client_hello2_wire, prepare_retry_server);

    test_tls13_hrr_rejects_changed_psk_modes(client_hello1_wire, prepare_retry_server, configure_resumption);

    test_tls13_hrr_psk_decline_after_binder(client_hello1_wire, prepare_retry_server, configure_resumption);

    test_tls13_second_hrr_rejected(client_hello1_wire, hrr_wire, client_hello2_wire, configure_resumption);

    binary_t selected_server_hello_wire;
    test_tls13_hrr_selects_psk_and_completes_finished(server, client, client_hello1_wire, client_hello2_wire, hrr_wire, in_flight_early_data_record,
                                                      selected_server_hello_wire);

    test_tls13_hrr_rejects_out_of_range_selected_identity(client_hello1_wire, hrr_wire, client_hello2_wire, selected_server_hello_wire, hrr_random, configure_resumption);

    test_tls13_hrr_rejects_invalid_early_data_acceptance(__FUNCTION__);
}

static void test_tls13_hrr_mixed_hash_selected_identity_mapping() {
    // Scenario: filter mixed-hash cached tickets after HRR and select a later compatible identity.
    // Action: offer SHA-256 and SHA-384 tickets, then process ClientHello2 under the HRR-selected SHA-256 suite.
    // Expected: selected_identity uses ClientHello2 wire indexing and both peers restore the same ticket.
    _test_case.begin("TLS 1.3 HRR mixed-hash filtering preserves selected_identity wire index");

    const uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket sha256_first;
    sha256_first.identity = {0xa1};
    sha256_first.psk = binary_t(32, 0x31);
    sha256_first.version = static_cast<uint16>(tls1_3);
    sha256_first.cipher_suite = 0x1301;
    sha256_first.lifetime = 3600;
    sha256_first.timestamp = now_ms - 100;

    tls_resumption_ticket sha384_middle;
    sha384_middle.identity = {0xb2};
    sha384_middle.psk = binary_t(48, 0x42);
    sha384_middle.version = static_cast<uint16>(tls1_3);
    sha384_middle.cipher_suite = 0x1302;
    sha384_middle.lifetime = 3600;
    sha384_middle.timestamp = now_ms - 100;

    tls_resumption_ticket sha256_last = sha256_first;
    sha256_last.identity = {0xc3};
    sha256_last.psk = binary_t(32, 0x53);
    sha256_last.cipher_suite = 0x1303;

    auto configure_resumption = [&](tls_session& session) {
        session.set_type(session_type_t::tls);
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls1_3);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls1_3);
        session.update_session_status(session_status_server_finished);
        session.update_session_status(session_status_client_finished);
        session.get_keyvalue().set(session_handshake_finished, 1);
        session.get_session_info(from_client).set_status(tls_handshake_type_t::finished);
        session.get_session_info(from_server).set_status(tls_handshake_type_t::finished);
    };

    tls_session client;
    configure_resumption(client);
    client.store_resumption_ticket(sha256_first);
    client.store_resumption_ticket(sha384_middle);
    client.store_resumption_ticket(sha256_last);

    tls_session server;
    configure_resumption(server);
    // The server knows only the last SHA-256 ticket. The middle SHA-384
    // identity is unknown to it and cannot be classified from its cache.
    server.store_resumption_ticket(sha256_last);
    auto tlsadvisor = tls_advisor::get_instance();
    uint16 retry_group = static_cast<uint16>(tlsadvisor->valueof_group("x25519"));
    server.get_keyvalue().set(session_conf_enforce_key_share_group, retry_group);

    auto client_hello1 = new tls_handshake_client_hello(&client);
    client_hello1->add_ciphersuite(0x1301);
    client_hello1->add_ciphersuite(0x1302);
    client_hello1->add_ciphersuite(0x1303);
    auto versions1 = new tls_extension_client_supported_versions(client_hello1);
    versions1->add(tls1_3);
    client_hello1->get_extensions().add(versions1);
    auto groups1 = new tls_extension_supported_groups(client_hello1);
    groups1->add("x25519");
    client_hello1->get_extensions().add(groups1);
    auto modes1 = new tls_extension_psk_key_exchange_modes(client_hello1);
    modes1->add(1);  // psk_dhe_ke
    client_hello1->get_extensions().add(modes1);
    auto psk1 = new tls_extension_client_psk(client_hello1);
    client_hello1->get_extensions().add(psk1);

    tls_record_handshake client_hello1_record(&client);
    client_hello1_record << client_hello1;
    binary_t client_hello1_wire;
    return_t ret = client_hello1_record.write(from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello1 with SHA-256, SHA-384, and SHA-256 PSK identities");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(3 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record all three ClientHello1 PSK identities");

    tls_records server_clienthello1_records;
    ret = server_clienthello1_records.read(&server, from_client, client_hello1_wire);
    _test_case.test(ret, __FUNCTION__, "server verifies the binder for the third ClientHello1 identity");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(2 == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                      "select the third wire identity when it is the only cached PSK");

    const binary_t hrr_random = {0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};
    auto hrr = new tls_handshake_server_hello(&server);
    hrr->set_random(hrr_random);
    ret = hrr->set_cipher_suite(0x1303);
    _test_case.test(ret, __FUNCTION__, "select the SHA-256 HRR cipher suite");
    if (errorcode_t::success != ret) {
        hrr->release();
        return;
    }
    auto hrr_versions = new tls_extension_server_supported_versions(hrr);
    hrr_versions->set(tls1_3);
    hrr->get_extensions().add(hrr_versions);
    auto hrr_key_share = new tls_extension_server_key_share(hrr);
    ret = hrr_key_share->add_keyshare();
    _test_case.test(ret, __FUNCTION__, "select x25519 for the HRR key share");
    if (errorcode_t::success != ret) {
        hrr->release();
        return;
    }
    hrr->get_extensions().add(hrr_key_share);

    tls_record_handshake hrr_record(&server);
    hrr_record << hrr;
    binary_t hrr_wire;
    ret = hrr_record.write(from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "serialize the HRR with the selected SHA-256 suite");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_records client_hrr_records;
    ret = client_hrr_records.read(&client, from_server, hrr_wire);
    _test_case.test(ret, __FUNCTION__, "client processes the SHA-256 HRR");
    if (errorcode_t::success != ret) {
        return;
    }
    _test_case.assert(tls_flow_t::hello_retry_request == client.get_tls_protection().get_flow(), __FUNCTION__, "enter HRR flow before constructing ClientHello2");

    auto client_hello2 = new tls_handshake_client_hello(&client);
    client_hello2->add_ciphersuite(0x1301);
    client_hello2->add_ciphersuite(0x1302);
    client_hello2->add_ciphersuite(0x1303);
    auto versions2 = new tls_extension_client_supported_versions(client_hello2);
    versions2->add(tls1_3);
    client_hello2->get_extensions().add(versions2);
    auto groups2 = new tls_extension_supported_groups(client_hello2);
    groups2->add("x25519");
    client_hello2->get_extensions().add(groups2);
    auto key_share2 = new tls_extension_client_key_share(client_hello2);
    client_hello2->get_extensions().add(key_share2);
    auto modes2 = new tls_extension_psk_key_exchange_modes(client_hello2);
    modes2->add(1);  // psk_dhe_ke
    client_hello2->get_extensions().add(modes2);
    auto psk2 = new tls_extension_client_psk(client_hello2);
    client_hello2->get_extensions().add(psk2);

    ret = key_share2->add(static_cast<tls_group_t>(retry_group));
    _test_case.test(ret, __FUNCTION__, "generate the ClientHello2 key share requested by HRR");
    if (errorcode_t::success != ret) {
        return;
    }
    key_share2->clear();

    tls_record_handshake client_hello2_record(&client);
    client_hello2_record << client_hello2;
    binary_t client_hello2_wire;
    ret = client_hello2_record.write(from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 after filtering the incompatible SHA-384 identity");
    if (errorcode_t::success != ret) {
        return;
    }
    const auto& clienthello2_identities = psk2->get_identities();
    _test_case.assert(2 == clienthello2_identities.size(), __FUNCTION__, "retain exactly two SHA-256 identities in ClientHello2");
    if (2 == clienthello2_identities.size()) {
        _test_case.assert(sha256_first.identity == clienthello2_identities[0], __FUNCTION__, "retain the first SHA-256 identity at wire index zero");
        _test_case.assert(sha256_last.identity == clienthello2_identities[1], __FUNCTION__, "move the later SHA-256 identity to wire index one after filtering");
    }
    _test_case.assert(2 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the filtered ClientHello2 identity count on the client");
    const auto offered_tickets = client.get_offered_resumption_tickets();
    _test_case.assert(2 == offered_tickets.size(), __FUNCTION__, "retain the matching ClientHello2 ticket snapshot for ServerHello validation");
    if (2 == offered_tickets.size()) {
        _test_case.assert(sha256_first.identity == offered_tickets[0].identity, __FUNCTION__, "map ClientHello2 identity zero to its original ticket");
        _test_case.assert(sha256_last.identity == offered_tickets[1].identity, __FUNCTION__, "map ClientHello2 identity one to the later original ticket");
    }

    // The server-side SHA-384 ticket is now expired, while the client still
    // retains its valid copy and omits it from ClientHello2 because HRR fixed
    // the SHA-256 suite. Expiration cleanup must not depend on that identity
    // appearing in the filtered ClientHello2 offer.
    tls_resumption_ticket expired_hash_incompatible_ticket = sha384_middle;
    expired_hash_incompatible_ticket.timestamp = now_ms - (static_cast<uint64>(expired_hash_incompatible_ticket.lifetime) * 1000 + 1);
    server.store_resumption_ticket(expired_hash_incompatible_ticket);

    tls_records server_clienthello2_records;
    ret = server_clienthello2_records.read(&server, from_client, client_hello2_wire);
    _test_case.test(ret, __FUNCTION__, "server accepts filtered ClientHello2 and verifies the binder for the remaining second identity");
    if (errorcode_t::success == ret) {
        _test_case.assert(2 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the two identities actually present in ClientHello2");
        _test_case.assert(1 == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                          "report selected_identity one using ClientHello2 wire indexing, not the ClientHello1 index");
        _test_case.assert(0x1303 == server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                          "retain the selected ticket's cipher suite after the HRR");
        binary_t expected_early_secret;
        return_t secret_ret = server.get_tls_protection().calc_resumption_early_secret(sha256_last.psk, expected_early_secret);
        _test_case.test(secret_ret, __FUNCTION__, "derive the expected Early Secret from the selected third ticket");
        if (errorcode_t::success == secret_ret) {
            _test_case.assert(expected_early_secret == server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early), __FUNCTION__,
                              "derive the Early Secret from the ticket at ClientHello2 wire index one");
        }
        const auto remaining_server_tickets = server.get_resumption_tickets();
        _test_case.assert(1 == remaining_server_tickets.size(), __FUNCTION__, "retire the expired SHA-384 ticket even though ClientHello2 omitted its identity");
        if (1 == remaining_server_tickets.size()) {
            _test_case.assert(sha256_last.identity == remaining_server_tickets.front().identity, __FUNCTION__,
                              "retain the valid SHA-256 ticket selected by ClientHello2");
        }

        // Complete the mixed-cache case through the final ServerHello. The
        // selected_identity must address ClientHello2's filtered offer on both
        // peers, so the client restores the same original ticket as the server.
        auto final_server_hello = new tls_handshake_server_hello(&server);
        return_t final_ret = final_server_hello->set_cipher_suite(0x1303);
        _test_case.test(final_ret, __FUNCTION__, "select the SHA-256 suite fixed by HRR in the final ServerHello");
        if (errorcode_t::success == final_ret) {
            auto final_versions = new tls_extension_server_supported_versions(final_server_hello);
            final_versions->set(tls1_3);
            final_server_hello->get_extensions().add(final_versions);

            auto final_key_share = new tls_extension_server_key_share(final_server_hello);
            final_ret = final_key_share->add_keyshare();
            _test_case.test(final_ret, __FUNCTION__, "create the final ServerHello key share for the HRR-selected group");
            if (errorcode_t::success == final_ret) {
                final_server_hello->get_extensions().add(final_key_share);
                auto final_psk = new tls_extension_server_psk(final_server_hello);
                final_psk->set_selected_identity(1);
                final_server_hello->get_extensions().add(final_psk);

                tls_record_handshake final_server_hello_record(&server);
                final_server_hello_record << final_server_hello;
                binary_t final_server_hello_wire;
                final_ret = final_server_hello_record.write(from_server, final_server_hello_wire);
                _test_case.test(final_ret, __FUNCTION__, "serialize the final ServerHello selecting ClientHello2 identity one");
                if (errorcode_t::success == final_ret) {
                    tls_records client_server_hello_records;
                    final_ret = client_server_hello_records.read(&client, from_server, final_server_hello_wire);
                    _test_case.test(final_ret, __FUNCTION__, "client accepts the final ServerHello selecting the filtered second ticket");
                    if (errorcode_t::success == final_ret) {
                        _test_case.assert(1 == client.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                          "retain selected_identity one from the ClientHello2 wire vector");
                        _test_case.assert(1 == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                                          "server and client agree on ClientHello2 selected_identity one");
                        _test_case.assert(server.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early) ==
                                              client.get_tls_protection().get_secrets().get(tls_secret_t::resumption_early),
                                          __FUNCTION__, "derive the same resumption Early Secret from the filtered second identity");
                        _test_case.assert(client.get_offered_resumption_tickets().empty(), __FUNCTION__,
                                          "consume the ClientHello2 ticket snapshot after final ServerHello selection");
                    }
                }
            }
        }
    }
}

static void test_tls13_client_suppresses_incompatible_psks_after_hrr() {
    // Scenario: no cached PSK matches the cipher-suite hash selected by HRR.
    // Action: serialize ClientHello2 and process it on a server that received the original PSK offer.
    // Expected: omit pre_shared_key entirely and accept the reduced ClientHello2 as an ordered subset.
    _test_case.begin("TLS 1.3 ClientHello2 suppresses PSK when every cached ticket has an incompatible hash");

    const uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    tls_resumption_ticket sha384_ticket;
    sha384_ticket.identity = {0xb2};
    sha384_ticket.psk = binary_t(48, 0x42);
    sha384_ticket.version = static_cast<uint16>(tls1_3);
    sha384_ticket.cipher_suite = 0x1302;
    sha384_ticket.lifetime = 3600;
    sha384_ticket.timestamp = now_ms - 100;

    tls_session client;
    client.set_type(session_type_t::tls);
    auto& protection = client.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1301);
    protection.set_flow(tls_flow_t::hello_retry_request);
    client.get_keyvalue().set(session_tls_version, tls1_3);
    client.store_resumption_ticket(sha384_ticket);

    auto tlsadvisor = tls_advisor::get_instance();
    uint16 retry_group = static_cast<uint16>(tlsadvisor->valueof_group("x25519"));
    client.get_session_info(from_server).get_keyvalue().set(session_key_share_group, retry_group);

    auto hello = new tls_handshake_client_hello(&client);
    hello->add_ciphersuite(0x1301);
    auto versions = new tls_extension_client_supported_versions(hello);
    versions->add(tls1_3);
    hello->get_extensions().add(versions);
    auto groups = new tls_extension_supported_groups(hello);
    groups->add("x25519");
    hello->get_extensions().add(groups);
    auto key_share = new tls_extension_client_key_share(hello);
    hello->get_extensions().add(key_share);
    auto modes = new tls_extension_psk_key_exchange_modes(hello);
    modes->add(1);  // psk_dhe_ke
    hello->get_extensions().add(modes);
    auto psk = new tls_extension_client_psk(hello);
    hello->get_extensions().add(psk);

    // This focused test starts directly in HRR flow rather than serializing
    // ClientHello1 and receiving an HRR. Seed the two ClientHello1 snapshots
    // that the real exchange would have retained, so ClientHello2 validation
    // compares its unchanged psk_key_exchange_modes and its (now empty) PSK
    // identity list against a valid original offer.
    binary_t original_psk_modes_wire;
    return_t snapshot_ret = modes->write(from_client, original_psk_modes_wire);
    _test_case.test(snapshot_ret, __FUNCTION__, "encode the original ClientHello1 PSK key-exchange modes");
    if (errorcode_t::success != snapshot_ret) {
        return;
    }
    protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, std::move(original_psk_modes_wire));
    protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, binary_t{0x00, 0x01, 0xb2});

    tls_record_handshake record(&client);
    record << hello;
    binary_t wire;
    return_t ret = record.write(from_client, wire);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 after the HRR-selected SHA-256 suite");
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(psk->is_suppressed(), __FUNCTION__, "suppress PSK when every cached ticket uses a different hash from the HRR suite");
    _test_case.assert(tls_flow_t::hello_retry_request == protection.get_flow(), __FUNCTION__, "retain the HRR transcript flow when falling back to a full handshake");
    _test_case.assert(0 == client.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__,
                      "record no ClientHello2 PSK identities after suppressing the extension");
    _test_case.assert(client.get_offered_resumption_tickets().empty(), __FUNCTION__, "retain no offered-ticket snapshot when ClientHello2 omits PSK");

    // Parse the serialized ClientHello extension vector and ensure pre_shared_key
    // was omitted rather than emitted with an empty identities vector.
    size_t pos = 5 + sizeof(tls_handshake_t) + 2 + 32;
    if (pos >= wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate the ClientHello session ID");
        return;
    }
    uint8 session_id_length = wire[pos++];
    if (session_id_length > wire.size() - pos) {
        _test_case.assert(false, __FUNCTION__, "bound the ClientHello session ID");
        return;
    }
    pos += session_id_length;
    if (pos + 2 > wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate the ClientHello cipher-suite vector");
        return;
    }
    uint16 cipher_suites_length = test_read_u16(wire, pos);
    pos += 2;
    if (cipher_suites_length > wire.size() - pos) {
        _test_case.assert(false, __FUNCTION__, "bound the ClientHello cipher-suite vector");
        return;
    }
    pos += cipher_suites_length;
    if (pos >= wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate the ClientHello compression-method vector");
        return;
    }
    uint8 compression_methods_length = wire[pos++];
    if (compression_methods_length > wire.size() - pos) {
        _test_case.assert(false, __FUNCTION__, "bound the ClientHello compression-method vector");
        return;
    }
    pos += compression_methods_length;
    if (pos + 2 > wire.size()) {
        _test_case.assert(false, __FUNCTION__, "locate the ClientHello extension vector");
        return;
    }
    uint16 extensions_length = test_read_u16(wire, pos);
    pos += 2;
    if (extensions_length != wire.size() - pos) {
        _test_case.assert(false, __FUNCTION__, "validate the ClientHello extension-vector boundary");
        return;
    }

    bool psk_extension_present = false;
    const size_t extensions_end = pos + extensions_length;
    while (pos < extensions_end) {
        if (extensions_end - pos < 4) {
            _test_case.assert(false, __FUNCTION__, "parse a complete ClientHello extension header");
            return;
        }
        uint16 extension_type = test_read_u16(wire, pos);
        uint16 extension_length = test_read_u16(wire, pos + 2);
        pos += 4;
        if (extension_length > extensions_end - pos) {
            _test_case.assert(false, __FUNCTION__, "bound a ClientHello extension body");
            return;
        }
        psk_extension_present = psk_extension_present || (static_cast<uint16>(tls_extension_type_t::pre_shared_key) == extension_type);
        pos += extension_length;
    }
    _test_case.assert(false == psk_extension_present, __FUNCTION__, "omit pre_shared_key entirely when no HRR-compatible ticket remains");

    // Exercise the peer's receive path as well. ClientHello2 may legally omit
    // pre_shared_key after HRR when none of the cached identities matches the
    // HRR-selected cipher-suite hash; the server must accept the reduced offer
    // as an ordered subset of ClientHello1.
    tls_session server;
    server.set_type(session_type_t::tls);
    auto& server_protection = server.get_tls_protection();
    server_protection.set_tls_version(tls1_3);
    server_protection.set_cipher_suite(0x1301);
    server_protection.set_flow(tls_flow_t::hello_retry_request);
    server.update_session_status(session_status_hello_retry_request);
    server.get_session_info(from_server).get_keyvalue().set(session_key_share_group, retry_group);
    server.get_keyvalue().set(session_client_post_handshake_auth, 0);
    server.get_keyvalue().set(session_server_psk_selected_identity, 0);
    server.get_keyvalue().set(session_server_psk_ticket_cipher_suite, 0x1302);
    server_protection.get_secrets().assign(tls_secret_t::client_hello_psk_modes, protection.get_secrets().get(tls_secret_t::client_hello_psk_modes));
    server_protection.get_secrets().assign(tls_secret_t::client_hello_psk_identities, binary_t{0x00, 0x01, 0xb2});

    tls_records server_records;
    ret = server_records.read(&server, from_client, wire);
    _test_case.test(ret, __FUNCTION__, "server accepts ClientHello2 without pre_shared_key after HRR");
    if (errorcode_t::success == ret) {
        _test_case.assert(tls_flow_t::hello_retry_request == server_protection.get_flow(), __FUNCTION__, "preserve HRR transcript flow when ClientHello2 omits PSK");
        _test_case.assert(0 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record zero PSK identities from the received ClientHello2");
        _test_case.assert(0xffff == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__,
                          "clear the provisional PSK identity when ClientHello2 omits the extension");
        _test_case.assert(0 == server.get_keyvalue().get(session_server_psk_ticket_cipher_suite), __FUNCTION__,
                          "clear the provisional ticket cipher-suite metadata when ClientHello2 omits PSK");
    }
}

static void test_tls13_clienthello2_can_remove_unknown_psk_identity() {
    // Scenario: ClientHello2 removes an unknown PSK identity after HRR.
    // Action: retain the compatible known identities and validate the resulting ordered subset.
    // Expected: accept ClientHello2 and record only the identities actually present on the wire.
    _test_case.begin("TLS 1.3 ClientHello2 may remove an unknown PSK identity after HRR");

    class client_hello_postprocess_probe : public tls_handshake_client_hello {
       public:
        explicit client_hello_postprocess_probe(tls_session* session) : tls_handshake_client_hello(session) {}
        return_t run_postprocess(tls_direction_t dir, tls_io_operation_t opdir, const byte_t* stream, size_t size) { return do_postprocess(dir, opdir, stream, size); }
    };

    tls_session server;
    server.set_type(session_type_t::tls);
    auto& protection = server.get_tls_protection();
    protection.set_tls_version(tls1_3);
    protection.set_cipher_suite(0x1303);
    protection.set_flow(tls_flow_t::hello_retry_request);
    server.update_session_status(session_status_hello_retry_request);
    server.get_session_info(from_server).get_keyvalue().set(session_key_share_group, t_underlying(tls_group_t::unknown));
    server.get_keyvalue().set(session_client_post_handshake_auth, 0);

    // ClientHello1 offered A, B, C. The server has A and C, but B is an
    // unknown SHA-384 PSK which the client removes after a SHA-256 HRR.
    binary_t original_identities = {0x00, 0x01, 0xa1, 0x00, 0x01, 0xb2, 0x00, 0x01, 0xc3};
    binary_t original_modes_wire = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
    auto& secrets = protection.get_secrets();
    secrets.assign(tls_secret_t::client_hello_psk_identities, original_identities);
    secrets.assign(tls_secret_t::client_hello_psk_modes, original_modes_wire);

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket first_ticket;
    first_ticket.identity = {0xa1};
    first_ticket.psk = binary_t(32, 0x31);
    first_ticket.version = static_cast<uint16>(tls1_3);
    first_ticket.cipher_suite = 0x1301;
    first_ticket.lifetime = 3600;
    first_ticket.timestamp = now_ms - 100;
    server.store_resumption_ticket(first_ticket);

    tls_resumption_ticket last_ticket = first_ticket;
    last_ticket.identity = {0xc3};
    last_ticket.psk = binary_t(32, 0x33);
    last_ticket.cipher_suite = 0x1303;
    server.store_resumption_ticket(last_ticket);

    client_hello_postprocess_probe client_hello(&server);
    client_hello.add_ciphersuite(0x1303);
    auto modes = new tls_extension_psk_key_exchange_modes(&client_hello);
    modes->add(1);  // psk_dhe_ke
    client_hello.get_extensions().add(modes);
    auto psk = new tls_extension_client_psk(&client_hello);
    client_hello.get_extensions().add(psk);

    binary_t psk_wire;
    return_t ret = psk->write(from_client, psk_wire);
    _test_case.test(ret, __FUNCTION__, "prepare the ClientHello2 PSK identities retained by the server cache");
    if (errorcode_t::success != ret) {
        return;
    }
    const auto& current_identities = psk->get_identities();
    _test_case.assert(2 == current_identities.size(), __FUNCTION__, "retain the two SHA-256 identities compatible with the HRR suite");
    if (2 == current_identities.size()) {
        _test_case.assert(first_ticket.identity == current_identities[0], __FUNCTION__, "preserve the first compatible identity");
        _test_case.assert(last_ticket.identity == current_identities[1], __FUNCTION__, "preserve the later compatible identity after removing the unknown middle PSK");
    }

    binary_t transcript_input(1024, 0);
    ret = client_hello.run_postprocess(from_client, tls_io_operation_t::read, transcript_input.data(), transcript_input.size());
    _test_case.assert(errorcode_t::success == ret, __FUNCTION__, "accept ClientHello2 as an ordered subset when the omitted PSK is unknown to the server");
    _test_case.assert(2 == server.get_keyvalue().get(session_client_psk_identity_count), __FUNCTION__, "record the actual ClientHello2 identity count after filtering");
    _test_case.assert((session_status_client_hello & server.get_session_status()) != 0, __FUNCTION__,
                      "commit ClientHello2 status after accepting the filtered identity list");
}

void testcase_gpt_psk_hrr_binder() {
    test_tls13_psk_binder_hrr_transcript();
    test_tls13_hrr_mixed_hash_selected_identity_mapping();
    test_tls13_client_suppresses_incompatible_psks_after_hrr();
    test_tls13_clienthello2_can_remove_unknown_psk_identity();
    test_tls13_hrr_transcript_hash_switch();
    test_tls13_post_hrr_zero_psk_fallback_handshake();
    test_tls13_clienthello2_psk_binder_hrr_roundtrip();
}
