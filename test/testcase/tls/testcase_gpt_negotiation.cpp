/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_negotiation.cpp
 * @author GPT
 * @desc   TLS version, cipher-suite, and downgrade negotiation tests.
 */

#include "testcase_gpt_common.hpp"

static void test_supported_versions_negative_paths() {
    test_client_supported_versions_vector("supported_versions vector length 2 boundary", 2, binary_t{0x03, 0x04}, true);
    test_client_supported_versions_vector("supported_versions vector length 0", 0, binary_t(), false);
    test_client_supported_versions_vector("supported_versions vector length 1", 1, binary_t{0x03}, false);
    test_client_supported_versions_vector("supported_versions odd vector length 3", 3, binary_t{0x03, 0x04, 0x03}, false);

    binary_t versions_254;
    for (uint16 i = 0; i < 127; ++i) {
        uint16 version = (uint16)(0x7f00 + i);
        versions_254.push_back((byte_t)(version >> 8));
        versions_254.push_back((byte_t)version);
    }
    test_client_supported_versions_vector("supported_versions vector length 254 boundary", 254, versions_254, true);

    binary_t versions_255(255, (byte_t)0x7f);
    test_client_supported_versions_vector("supported_versions vector length 255", 255, versions_255, false);
    test_client_supported_versions_vector("supported_versions declared length exceeds available bytes", 4, binary_t{0x03, 0x04}, false);
    test_client_supported_versions_vector("supported_versions has trailing bytes beyond declared vector", 2, binary_t{0x03, 0x04, 0x03, 0x04}, false);

    test_serverhello_unoffered_supported_version();
}

static void test_supported_versions_unknown_and_legacy_fallback() {
    // Scenario under test: supported_versions ignores unknown values and preserves TLS 1.2 fallback.
    // Action: construct mixed-version ClientHello.
    // Expected: write mixed known/unknown supported_versions.
    _test_case.begin("supported_versions ignores unknown values and preserves TLS 1.2 fallback");

    tls_session mixed_client;
    tls_session mixed_server;
    binary_t mixed_client_hello;
    return_t ret = test_client_supportedversion_clienthello(&mixed_client, tls_12, tls_13, mixed_client_hello);
    _test_case.test(ret, __FUNCTION__, "construct mixed-version ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Unknown versions surrounding known TLS 1.3 and TLS 1.2 values must be ignored.
    const binary_t mixed_versions{0x7f, 0x1c, 0x03, 0x04, 0x7f, 0x1d, 0x03, 0x03};
    bool rewritten = test_rewrite_client_hello_supported_versions(mixed_client_hello, (uint8)mixed_versions.size(), mixed_versions);
    _test_case.assert(rewritten, __FUNCTION__, "write mixed known/unknown supported_versions");
    if (false == rewritten) {
        return;
    }

    tls_records records;
    ret = records.read(&mixed_server, from_client, mixed_client_hello);
    _test_case.test(ret, __FUNCTION__, "parse mixed known/unknown supported_versions");
    if (errorcode_t::success != ret) {
        return;
    }

    tls_version_t selected = tls_version_t{};
    ret = test_client_supportedversion_serverhello(&mixed_server, tls_12, tls_13, selected);
    _test_case.test(ret, __FUNCTION__, "negotiate from mixed known/unknown versions");
    _test_case.assert(tls_13 == selected, __FUNCTION__, "select highest locally supported version offered by peer");

    tls_session unknown_client;
    tls_session unknown_server;
    binary_t unknown_client_hello;
    ret = test_client_supportedversion_clienthello(&unknown_client, tls_12, tls_13, unknown_client_hello);
    _test_case.test(ret, __FUNCTION__, "construct unknown-only ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    // Unknown values are ignored; with no mutually supported version, negotiation fails.
    const binary_t unknown_versions{0x7f, 0x1c, 0x7f, 0x1d};
    rewritten = test_rewrite_client_hello_supported_versions(unknown_client_hello, (uint8)unknown_versions.size(), unknown_versions);
    _test_case.assert(rewritten, __FUNCTION__, "write unknown-only supported_versions");
    if (false == rewritten) {
        return;
    }

    tls_records unknown_records;
    ret = unknown_records.read(&unknown_server, from_client, unknown_client_hello);
    _test_case.test(ret, __FUNCTION__, "parse unknown-only supported_versions");
    if (errorcode_t::success != ret) {
        return;
    }

    selected = tls_version_t{};
    ret = test_client_supportedversion_serverhello(&unknown_server, tls_12, tls_13, selected);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "fail when no mutually supported version remains");

    tls_session legacy_client;
    tls_session legacy_server;
    binary_t legacy_client_hello;
    ret = test_client_supportedversion_clienthello(&legacy_client, tls_12, tls_13, legacy_client_hello);
    _test_case.test(ret, __FUNCTION__, "construct ClientHello for legacy fallback");
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(0x0303 == test_read_u16(legacy_client_hello, 9), __FUNCTION__, "ClientHello legacy_version is TLS 1.2");
    bool removed = test_remove_client_hello_supported_versions(legacy_client_hello);
    _test_case.assert(removed, __FUNCTION__, "remove supported_versions extension");
    if (false == removed) {
        return;
    }

    tls_records legacy_records;
    ret = legacy_records.read(&legacy_server, from_client, legacy_client_hello);
    _test_case.test(ret, __FUNCTION__, "parse ClientHello without supported_versions");
    if (errorcode_t::success != ret) {
        return;
    }

    selected = tls_version_t{};
    ret = test_client_supportedversion_serverhello(&legacy_server, tls_12, tls_13, selected);
    _test_case.test(ret, __FUNCTION__, "negotiate using legacy_version fallback");
    _test_case.assert(tls_12 == selected, __FUNCTION__, "fall back to TLS 1.2 when supported_versions is absent");
}

static void test_psk_hash_does_not_override_cipher_suite_preference() {
    // Scenario under test: TLS 1.3 PSK hash mismatch does not override cipher-suite preference.
    // Action: negotiate with a verified SHA-256 PSK and SHA-384-first client preference.
    // Expected: preserve the client's first offered TLS 1.3 cipher suite even when its hash differs from the PSK.
    _test_case.begin("TLS 1.3 PSK hash mismatch does not override cipher-suite preference");

    auto run_case = [](bool psk_selected, uint16& selected_suite) -> return_t {
        tls_session session;
        auto& protection = session.get_tls_protection();
        auto& context = protection.get_protection_context();

        // The server follows the client's cipher-suite order. A PSK with a
        // different hash is declined later when composing ServerHello.
        context.add_cipher_suite(0x1302);
        context.add_cipher_suite(0x1301);
        context.add_supported_version(tls_13);

        const tls_cipher_suite_t* sha256_suite = tls_advisor::get_instance()->hintof_cipher_suite(0x1301);
        if (nullptr == sha256_suite) {
            return errorcode_t::not_found;
        }
        session.get_keyvalue().set(session_server_psk_selected_identity, psk_selected ? 0 : 0xffff);
        session.get_keyvalue().set(session_client_psk_hash, static_cast<uint16>(sha256_suite->mac));

        tls_version_t selected_version = tls_version_t{};
        return protection.negotiate(&session, tls_13, tls_13, selected_suite, selected_version);
    };

    uint16 selected_suite = 0;
    return_t ret = run_case(true, selected_suite);
    _test_case.test(ret, __FUNCTION__, "negotiate with a verified SHA-256 PSK and SHA-384-first client preference");
    _test_case.assert(0x1302 == selected_suite, __FUNCTION__, "preserve the client's first offered TLS 1.3 cipher suite even when its hash differs from the PSK");

    selected_suite = 0;
    ret = run_case(false, selected_suite);
    _test_case.test(ret, __FUNCTION__, "negotiate without a selected PSK");
    _test_case.assert(0x1302 == selected_suite, __FUNCTION__, "preserve ordinary client cipher-suite preference when no PSK was selected");
}

static void test_tls_downgrade_sentinel() {
    static const byte_t downgrade_tls12[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01};
    static const byte_t downgrade_tls11[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00};
    static const byte_t no_sentinel[8] = {0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5};

    // Scenario under test: TLS downgrade sentinel emission and validation.
    // Action: construct TLS 1.2 ServerHello after a TLS 1.3-capable ClientHello.
    // Expected: TLS 1.3 server emits DOWNGRD\\x01 in TLS 1.2 ServerHello.random.
    _test_case.begin("TLS downgrade sentinel emission and validation");

    {
        tls_session client;
        tls_session server;
        binary_t wire;
        return_t ret = test_build_tls12_serverhello(client, server, tls_12, tls_13, wire);
        _test_case.test(ret, __FUNCTION__, "construct TLS 1.2 ServerHello after a TLS 1.3-capable ClientHello");
        if (errorcode_t::success == ret) {
            bool marker_found = (wire.size() >= 43);
            bool random_prefix_preserved = marker_found;
            if (marker_found) {
                for (size_t i = 0; i < 8; ++i) {
                    marker_found = marker_found && (wire[35 + i] == downgrade_tls12[i]);
                }
                for (size_t i = 0; i < 24; ++i) {
                    random_prefix_preserved = random_prefix_preserved && (wire[11 + i] == 0x5a);
                }
            }
            _test_case.assert(marker_found, __FUNCTION__, "TLS 1.3 server emits DOWNGRD\\x01 in TLS 1.2 ServerHello.random");
            _test_case.assert(random_prefix_preserved, __FUNCTION__, "preserve the first 24 ServerHello.random bytes");
        }
    }

    {
        tls_session client;
        tls_session server;
        binary_t wire;
        return_t ret = test_build_tls12_serverhello(client, server, tls_12, tls_13, wire);
        _test_case.test(ret, __FUNCTION__, "construct TLS 1.2 ServerHello for DOWNGRD\\x01 validation");
        if (errorcode_t::success == ret) {
            tls_records records;
            ret = records.read(&client, from_server, wire);
            _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "TLS 1.3 client rejects DOWNGRD\\x01");
            size_t fatal_alert_count = 0;
            std::set<tls_alertdesc_t> fatal_alerts;
            client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if (tls_alertlevel_t::fatal == level) {
                    ++fatal_alert_count;
                    fatal_alerts.insert(desc);
                }
            });
            _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue exactly one fatal alert for DOWNGRD\\x01");
            _test_case.assert(fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__, "use illegal_parameter for DOWNGRD\\x01");
        }
    }

    {
        tls_session client;
        tls_session server;
        binary_t wire;
        return_t ret = test_build_tls12_serverhello(client, server, tls_12, tls_13, wire);
        _test_case.test(ret, __FUNCTION__, "construct TLS 1.2 ServerHello for DOWNGRD\\x00 validation");
        if (errorcode_t::success == ret) {
            bool rewritten = test_set_tls_serverhello_random_suffix(wire, downgrade_tls11);
            _test_case.assert(rewritten, __FUNCTION__, "rewrite ServerHello.random with DOWNGRD\\x00");
            if (rewritten) {
                tls_records records;
                ret = records.read(&client, from_server, wire);
                _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "TLS 1.3 client rejects DOWNGRD\\x00");
                size_t fatal_alert_count = 0;
                std::set<tls_alertdesc_t> fatal_alerts;
                client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                    if (tls_alertlevel_t::fatal == level) {
                        ++fatal_alert_count;
                        fatal_alerts.insert(desc);
                    }
                });
                _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue exactly one fatal alert for DOWNGRD\\x00");
                _test_case.assert(fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__, "use illegal_parameter for DOWNGRD\\x00");
            }
        }
    }

    {
        tls_session client;
        tls_session server;
        binary_t wire;
        return_t ret = test_build_tls12_serverhello(client, server, tls_12, tls_13, wire);
        _test_case.test(ret, __FUNCTION__, "construct TLS 1.2 ServerHello without a downgrade marker");
        if (errorcode_t::success == ret) {
            bool rewritten = test_set_tls_serverhello_random_suffix(wire, no_sentinel);
            _test_case.assert(rewritten, __FUNCTION__, "remove the downgrade marker from ServerHello.random");
            if (rewritten) {
                tls_records records;
                ret = records.read(&client, from_server, wire);
                _test_case.test(ret, __FUNCTION__, "accept TLS 1.2 when no downgrade sentinel is present");
            }
        }
    }

    {
        tls_session source_client;
        tls_session server;
        tls_session legacy_client;
        binary_t wire;
        return_t ret = test_build_tls12_serverhello(source_client, server, tls_12, tls_13, wire);
        _test_case.test(ret, __FUNCTION__, "construct TLS 1.2 ServerHello carrying a downgrade sentinel");
        if (errorcode_t::success == ret) {
            binary_t legacy_client_hello;
            ret = test_client_supportedversion_clienthello(&legacy_client, tls_12, tls_13, legacy_client_hello);
            _test_case.test(ret, __FUNCTION__, "construct ClientHello before removing supported_versions");
            if (errorcode_t::success == ret) {
                bool removed = test_remove_client_hello_supported_versions(legacy_client_hello);
                _test_case.assert(removed, __FUNCTION__, "remove supported_versions to model a legacy TLS 1.2 client");
                if (removed) {
                    tls_records client_hello_records;
                    ret = client_hello_records.read(&legacy_client, from_client, legacy_client_hello);
                    _test_case.test(ret, __FUNCTION__, "parse legacy ClientHello without supported_versions");
                    if (errorcode_t::success == ret) {
                        tls_records records;
                        ret = records.read(&legacy_client, from_server, wire);
                        _test_case.test(ret, __FUNCTION__, "accept TLS 1.2 ServerHello sentinel from a legacy ClientHello peer");
                    }
                }
            }
        }
    }

    {
        tls_session client;
        tls_session server;
        binary_t wire;
        return_t ret = test_build_tls12_serverhello(client, server, tls_12, tls_13, wire);
        _test_case.test(ret, __FUNCTION__, "construct TLS 1.2 ServerHello for misplaced-marker validation");
        if (errorcode_t::success == ret) {
            bool rewritten = test_set_tls_serverhello_random_suffix(wire, downgrade_tls12);
            _test_case.assert(rewritten, __FUNCTION__, "rewrite the final eight bytes of ServerHello.random");
            if (rewritten) {
                // Move the marker one byte earlier, leaving the final byte unchanged.
                for (size_t i = 0; i < 8; ++i) {
                    wire[34 + i] = downgrade_tls12[i];
                }
                wire[42] = 0x5a;
                tls_records records;
                ret = records.read(&client, from_server, wire);
                _test_case.test(ret, __FUNCTION__, "ignore a marker that is not aligned to the final eight bytes");
            }
        }
    }

    {
        tls_session client;
        tls_session server;
        binary_t wire;
        return_t ret = test_build_tls12_serverhello(client, server, tls_12, tls_13, wire, true);
        _test_case.test(ret, __FUNCTION__, "construct TLS 1.3-capable client offering only TLS 1.2 through supported_versions");
        if (errorcode_t::success == ret) {
            tls_records records;
            ret = records.read(&client, from_server, wire);
            _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__,
                              "TLS 1.3-capable client checks the sentinel even when its offer is restricted to TLS 1.2");
            size_t fatal_alert_count = 0;
            std::set<tls_alertdesc_t> fatal_alerts;
            client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if (tls_alertlevel_t::fatal == level) {
                    ++fatal_alert_count;
                    fatal_alerts.insert(desc);
                }
            });
            _test_case.assert(1 == fatal_alert_count, __FUNCTION__, "queue exactly one fatal alert for a TLS 1.3-capable client with a TLS 1.2-only offer");
            _test_case.assert(fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__,
                              "use illegal_parameter for a TLS 1.3-capable client with a TLS 1.2-only offer");
        }
    }
}

void testcase_gpt_negotiation() {
    test_supported_versions_negative_paths();
    test_supported_versions_unknown_and_legacy_fallback();
    test_psk_hash_does_not_override_cipher_suite_preference();
    test_tls_downgrade_sentinel();
}
