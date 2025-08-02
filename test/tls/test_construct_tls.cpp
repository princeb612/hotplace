/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

static return_t do_test_construct_client_hello(const TLS_OPTION& option, tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    tls_record_handshake record(session);
    tls_handshake_client_hello* handshake = nullptr;

    __try2 {
        __try_new_catch(handshake, new tls_handshake_client_hello(session), ret, __leave2);

        {
            // client_hello generate random member

            openssl_prng prng;
            binary_t session_id;
            prng.random(session_id, 32);
            handshake->set_session_id(session_id);
        }

        // cipher suites
        {
            if (option.cipher_suite.empty()) {
                *handshake << "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
                           << "TLS_CHACHA20_POLY1305_SHA256"
                           << "TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256"
                           << "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                           << "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
                           << "TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
                           << "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
                           << "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                           << "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
                           << "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
            } else {
                handshake->add_ciphersuites(option.cipher_suite.c_str());
            }
        }

        {
            auto sni = new tls_extension_sni(handshake);
            auto& hostname = sni->get_hostname();
            hostname = "test.server.com";
            handshake->get_extensions().add(sni);
        }
        {
            // RFC 9325 4.2.1
            // Note that [RFC8422] deprecates all but the uncompressed point format.
            // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element, "uncompressed".
            auto ec_point_formats = new tls_extension_ec_point_formats(handshake);
            (*ec_point_formats).add("uncompressed");
            handshake->get_extensions().add(ec_point_formats);
        }
        {
            // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
            auto supported_groups = new tls_extension_supported_groups(handshake);
            (*supported_groups)
                .add("x25519")
                .add("secp256r1")
                .add("x448")
                .add("secp521r1")
                .add("secp384r1")
                .add("ffdhe2048")
                .add("ffdhe3072")
                .add("ffdhe4096")
                .add("ffdhe6144")
                .add("ffdhe8192");
            handshake->get_extensions().add(supported_groups);
        }
        {
            auto extension = new tls_extension_unknown(tls_ext_next_protocol_negotiation, handshake);
            handshake->get_extensions().add(extension);
        }
        {
            auto extension = new tls_extension_unknown(tls_ext_encrypt_then_mac, handshake);
            handshake->get_extensions().add(extension);
        }
        {
            auto extension = new tls_extension_unknown(tls_ext_extended_master_secret, handshake);
            handshake->get_extensions().add(extension);
        }
        {
            auto extension = new tls_extension_unknown(tls_ext_post_handshake_auth, handshake);
            handshake->get_extensions().add(extension);
        }
        {
            auto signature_algorithms = new tls_extension_signature_algorithms(handshake);
            (*signature_algorithms)
                .add("ecdsa_secp256r1_sha256")
                .add("ecdsa_secp384r1_sha384")
                .add("ecdsa_secp521r1_sha512")
                .add("ed25519")
                .add("ed448")
                .add("rsa_pkcs1_sha256")
                .add("rsa_pkcs1_sha384")
                .add("rsa_pkcs1_sha512")
                .add("rsa_pss_pss_sha256")
                .add("rsa_pss_pss_sha384")
                .add("rsa_pss_pss_sha512")
                .add("rsa_pss_rsae_sha256")
                .add("rsa_pss_rsae_sha384")
                .add("rsa_pss_rsae_sha512");
            handshake->get_extensions().add(signature_algorithms);
        }
        {
            auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(handshake);
            (*psk_key_exchange_modes).add("psk_dhe_ke");
            handshake->get_extensions().add(psk_key_exchange_modes);
        }
        if (tls_13 == option.version) {
            {
                auto supported_versions = new tls_extension_client_supported_versions(handshake);
                if (tlsadvisor->is_kindof(tls_13, option.version)) {
                    (*supported_versions).add(tls_13);
                } else {
                    (*supported_versions).add(tls_12);
                }
                handshake->get_extensions().add(supported_versions);
            }

            {
                auto key_share = new tls_extension_client_key_share(handshake);
                key_share->clear();
                key_share->add("x25519");
                handshake->get_extensions().add(key_share);
            }

            basic_stream bs;
            auto pkey = session->get_tls_protection().get_keyexchange().find(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
            dump_key(pkey, &bs);
            _logger->write(bs);
            _test_case.assert(pkey, __FUNCTION__, "{client} key share (client generated)");
        }
    }
    __finally2 {
        if (errorcode_t::success == ret) {
            record.get_handshakes().add(handshake);
            ret = record.write(dir, bin);
        }

        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_hello(const TLS_OPTION& option, tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;

    auto& protection = session->get_tls_protection();

    uint16 server_cs = 0;
    uint16 server_version = 0;
    protection.negotiate(session, server_cs, server_version);

    tls_handshake_server_hello* handshake = nullptr;

    __try2 {
        if (0x0000 == server_cs) {
            ret = errorcode_t::unknown;
            _test_case.test(ret, __FUNCTION__, "no cipher suite");
            __leave2;
        }

        __try_new_catch(handshake, new tls_handshake_server_hello(session), ret, __leave2);

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto csname = tlsadvisor->cipher_suite_string(server_cs);
            _test_case.assert(csname.size(), __FUNCTION__, "%s", csname.c_str());
        }

        {
            // client_hello generate random member

            openssl_prng prng;

            binary_t session_id;
            prng.random(session_id, 32);
            handshake->set_session_id(session_id);

            handshake->set_cipher_suite(server_cs);
        }

        {
            {
                auto renegotiation_info = new tls_extension_renegotiation_info(handshake);
                handshake->get_extensions().add(renegotiation_info);
            }
            {
                auto ec_point_formats = new tls_extension_ec_point_formats(handshake);
                (*ec_point_formats).add("uncompressed");
                handshake->get_extensions().add(ec_point_formats);
            }
            {
                auto supported_groups = new tls_extension_supported_groups(handshake);
                (*supported_groups).add("x25519");
                handshake->get_extensions().add(supported_groups);
            }
        }

        if (tls_13 == option.version) {
            {
                auto supported_versions = new tls_extension_server_supported_versions(handshake);
                (*supported_versions).set(server_version);
                handshake->get_extensions().add(supported_versions);
            }
            {
                auto key_share = new tls_extension_server_key_share(handshake);
                key_share->clear();
                key_share->add_keyshare();
                handshake->get_extensions().add(key_share);

                basic_stream bs;
                auto svr_keyshare = protection.get_keyexchange().find(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE);
                dump_key(svr_keyshare, &bs);
                _logger->write(bs);
                _test_case.assert(svr_keyshare, __FUNCTION__, "{server} key share (server generated)");
            }
        } else {
            //
        }
    }
    __finally2 {
        if (errorcode_t::success == ret) {
            tls_record_handshake record(session);
            record.get_handshakes().add(handshake);
            ret = record.write(dir, bin);
        }

        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_change_cipher_spec(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_change_cipher_spec record(session);
        ret = record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_encrypted_extensions(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (tls_13 == session->get_tls_protection().get_tls_version()) {
            if (session->get_session_info(dir).apply_protection()) {
                tls_record_builder builder;
                auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

                auto handshake = new tls_handshake_encrypted_extensions(session);
                {
                    auto extension = new tls_extension_alpn(handshake);
                    binary_t protocols;
                    binary_append(protocols, uint8(2));
                    binary_append(protocols, "h2");
                    binary_append(protocols, uint8(8));
                    binary_append(protocols, "http/1.1");
                    extension->set_protocols(protocols);
                    handshake->get_extensions().add(extension);
                }
                *record << handshake;
                ret = record->write(dir, bin);
                record->release();
            }
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_certificate(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // SC (server certificate)
        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

        auto handshake = new tls_handshake_certificate(session);
        *record << handshake;

        record->write(dir, bin);
        record->release();
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_key_exchange(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (tls_12 == session->get_tls_protection().get_tls_version()) {
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

            *record << new tls_handshake_server_key_exchange(session);
            record->write(dir, bin);
            record->release();
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_hello_done(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (tls_12 == session->get_tls_protection().get_tls_version()) {
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

            *record << new tls_handshake_server_hello_done(session);
            record->write(dir, bin);
            record->release();
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_client_key_exchange(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (tls_12 == session->get_tls_protection().get_tls_version()) {
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

            *record << new tls_handshake_client_key_exchange(session);
            record->write(dir, bin);
            record->release();
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_certificate_verify(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (tls_13 == session->get_tls_protection().get_tls_version()) {
            tls_record_builder builder;
            auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

            *record << new tls_handshake_certificate_verify(session);
            record->write(dir, bin);
            record->release();
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_finished(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

        *record << new tls_handshake_finished(session);
        record->write(dir, bin);
        record->release();
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_client_finished(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();

        *record << new tls_handshake_finished(session);
        record->write(dir, bin);
        record->release();
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_client_change_cipher_spec(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_change_cipher_spec record(session);
        ret = record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_client_ping(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_records().add(new tls_record_application_data(session, "ping"));
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_pong(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_records().add(new tls_record_application_data(session, "pong"));
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_close_notify(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_alert).set(dir).construct().build();

        *record << new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify);
        record->write(dir, bin);
        record->release();
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_send_record(tls_session* session, tls_direction_t dir, const binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == message) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_records records;
        ret = records.read(session, dir, bin);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        bool has_fatal = false;

        auto lambda_test_fatal_alert = [&](uint8 level, uint8 desc) -> void {
            if (tls_alertlevel_fatal == level) {
                has_fatal = true;
            }
        };

        if (has_fatal) {
            ret = failed;
            __leave2;
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 1, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static void test_construct_tls_routine(const TLS_OPTION& option) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto ver = tlsadvisor->tls_version_string(option.version);
    auto hint = tlsadvisor->hintof_cipher_suite(option.cipher_suite);
    _test_case.begin("construct %s %s", ver.c_str(), hint->name_iana);

    // C -> S {client}
    // construct : write + client_session
    // send : read + server_session
    // S -> C {server}
    // construct : write + server_session
    // send : read + client_session

    return_t ret = errorcode_t::success;

    __try2 {
        tls_session client_session;
        tls_session server_session;

        // C -> S CH
        binary_t bin_client_hello;
        ret = do_test_construct_client_hello(option, &client_session, from_client, bin_client_hello, "construct client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&server_session, from_client, bin_client_hello, "send client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // S -> C SH
        binary_t bin_server_hello;
        ret = do_test_construct_server_hello(option, &server_session, from_server, bin_server_hello, "construct server hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&client_session, from_server, bin_server_hello, "send server hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        {
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            do_cross_check_keycalc(&client_session, &server_session, tls_context_client_hello_random, "tls_context_client_hello_random");
            do_cross_check_keycalc(&client_session, &server_session, tls_context_server_hello_random, "tls_context_server_hello_random");
            do_cross_check_keycalc(&client_session, &server_session, tls_context_empty_hash, "tls_context_empty_hash");
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            if (server_session.get_tls_protection().is_kindof_tls13()) {
                do_cross_check_keycalc(&client_session, &server_session, tls_context_shared_secret, "tls_context_shared_secret");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_early_secret, "tls_secret_early_secret");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_handshake_derived, "tls_secret_handshake_derived");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_handshake, "tls_secret_handshake");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_c_hs_traffic, "tls_secret_c_hs_traffic");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_s_hs_traffic, "tls_secret_s_hs_traffic");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_handshake_client_key, "tls_secret_handshake_client_key");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_handshake_client_iv, "tls_secret_handshake_client_iv");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_handshake_server_key, "tls_secret_handshake_server_key");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_handshake_server_iv, "tls_secret_handshake_server_iv");
            }
        }

        uint16 tlsversion = 0;
        uint16 keyexchange = 0;
        uint8 mode = 0;
        {
            auto& protection = server_session.get_tls_protection();
            auto cs = protection.get_cipher_suite();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            const tls_cipher_suite_t* hint = tlsadvisor->hintof_cipher_suite(cs);
            keyexchange = hint->keyexchange;

            auto svr_tlsversion = server_session.get_tls_protection().get_tls_version();
            auto cli_tlsversion = client_session.get_tls_protection().get_tls_version();

            tlsversion = svr_tlsversion;

            _test_case.assert(svr_tlsversion == cli_tlsversion, __FUNCTION__, "TLS version %04x", svr_tlsversion);
        }

        if (tls_13 == tlsversion) {
            // S -> C CCS
            binary_t bin_server_change_cipher_spec;
            do_test_construct_server_change_cipher_spec(&server_session, from_server, bin_server_change_cipher_spec, "construct change_cipher_spec");
            ret = do_test_send_record(&client_session, from_server, bin_server_change_cipher_spec, "send change_cipher_spec");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // S -> C EE
            binary_t bin_encrypted_extensions;
            do_test_construct_encrypted_extensions(&server_session, from_server, bin_encrypted_extensions, "construct encrypted extensions");
            ret = do_test_send_record(&client_session, from_server, bin_encrypted_extensions, "send encrypted extensions");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // S -> C SC
            binary_t bin_certificate;
            do_test_construct_certificate(&server_session, from_server, bin_certificate, "construct certificate");
            ret = do_test_send_record(&client_session, from_server, bin_certificate, "send cerficate");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // S -> C SCV
            binary_t bin_certificate_verify;
            do_test_construct_certificate_verify(&server_session, from_server, bin_certificate_verify, "construct certificate verify");
            ret = do_test_send_record(&client_session, from_server, bin_certificate_verify, "send cerficate verify");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // S -> C SF
            binary_t bin_server_finished;
            do_test_construct_server_finished(&server_session, from_server, bin_server_finished, "construct server finished");
            do_test_send_record(&client_session, from_server, bin_server_finished, "send server finished");

            // C -> S CCS
            binary_t bin_client_change_cipher_spec;
            do_test_construct_client_change_cipher_spec(&client_session, from_client, bin_client_change_cipher_spec, "construct change_cipher_spec");
            ret = do_test_send_record(&server_session, from_client, bin_client_change_cipher_spec, "send change_cipher_spec");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // C -> S CF
            binary_t bin_client_finished;
            do_test_construct_client_finished(&client_session, from_client, bin_client_finished, "construct client finished");
            ret = do_test_send_record(&server_session, from_client, bin_client_finished, "send client finished");
            if (errorcode_t::success != ret) {
                __leave2;
            }
        } else if (tls_12 == tlsversion) {
            // S -> C SC
            binary_t bin_certificate;
            do_test_construct_certificate(&server_session, from_server, bin_certificate, "construct certificate");
            ret = do_test_send_record(&client_session, from_server, bin_certificate, "send cerficate");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // before change_cipher_spec
            // S->C SKE server_key_exchange
            // S->C SHD server_hello_done
            // C->S CKE client_key_exchange
            binary_t bin_server_key_exchange;
            do_test_construct_server_key_exchange(&server_session, from_server, bin_server_key_exchange, "construct server_key_exchange");
            ret = do_test_send_record(&client_session, from_server, bin_server_key_exchange, "send server_key_exchange");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            binary_t bin_server_hello_done;
            do_test_construct_server_hello_done(&server_session, from_server, bin_server_hello_done, "construct server_hello_done");
            ret = do_test_send_record(&client_session, from_server, bin_server_hello_done, "send server_hello_done");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            binary_t bin_client_key_exchange;
            do_test_construct_client_key_exchange(&client_session, from_client, bin_client_key_exchange, "construct client_key_exchange");
            ret = do_test_send_record(&server_session, from_client, bin_client_key_exchange, "send client_key_exchange");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // CKE

            {
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_server_key, "tls_secret_server_key");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_server_mac_key, "tls_secret_server_mac_key");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_client_key, "tls_secret_client_key");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_client_mac_key, "tls_secret_client_mac_key");
            }

            // C -> S CCS
            binary_t bin_client_change_cipher_spec;
            do_test_construct_client_change_cipher_spec(&client_session, from_client, bin_client_change_cipher_spec, "construct change_cipher_spec");
            ret = do_test_send_record(&server_session, from_client, bin_client_change_cipher_spec, "send change_cipher_spec");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // C -> S CF
            binary_t bin_client_finished;
            do_test_construct_client_finished(&client_session, from_client, bin_client_finished, "construct client finished");
            ret = do_test_send_record(&server_session, from_client, bin_client_finished, "send client finished");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // S -> C CCS
            binary_t bin_server_change_cipher_spec;
            do_test_construct_server_change_cipher_spec(&server_session, from_server, bin_server_change_cipher_spec, "construct change_cipher_spec");
            ret = do_test_send_record(&client_session, from_server, bin_server_change_cipher_spec, "send change_cipher_spec");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                //
                do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            }

            // S -> C SF
            binary_t bin_server_finished;
            do_test_construct_server_finished(&server_session, from_server, bin_server_finished, "construct server finished");
            ret = do_test_send_record(&client_session, from_server, bin_server_finished, "send server finished");
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        {
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            if (server_session.get_tls_protection().is_kindof_tls13()) {
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_application_derived, "tls_secret_application_derived");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_application, "tls_secret_application");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_c_ap_traffic, "tls_secret_c_ap_traffic");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_application_client_key, "tls_secret_application_client_key");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_application_client_iv, "tls_secret_application_client_iv");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_s_ap_traffic, "tls_secret_s_ap_traffic");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_application_server_key, "tls_secret_application_server_key");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_application_server_iv, "tls_secret_application_server_iv");
                do_cross_check_keycalc(&client_session, &server_session, tls_secret_exp_master, "tls_secret_exp_master");
            }
        }

        {
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_res_master, "tls_secret_res_master");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_resumption, "tls_secret_resumption");
        }

        // C->S ping
        binary_t bin_client_ping;
        do_test_construct_client_ping(&client_session, from_client, bin_client_ping, "construct client ping");
        ret = do_test_send_record(&server_session, from_client, bin_client_ping, "send client ping");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // C<-S pong
        binary_t bin_server_pong;
        do_test_construct_server_pong(&server_session, from_server, bin_server_pong, "construct server pong");
        ret = do_test_send_record(&client_session, from_server, bin_server_pong, "send server pong");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // C->S close notify
        binary_t bin_client_close_notify;
        do_test_construct_close_notify(&client_session, from_client, bin_client_close_notify, "construct client close notify");
        ret = do_test_send_record(&server_session, from_client, bin_client_close_notify, "send client close notify");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // S->C close notify
        binary_t bin_server_close_notify;
        do_test_construct_close_notify(&server_session, from_server, bin_server_close_notify, "construct server close notify");
        ret = do_test_send_record(&client_session, from_server, bin_server_close_notify, "send server close notify");
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
}

void test_construct_tls() {
    TLS_OPTION testvector[] = {
        // tested

        {tls_13, "TLS_AES_128_GCM_SHA256"},
        {tls_13, "TLS_AES_256_GCM_SHA384"},
        {tls_13, "TLS_CHACHA20_POLY1305_SHA256"},
        {tls_13, "TLS_AES_128_CCM_SHA256"},
        {tls_13, "TLS_AES_128_CCM_8_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
        {tls_12, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"},

        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},

        // no test vector (feat. s_server and s_client)
        // so the actual authenticity cannot be verified...

        {tls_12, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"},
        {tls_12, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"},

        {tls_12, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    };

    for (auto item : testvector) {
        test_construct_tls_routine(item);
    }
}
