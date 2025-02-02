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

void direction_string(tls_direction_t dir, int send, std::string& s) {
    s += "{";
    if (from_client == dir) {
        if (0 == send) {
            s += "*";
        }
        s += "client->server";
        if (send) {
            s += "*";
        }
    } else {
        if (send) {
            s += "*";
        }
        s += "client<-server";
        if (0 == send) {
            s += "*";
        }
    }
    s += "}";
}

return_t do_test_construct_client_hello(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;

    tls_record_handshake record(session);
    tls_handshake_client_hello* handshake = nullptr;

    const OPTION& option = _cmdline->value();

    __try2 {
        __try_new_catch(handshake, new tls_handshake_client_hello(session), ret, __leave2);

        // random
        {
            openssl_prng prng;
            binary_t random;
            binary_t session_id;
            prng.random(random, 32);
            prng.random(session_id, 32);

            handshake->get_random() = random;
            handshake->get_session_id() = session_id;
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
            auto sni = new tls_extension_sni(session);
            auto& hostname = sni->get_hostname();
            // hostname = "server";
            handshake->get_extensions().add(sni);
        }
        {
            auto ec_point_formats = new tls_extension_ec_point_formats(session);
            (*ec_point_formats).add("uncompressed").add("ansiX962_compressed_prime").add("ansiX962_compressed_char2");
            handshake->get_extensions().add(ec_point_formats);
        }
        {
            auto supported_groups = new tls_extension_supported_groups(session);
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
            auto signature_algorithms = new tls_extension_signature_algorithms(session);
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
            auto supported_versions = new tls_extension_client_supported_versions(session);
            if (tls_13 == option.version) {
                (*supported_versions).add(tls_13);
            } else {
                (*supported_versions).add(tls_12);
            }
            handshake->get_extensions().add(supported_versions);
        }
        {
            auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(session);
            (*psk_key_exchange_modes).add("psk_dhe_ke");
            handshake->get_extensions().add(psk_key_exchange_modes);
        }
        {
            auto key_share = new tls_extension_client_key_share(session);
            (*key_share).add("x25519");
            handshake->get_extensions().add(key_share);
        }
        {
            basic_stream bs;
            auto pkey = session->get_tls_protection().get_keyexchange().find("client");
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

return_t do_test_construct_server_hello(tls_direction_t dir, tls_session* session, tls_session* client_session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    uint16 server_version = option.version;
    uint16 server_cs = 0;
    auto& client_handshake_context = client_session->get_tls_protection().get_protection_context();
    auto& server_handshake_context = session->get_tls_protection().get_protection_context();
    server_handshake_context.select_from(client_handshake_context);
    server_cs = server_handshake_context.get0_cipher_suite();
    server_version = server_handshake_context.get0_supported_version();

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
            openssl_prng prng;
            binary_t random;
            binary_t session_id;
            prng.random(random, 32);
            prng.random(session_id, 32);

            handshake->get_random() = random;
            handshake->get_session_id() = session_id;
            handshake->set_cipher_suite(server_cs);
        }
        {
            auto supported_versions = new tls_extension_server_supported_versions(session);
            (*supported_versions).set(server_version);
            handshake->get_extensions().add(supported_versions);
        }
        {
            auto key_share = new tls_extension_server_key_share(session);
            (*key_share).add("x25519");
            handshake->get_extensions().add(key_share);
        }

        {
            basic_stream bs;
            auto pkey = session->get_tls_protection().get_keyexchange().find("server");
            dump_key(pkey, &bs);
            _logger->write(bs);
            _test_case.assert(pkey, __FUNCTION__, "{server} key share (server generated)");
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

void do_cross_check_keycalc(tls_session* clisession, tls_session* svrsession, tls_secret_t secret, const char* secret_name) {
    auto& client_protection = clisession->get_tls_protection();
    auto& server_protection = svrsession->get_tls_protection();

    binary_t client_secret;
    binary_t server_secret;

    client_protection.get_item(secret, client_secret);
    server_protection.get_item(secret, server_secret);

    _logger->writeln("client secret %s (internal 0x%04x) %s", secret_name, secret, base16_encode(client_secret).c_str());
    _logger->writeln("server secret %s (internal 0x%04x) %s", secret_name, secret, base16_encode(server_secret).c_str());

    _test_case.assert((false == client_secret.empty()) && (client_secret == server_secret), __FUNCTION__, "cross-check secret %s", secret_name);
}

void do_test_keycalc_server_hello(tls_session* clisession, tls_session* svrsession) {
    do_cross_check_keycalc(clisession, svrsession, tls_context_client_hello_random, "tls_context_client_hello_random");
    do_cross_check_keycalc(clisession, svrsession, tls_context_server_hello_random, "tls_context_server_hello_random");
    do_cross_check_keycalc(clisession, svrsession, tls_context_empty_hash, "tls_context_empty_hash");
    do_cross_check_keycalc(clisession, svrsession, tls_context_shared_secret, "tls_context_shared_secret");
    do_cross_check_keycalc(clisession, svrsession, tls_context_transcript_hash, "tls_context_transcript_hash");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_early_secret, "tls_secret_early_secret");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_handshake_derived, "tls_secret_handshake_derived");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_handshake, "tls_secret_handshake");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_c_hs_traffic, "tls_secret_c_hs_traffic");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_s_hs_traffic, "tls_secret_s_hs_traffic");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_handshake_client_key, "tls_secret_handshake_client_key");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_handshake_client_iv, "tls_secret_handshake_client_iv");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_handshake_server_key, "tls_secret_handshake_server_key");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_handshake_server_iv, "tls_secret_handshake_server_iv");
}

return_t do_test_construct_server_change_cipher_spec(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
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

return_t do_test_construct_encrypted_extensions(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_handshakes().add(new tls_handshake_encrypted_extensions(session));
        ret = record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

return_t do_test_construct_certificate(tls_direction_t dir, tls_session* session, const char* certfile, const char* keyfile, binary_t& bin,
                                       const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);

        auto handshake = new tls_handshake_certificate(session);
        handshake->set(dir, certfile, keyfile);  // SC (server certificate)

        record.get_handshakes().add(handshake);
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

return_t do_test_construct_server_key_exchange(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_handshake record(session);

        auto handshake = new tls_handshake_server_key_exchange(session);

        record.get_handshakes().add(handshake);
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

return_t do_test_construct_server_hello_done(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t do_test_construct_client_key_exchange(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_handshake record(session);

        auto handshake = new tls_handshake_client_key_exchange(session);

        record.get_handshakes().add(handshake);
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

return_t do_test_construct_certificate_verify(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_handshakes().add(new tls_handshake_certificate_verify(session));
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

return_t do_test_construct_server_finished(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_handshakes().add(new tls_handshake_finished(session));
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

void do_test_keycalc_server_finished(tls_session* clisession, tls_session* svrsession) {
    do_cross_check_keycalc(clisession, svrsession, tls_context_transcript_hash, "tls_context_transcript_hash");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_application_derived, "tls_secret_application_derived");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_application, "tls_secret_application");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_c_ap_traffic, "tls_secret_c_ap_traffic");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_application_client_key, "tls_secret_application_client_key");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_application_client_iv, "tls_secret_application_client_iv");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_s_ap_traffic, "tls_secret_s_ap_traffic");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_application_server_key, "tls_secret_application_server_key");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_application_server_iv, "tls_secret_application_server_iv");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_exp_master, "tls_secret_exp_master");
}

return_t do_test_construct_client_finished(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_handshakes().add(new tls_handshake_finished(session));
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

return_t do_test_construct_client_change_cipher_spec(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
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

void do_test_keycalc_client_finished(tls_session* clisession, tls_session* svrsession) {
    do_cross_check_keycalc(clisession, svrsession, tls_context_transcript_hash, "tls_context_transcript_hash");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_res_master, "tls_secret_res_master");
    do_cross_check_keycalc(clisession, svrsession, tls_secret_resumption, "tls_secret_resumption");
}

return_t do_test_construct_client_ping(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
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

return_t do_test_construct_server_pong(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
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

return_t do_test_construct_close_notify(tls_direction_t dir, tls_session* session, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_application_data record(session);
        record.get_records().add(new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify));
        record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

return_t do_test_send_record(tls_direction_t dir, tls_session* session, const binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == message) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_records records;
        ret = records.read(session, dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 1, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

void test_construct_server_certificate(tls_session* client_session, tls_session* server_session) {
    // S -> C SC
    binary_t bin_certificate;
    do_test_construct_certificate(from_server, server_session, "server.crt", "server.key", bin_certificate, "construct certificate");
    do_test_send_record(from_server, client_session, bin_certificate, "send cerficate");

    do_cross_check_keycalc(client_session, server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
}

void test_construct() {
    _test_case.begin("construct");

    // C -> S {client}
    // construct : write + client_session
    // send : read + server_session
    // S -> C {server}
    // construct : write + server_session
    // send : read + client_session

    return_t ret = errorcode_t::success;
    const OPTION& option = _cmdline->value();

    __try2 {
        tls_session client_session;
        tls_session server_session;

        // C -> S CH
        binary_t bin_client_hello;
        ret = do_test_construct_client_hello(from_client, &client_session, bin_client_hello, "construct client hello message");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        do_test_send_record(from_client, &server_session, bin_client_hello, "send client hello");

        // S -> C SH
        binary_t bin_server_hello;
        ret = do_test_construct_server_hello(from_server, &server_session, &client_session, bin_server_hello, "construct server hello message");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        do_test_send_record(from_server, &client_session, bin_server_hello, "send server hello");

        do_test_keycalc_server_hello(&client_session, &server_session);
        do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

        uint16 tlsversion = 0;
        uint16 keyexchange = 0;
        uint8 mode = 0;
        {
            auto& protection = server_session.get_tls_protection();
            auto cs = protection.get_cipher_suite();
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            const tls_cipher_suite_t* hint = tlsadvisor->hintof_cipher_suite(cs);
            keyexchange = hint->keyexchange;
            mode = hint->mode;

            auto svr_tlsversion = server_session.get_tls_protection().get_tls_version();
            auto cli_tlsversion = client_session.get_tls_protection().get_tls_version();

            tlsversion = svr_tlsversion;

            _test_case.assert(svr_tlsversion == cli_tlsversion, __FUNCTION__, "TLS version %04x", svr_tlsversion);
        }

        if (cbc == mode)  // keyexchange_null != keyexchange
        {
            test_construct_server_certificate(&client_session, &server_session);

            // before change_cipher_spec
            // S->C SKE server_key_exchange
            // S->C SHD server_hello_done
            // C->S CKE client_key_exchange
            binary_t bin_server_key_exchange;
            do_test_construct_server_key_exchange(from_server, &server_session, bin_server_key_exchange, "construct server_key_exchange");
            do_test_send_record(from_server, &client_session, bin_server_key_exchange, "send server_key_exchange");
            // binary_t bin_server_hello_done;
            // do_test_construct_server_hello_done(from_server, &server_session, bin_server_hello_done, "construct server_hello_done");
            // do_test_send_record(from_server, &client_session, bin_server_hello_done, "send server_hello_done");
            binary_t bin_client_key_exchange;
            do_test_construct_client_key_exchange(from_client, &client_session, bin_client_key_exchange, "construct client_key_exchange");
            do_test_send_record(from_client, &server_session, bin_client_key_exchange, "send client_key_exchange");

            // CKE

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_server_key, "tls_secret_server_key");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_server_mac_key, "tls_secret_server_mac_key");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_client_key, "tls_secret_client_key");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_client_mac_key, "tls_secret_client_mac_key");
        }

        // change_cipher_spec
        {
            // S -> C CCS
            binary_t bin_server_change_cipher_spec;
            do_test_construct_server_change_cipher_spec(from_server, &server_session, bin_server_change_cipher_spec, "construct change_cipher_spec");
            do_test_send_record(from_server, &client_session, bin_server_change_cipher_spec, "send change_cipher_spec");

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

            // C -> S CCS
            binary_t bin_client_change_cipher_spec;
            do_test_construct_client_change_cipher_spec(from_client, &client_session, bin_client_change_cipher_spec, "construct change_cipher_spec");
            do_test_send_record(from_client, &server_session, bin_client_change_cipher_spec, "send change_cipher_spec");

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
        }

        if (tls_13 == tlsversion) {
            // S -> C EE
            binary_t bin_encrypted_extensions;
            do_test_construct_encrypted_extensions(from_server, &server_session, bin_encrypted_extensions, "construct encrypted extensions");
            do_test_send_record(from_server, &client_session, bin_encrypted_extensions, "send encrypted extensions");

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
        }

        if (keyexchange_null == keyexchange) {
            test_construct_server_certificate(&client_session, &server_session);
        }

        if (tls_13 == tlsversion) {
            // S -> C SCV
            binary_t bin_certificate_verify;
            do_test_construct_certificate_verify(from_server, &server_session, bin_certificate_verify, "construct certificate verify");
            do_test_send_record(from_server, &client_session, bin_certificate_verify, "send cerficate verify");

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
        }

        // S -> C SF
        binary_t bin_server_finished;
        do_test_construct_server_finished(from_server, &server_session, bin_server_finished, "construct server finished");
        do_test_send_record(from_server, &client_session, bin_server_finished, "send server finished");

        do_test_keycalc_server_finished(&client_session, &server_session);

        // C -> S CF
        binary_t bin_client_finished;
        do_test_construct_client_finished(from_client, &client_session, bin_client_finished, "construct client finished");
        do_test_send_record(from_client, &server_session, bin_client_finished, "send client finished");

        do_test_keycalc_client_finished(&client_session, &server_session);

        // C->S ping
        binary_t bin_client_ping;
        do_test_construct_client_ping(from_client, &client_session, bin_client_ping, "construct client ping");
        do_test_send_record(from_client, &server_session, bin_client_ping, "send client ping");

        // C<-S pong
        binary_t bin_server_pong;
        do_test_construct_server_pong(from_server, &server_session, bin_server_pong, "construct server pong");
        do_test_send_record(from_server, &client_session, bin_server_pong, "send server pong");

        // C->S close notify
        binary_t bin_client_close_notify;
        do_test_construct_close_notify(from_client, &client_session, bin_client_close_notify, "construct client close notify");
        do_test_send_record(from_client, &server_session, bin_client_close_notify, "send client close notify");

        // S->C close notify
        binary_t bin_server_close_notify;
        do_test_construct_close_notify(from_server, &server_session, bin_server_close_notify, "construct server close notify");
        do_test_send_record(from_server, &client_session, bin_server_close_notify, "send server close notify");
    }
    __finally2 {}
}
