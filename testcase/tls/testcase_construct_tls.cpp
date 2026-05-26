/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_construct_tls.cpp
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

    __try2 {
        tls_record_handshake record(session);
        tls_handshake* handshake = nullptr;

        ret = tls_composer::construct_client_hello(&handshake, session, nullptr, option.version, option.version);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        record << handshake;
        ret = record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_hello(const TLS_OPTION& option, tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;

    __try2 {
        tls_record_handshake record(session);
        tls_handshake* handshake = nullptr;

        ret = tls_composer::construct_server_hello(&handshake, session, nullptr, option.version, option.version);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        record << handshake;
        ret = record.write(dir, bin);

        auto& tlskey = session->get_tls_protection().get_key();
        tlskey.for_each([&](crypto_key_object* obj, void* user) -> void {
            if (KID_TLS_CLIENTHELLO_KEYSHARE_PUBLIC == obj->get_desc().get_kid_str()) {
                auto pkey = obj->get_pkey();
                _logger->write([&](basic_stream& bs) -> void { dump_key(pkey, &bs); });
            }
        });
    }
    __finally2 {
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
                if (record) {
                    ret = (*record)
                              .add(tls_hs_encrypted_extensions, session,
                                   [&](tls_handshake* handshake) -> return_t {
                                       handshake->get_extensions().add(tls_ext_alpn, dir, handshake, [](tls_extension* extension) -> return_t {
                                           auto alpn = (tls_extension_alpn*)extension;
                                           binary_t protocols;
                                           binary_append(protocols, uint8(2));
                                           binary_append(protocols, "h2");
                                           binary_append(protocols, uint8(8));
                                           binary_append(protocols, "http/1.1");
                                           alpn->set_protocols(protocols);
                                           return errorcode_t::success;
                                       });
                                       return errorcode_t::success;
                                   })
                              .write(dir, bin);
                    record->release();
                }
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
        if (record) {
            ret = (*record).add(tls_hs_certificate, session).write(dir, bin);
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
            if (record) {
                ret = (*record).add(tls_hs_server_key_exchange, session).write(dir, bin);
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
            if (record) {
                ret = (*record).add(tls_hs_server_hello_done, session).write(dir, bin);
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
            if (record) {
                ret = (*record).add(tls_hs_client_key_exchange, session).write(dir, bin);
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
            if (record) {
                ret = (*record).add(tls_hs_certificate_verify, session).write(dir, bin);
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

static return_t do_test_construct_server_finished(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
        if (record) {
            ret = (*record).add(tls_hs_finished, session).write(dir, bin);
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

static return_t do_test_construct_client_finished(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_record_builder builder;
        auto record = builder.set(session).set(tls_content_type_handshake).set(dir).construct().build();
        if (record) {
            ret = (*record).add(tls_hs_finished, session).write(dir, bin);
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
        ret = record.write(dir, bin);
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
        ret = record.write(dir, bin);
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
        if (record) {
            *record << new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify);
            ret = record->write(dir, bin);
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
        session->get_alert(dir, lambda_test_fatal_alert);

        if (has_fatal) {
            ret = errorcode_t::failed;
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

static void test_construct_tls_routine(const TLS_OPTION& option, const char* group_param) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    tlsadvisor->set_tls_groups(group_param);

    auto ver = tlsadvisor->nameof_tls_version(option.version);
    auto hint = tlsadvisor->hintof_cipher_suite(option.cipher_suite);
    _test_case.begin("construct %s %s %s", ver.c_str(), hint->name_iana, group_param);

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

        uint16 tlsversion = 0;
        {
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

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

            // S -> C EE
            binary_t bin_encrypted_extensions;
            do_test_construct_encrypted_extensions(&server_session, from_server, bin_encrypted_extensions, "construct encrypted extensions");
            ret = do_test_send_record(&client_session, from_server, bin_encrypted_extensions, "send encrypted extensions");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

            // S -> C SC
            binary_t bin_certificate;
            do_test_construct_certificate(&server_session, from_server, bin_certificate, "construct certificate");
            ret = do_test_send_record(&client_session, from_server, bin_certificate, "send cerficate");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

            // S -> C SCV
            binary_t bin_certificate_verify;
            do_test_construct_certificate_verify(&server_session, from_server, bin_certificate_verify, "construct certificate verify");
            ret = do_test_send_record(&client_session, from_server, bin_certificate_verify, "send cerficate verify");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

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

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

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

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

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

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

            binary_t bin_server_hello_done;
            do_test_construct_server_hello_done(&server_session, from_server, bin_server_hello_done, "construct server_hello_done");
            ret = do_test_send_record(&client_session, from_server, bin_server_hello_done, "send server_hello_done");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

            binary_t bin_client_key_exchange;
            do_test_construct_client_key_exchange(&client_session, from_client, bin_client_key_exchange, "construct client_key_exchange");
            ret = do_test_send_record(&server_session, from_client, bin_client_key_exchange, "send client_key_exchange");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // CKE

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_server_key, "tls_secret_server_key");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_server_mac_key, "tls_secret_server_mac_key");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_client_key, "tls_secret_client_key");
            do_cross_check_keycalc(&client_session, &server_session, tls_secret_client_mac_key, "tls_secret_client_mac_key");

            // C -> S CCS
            binary_t bin_client_change_cipher_spec;
            do_test_construct_client_change_cipher_spec(&client_session, from_client, bin_client_change_cipher_spec, "construct change_cipher_spec");
            ret = do_test_send_record(&server_session, from_client, bin_client_change_cipher_spec, "send change_cipher_spec");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

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

            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");

            // S -> C SF
            binary_t bin_server_finished;
            do_test_construct_server_finished(&server_session, from_server, bin_server_finished, "construct server finished");
            ret = do_test_send_record(&client_session, from_server, bin_server_finished, "send server finished");
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

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

        do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
        do_cross_check_keycalc(&client_session, &server_session, tls_secret_res_master, "tls_secret_res_master");
        do_cross_check_keycalc(&client_session, &server_session, tls_secret_resumption, "tls_secret_resumption");

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
    const OPTION& option = _cmdline->value();

    TLS_OPTION testvector[] = {
        // tested

        {tls_13, "TLS_AES_128_CCM_8_SHA256"},
        {tls_13, "TLS_AES_128_CCM_SHA256"},
        {tls_13, "TLS_AES_128_GCM_SHA256"},
        {tls_13, "TLS_AES_256_GCM_SHA384"},
        {tls_13, "TLS_CHACHA20_POLY1305_SHA256"},

        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
        {tls_12, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
        {tls_12, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"},
        {tls_12, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},

        // TLS 1.2, httpserver1, curl
        // SSLKEYLOGFILE=sslkeylog curl -s https://localhost:9000/ -v --tlsv1.2 --tls-max 1.2 --http1.1 -k --ciphers TLS_ECDHE_ECDSA_WITH_AES_256_CCM

        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"},
        {tls_12, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"},
        {tls_12, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"},

#if 1
        // no test vector (feat. s_server and s_client)
        // so the actual authenticity cannot be verified...

        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"},
        {tls_12, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"},
#endif
    };

    auto tlsadvisor = tls_advisor::get_instance();
    for (auto item : testvector) {
        tlsadvisor->set_ciphersuites(item.cipher_suite.c_str());

        test_construct_tls_routine(item, "secp256r1");
        test_construct_tls_routine(item, "secp384r1");
        test_construct_tls_routine(item, "secp521r1");
        test_construct_tls_routine(item, "x25519");
        test_construct_tls_routine(item, "x448");
        if (option.test_ffdhe) {
            test_construct_tls_routine(item, "ffdhe2048");
            test_construct_tls_routine(item, "ffdhe3072");
            test_construct_tls_routine(item, "ffdhe4096");
            test_construct_tls_routine(item, "ffdhe6144");
            test_construct_tls_routine(item, "ffdhe8192");
        }

#if 0
        test_construct_tls_routine(item, (tls_13 == item.version) ? "brainpoolP256r1tls13" : "brainpoolP512r1");
        test_construct_tls_routine(item, (tls_13 == item.version) ? "brainpoolP384r1tls13" : "brainpoolP384r1");
        test_construct_tls_routine(item, (tls_13 == item.version) ? "brainpoolP512r1tls13" : "brainpoolP256r1");
#else
        if (tls_12 == item.version) {
            test_construct_tls_routine(item, "brainpoolP512r1");
            test_construct_tls_routine(item, "brainpoolP384r1");
            test_construct_tls_routine(item, "brainpoolP256r1");
        }
#endif
    }
}

void test_construct_tls13_mlkem() {
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    TLS_OPTION testvector[] = {
        {tls_13, "TLS_AES_128_CCM_8_SHA256"}, {tls_13, "TLS_AES_128_CCM_SHA256"},       {tls_13, "TLS_AES_128_GCM_SHA256"},
        {tls_13, "TLS_AES_256_GCM_SHA384"},   {tls_13, "TLS_CHACHA20_POLY1305_SHA256"},
    };

    auto tlsadvisor = tls_advisor::get_instance();
    for (auto item : testvector) {
        tlsadvisor->set_ciphersuites(item.cipher_suite.c_str());

        test_construct_tls_routine(item, "MLKEM512");
        test_construct_tls_routine(item, "MLKEM768");
        test_construct_tls_routine(item, "MLKEM1024");

        test_construct_tls_routine(item, "SecP256r1MLKEM768");
        test_construct_tls_routine(item, "X25519MLKEM768");
        test_construct_tls_routine(item, "SecP384r1MLKEM1024");
    }

    tlsadvisor->set_default_ciphersuites();  // allow all possible cipher suites
    tlsadvisor->set_default_tls_groups();    // allow all possible groups

#else
    _test_case.begin("TLS 1.3 keyshare MLKEM");
    _test_case.test(errorcode_t::not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_construct_tls() {
    test_construct_tls();
    test_construct_tls13_mlkem();
}
