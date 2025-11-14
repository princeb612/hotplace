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

    __try2 {
        tls_advisor* tlsadvisor = tls_advisor::get_instance();
        auto& protection = session->get_tls_protection();

        tls_record_handshake record(session);
        record.set_tls_version(option.version);
        ret =
            record
                .add(tls_hs_client_hello, session,
                     [&](tls_handshake* hs) -> return_t {
                         auto handshake = (tls_handshake_client_hello*)hs;

                         if (option.cipher_suite.empty()) {
                             *handshake << "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
                                        << "TLS_CHACHA20_POLY1305_SHA256"
                                        << "TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256";
                         } else {
                             handshake->add_ciphersuites(option.cipher_suite.c_str());
                         }

                         handshake->get_extensions()
                             .add(tls_ext_ec_point_formats, dir, handshake,
                                  // ec_point_formats
                                  // RFC 9325 4.2.1
                                  // Note that [RFC8422] deprecates all but the uncompressed point format.
                                  // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element,
                                  // "uncompressed".
                                  [](tls_extension* extension) -> return_t {
                                      (*(tls_extension_ec_point_formats*)extension).add("uncompressed");
                                      return success;
                                  })
                             .add(
                                 tls_ext_supported_groups, dir, handshake,
                                 // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
                                 [](tls_extension* extension) -> return_t {
                                     (*(tls_extension_supported_groups*)extension).add("x25519").add("secp256r1").add("x448").add("secp521r1").add("secp384r1");
                                     return success;
                                 })
                             .add(tls_ext_signature_algorithms, dir, handshake, [](tls_extension* extension) -> return_t {
                                 (*(tls_extension_signature_algorithms*)extension)
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
                                 return success;
                             });

                         if (tlsadvisor->is_kindof(tls_13, option.version)) {
                             handshake->get_extensions()
                                 .add(tls_ext_supported_versions, dir, handshake,
                                      [&](tls_extension* extension) -> return_t {
                                          (*(tls_extension_client_supported_versions*)extension).add(dtls_13);
                                          return success;
                                      })
                                 .add(tls_ext_psk_key_exchange_modes, dir, handshake,
                                      [](tls_extension* extension) -> return_t {
                                          (*(tls_extension_psk_key_exchange_modes*)extension).add("psk_dhe_ke");
                                          return success;
                                      })
                                 .add(tls_ext_key_share, dir, handshake, [&](tls_extension* extension) -> return_t {
                                     tls_extension_client_key_share* keyshare = (tls_extension_client_key_share*)extension;
                                     if (tls_flow_hello_retry_request != protection.get_flow()) {
                                         keyshare->clear();
                                         keyshare->add("x25519");
                                     }
                                     return success;
                                 });

                             {
                                 auto pkey = session->get_tls_protection().get_key().find(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
                                 _logger->write([&](basic_stream& bs) -> void { dump_key(pkey, &bs); });
                                 _test_case.assert(pkey, __FUNCTION__, "{client} key share (client generated)");
                             }
                         }

                         return success;
                     })
                .write(dir, bin);
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
        uint16 server_cs = 0;
        uint16 server_version = 0;

        auto& protection = session->get_tls_protection();
        protection.set_tls_version(option.version);
        protection.negotiate(session, server_cs, server_version);

        if (0x0000 == server_cs) {
            ret = errorcode_t::unknown;
            _test_case.test(ret, __FUNCTION__, "no cipher suite");
            __leave2;
        }

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto csname = tlsadvisor->nameof_tls_cipher_suite(server_cs);
            _test_case.assert(csname.size(), __FUNCTION__, "%s", csname.c_str());
        }

        tls_record_handshake record(session);
        record.set_tls_version(option.version);
        ret = record
                  .add(tls_hs_server_hello, session,
                       [&](tls_handshake* hs) -> return_t {
                           auto handshake = (tls_handshake_server_hello*)hs;

                           handshake->set_cipher_suite(server_cs);

                           handshake->get_extensions()
                               .add(tls_ext_supported_versions, dir, handshake,
                                    [&](tls_extension* extension) -> return_t {
                                        (*(tls_extension_server_supported_versions*)extension).set(server_version);
                                        return success;
                                    })
                               .add(tls_ext_key_share, dir, handshake,  //
                                    [](tls_extension* extension) -> return_t {
                                        auto keyshare = (tls_extension_server_key_share*)extension;
                                        keyshare->clear();
                                        keyshare->add_keyshare();
                                        return success;
                                    });

                           return success;
                       })
                  .write(dir, bin);

        {
            auto pkey = session->get_tls_protection().get_key().find(KID_TLS_SERVERHELLO_KEYSHARE_PRIVATE);
            _logger->write([&](basic_stream& bs) -> void { dump_key(pkey, &bs); });
            _test_case.assert(pkey, __FUNCTION__, "{server} key share (server generated)");
        }
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
        if (nullptr == session || nullptr == message) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        dtls13_ciphertext record(tls_content_type_handshake, session);
        record.add(tls_hs_encrypted_extensions, session,  //
                   [&](tls_handshake* handshake) -> return_t {
                       (*handshake)
                           .get_extensions()
                           .add(tls_ext_supported_groups, dir, handshake,  //
                                [](tls_extension* extension) -> return_t {
                                    (*(tls_extension_supported_groups*)extension).add("x25519").add("secp256r1").add("x448").add("secp521r1").add("secp384r1");
                                    return success;
                                });
                       return success;
                   });
        ret = record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 1, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_certificate(tls_session* session, tls_direction_t dir, tls_content_type_t content_type, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        dtls13_ciphertext record(content_type, session);
        record.add(tls_hs_certificate, session);
        ret = record.write(dir, bin);
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

        dtls13_ciphertext record(tls_content_type_handshake, session);
        record.add(tls_hs_certificate_verify, session);
        ret = record.write(dir, bin);
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

        dtls13_ciphertext record(tls_content_type_handshake, session);
        record.add(tls_hs_finished, session);
        ret = record.write(dir, bin);
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

        dtls13_ciphertext record(tls_content_type_handshake, session);
        record.add(tls_hs_finished, session);
        ret = record.write(dir, bin);
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_ack(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        dtls13_ciphertext record(tls_content_type_ack, session);
        record.add(tls_content_type_ack, session);
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

        dtls13_ciphertext record(tls_content_type_application_data, session);
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

        dtls13_ciphertext record(tls_content_type_application_data, session);
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

        dtls13_ciphertext record(tls_content_type_alert, session);
        record.get_records().add(new tls_record_alert(session, tls_alertlevel_warning, tls_alertdesc_close_notify));
        ret = record.write(dir, bin);
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
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 1, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

void test_construct_dtls_routine(const TLS_OPTION& option) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto ver = tlsadvisor->nameof_tls_version(option.version);
    auto hint = tlsadvisor->hintof_cipher_suite(option.cipher_suite);
    _test_case.begin("construct %s %s", ver.c_str(), hint->name_iana);

    return_t ret = errorcode_t::success;

    __try2 {
        tls_session client_session(session_type_dtls);
        tls_session server_session(session_type_dtls);

        // C -> S CH
        binary_t bin_client_hello;
        ret = do_test_construct_client_hello(option, &client_session, from_client, bin_client_hello, "construct client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        do_test_send_record(&server_session, from_client, bin_client_hello, "send client hello");

        // S -> C SH
        binary_t bin_server_hello;
        ret = do_test_construct_server_hello(option, &server_session, from_server, bin_server_hello, "construct server hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        do_test_send_record(&client_session, from_server, bin_server_hello, "send server hello");

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

        // S->C C
        binary_t bin_encrypted_extensions;
        do_test_construct_encrypted_extensions(&server_session, from_server, bin_encrypted_extensions, "construct encrypted_extensions");
        do_test_send_record(&client_session, from_server, bin_encrypted_extensions, "send encrypted_extensions");

        {
            //
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
        }

        // S -> C SC
        binary_t bin_certificate;
        do_test_construct_certificate(&server_session, from_server, tls_content_type_handshake, bin_certificate, "construct certificate");
        do_test_send_record(&client_session, from_server, bin_certificate, "send cerficate");

        {
            //
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
        }

        // S -> C SCV
        binary_t bin_certificate_verify;
        do_test_construct_certificate_verify(&server_session, from_server, bin_certificate_verify, "construct certificate verify");
        do_test_send_record(&client_session, from_server, bin_certificate_verify, "send cerficate verify");

        {
            //
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
        }

        // S -> C SF
        binary_t bin_server_finished;
        do_test_construct_server_finished(&server_session, from_server, bin_server_finished, "construct server finished");
        do_test_send_record(&client_session, from_server, bin_server_finished, "send server finished");

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

        // C -> S CF
        binary_t bin_client_finished;
        do_test_construct_client_finished(&client_session, from_client, bin_client_finished, "construct client finished");
        do_test_send_record(&server_session, from_client, bin_client_finished, "send client finished");

        {
            do_cross_check_keycalc(&client_session, &server_session, tls_context_transcript_hash, "tls_context_transcript_hash");
            // do_cross_check_keycalc(&client_session, &server_session, tls_secret_res_master, "tls_secret_res_master");
            // do_cross_check_keycalc(&client_session, &server_session, tls_secret_resumption, "tls_secret_resumption");
        }

        // C->S ack
        binary_t bin_client_ack;
        do_test_construct_ack(&client_session, from_client, bin_client_ack, "construct client ack");
        do_test_send_record(&server_session, from_client, bin_client_ack, "send client ack");

        // C->S ping
        binary_t bin_client_ping;
        do_test_construct_client_ping(&client_session, from_client, bin_client_ping, "construct client ping");
        do_test_send_record(&server_session, from_client, bin_client_ping, "send client ping");

        // C<-S pong
        binary_t bin_server_pong;
        do_test_construct_server_pong(&server_session, from_server, bin_server_pong, "construct server pong");
        do_test_send_record(&client_session, from_server, bin_server_pong, "send server pong");

        // S->C close notify
        binary_t bin_server_close_notify;
        do_test_construct_close_notify(&server_session, from_server, bin_server_close_notify, "construct server close notify");
        do_test_send_record(&client_session, from_server, bin_server_close_notify, "send server close notify");
    }
    __finally2 {}
}

void test_construct_dtls13() {
    TLS_OPTION testvector[] = {
        {dtls_13, "TLS_AES_128_CCM_8_SHA256"},      //
        {dtls_13, "TLS_AES_128_CCM_SHA256"},        //
        {dtls_13, "TLS_AES_128_GCM_SHA256"},        //
        {dtls_13, "TLS_AES_256_GCM_SHA384"},        //
        {dtls_13, "TLS_CHACHA20_POLY1305_SHA256"},  //
    };

    for (auto item : testvector) {
        test_construct_dtls_routine(item);
    }
}
