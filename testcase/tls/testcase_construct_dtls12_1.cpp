/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_construct_dtls12_1.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <random>

#include "sample.hpp"
#include "udp_traffic.hpp"

static udp_traffic _traffic;

static return_t do_test_construct_client_hello(const char* ciphersuite, tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        tls_handshake* handshake = nullptr;

        ret = tls_composer::construct_client_hello(&handshake, session, nullptr, tls_12, tls_12);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        record << handshake;

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_hello_verify_request(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        record.add(tls_handshake_type_t::hello_verify_request, session,  //
                   [&](tls_handshake* hs) -> return_t {
                       auto handshake = (tls_handshake_hello_verify_request*)hs;

                       binary_t cookie;
                       openssl_prng prng;
                       prng.random(cookie, 20);

                       handshake->set_cookie(std::move(cookie));

                       return errorcode_t::success;
                   });

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_hello(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        tls_handshake* handshake = nullptr;

        ret = tls_composer::construct_server_hello(&handshake, session, nullptr, tls_12, tls_12);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        record << handshake;

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_certificate(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        record.add(tls_handshake_type_t::certificate, session);

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_key_exchange(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        record.add(tls_handshake_type_t::server_key_exchange, session);

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_server_hello_done(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        record.add(tls_handshake_type_t::server_hello_done, session);

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_client_key_exchange(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        record.add(tls_handshake_type_t::client_key_exchange, session);

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_change_cipher_spec(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_change_cipher_spec record(session);

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_finished(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_record_handshake record(session);
        record.add(tls_handshake_type_t::finished, session);

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_send_record(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session || nullptr == message) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto& arrange = session->get_dtls_record_arrange();

        // sketch - arrange, reassemble

        // UDP traffic
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        _traffic.shuffle();
        auto lambda = [&](const binary_t& bin) { arrange.produce((sockaddr*)&addr, sizeof(addr), bin.data(), bin.size()); };
        _traffic.consume(lambda);

        bool has_fatal = false;
        auto lambda_test_fatal_alert =  //
            [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                has_fatal = true;
            }
        };
        session->get_alert(dir, lambda_test_fatal_alert);
        if (has_fatal) {
            __leave2;
        }

        // arrange
        binary_t bin;
        uint16 epoch = 0;
        uint64 seq = 0;
        while (true) {
            auto test = arrange.consume((sockaddr*)&addr, sizeof(addr), epoch, seq, bin);
            if (errorcode_t::empty == test) {
                break;
            } else if (errorcode_t::not_ready == test) {
                continue;
            }

            // _logger->hdump(format("epoch %i seq %I64i", epoch, seq).c_str(), bin, 16, 3);

            tls_records records;
            records.read(session, dir, bin);
        }
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 1, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

void do_test_construct_dtls12_1(const char* ciphersuite) {
    _test_case.begin("construct DTLS 1.2 %s (wo segmentation)", ciphersuite);

    tls_session session_client(session_type_dtls);
    tls_session session_server(session_type_dtls);

    session_client.get_dtls_record_publisher().set_fragment_size(128);
    session_server.get_dtls_record_publisher().set_fragment_size(128);

    return_t ret = errorcode_t::success;

    __try2 {
        auto lambda_check_tls_status = [&](const char* func, const char* mesg, tls_session* session, uint32 expected) -> void {
            uint32 status = session->get_session_status();
            bool test = (status & expected);
            _test_case.assert(test, func, mesg);
        };

        // C->S, record epoch 0, sequence 0..1, handshake sequence 0
        ret = do_test_construct_client_hello(ciphersuite, &session_client, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "CH", &session_client, session_status_client_hello);
        lambda_check_tls_status(__FUNCTION__, "CH", &session_server, session_status_client_hello);

        // S->C, record epoch 0, sequence 0, handshake sequence 0
        ret = do_test_construct_hello_verify_request(&session_server, from_server, "hello verify request");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "hello verify request");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "HVR", &session_client, session_status_hello_verify_request);
        lambda_check_tls_status(__FUNCTION__, "HVR", &session_server, session_status_hello_verify_request);

        // C->S, record epoch 0, sequence 2..3, handshake sequence 1
        ret = do_test_construct_client_hello(ciphersuite, &session_client, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "CH", &session_client, session_status_client_hello | session_status_hello_verify_request);
        lambda_check_tls_status(__FUNCTION__, "CH", &session_server, session_status_client_hello | session_status_hello_verify_request);

        // S->C, record epoch 0, sequence 1, handshake sequence 1
        ret = do_test_construct_server_hello(&session_server, from_server, "server hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "server hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "SH", &session_client, session_status_server_hello);
        lambda_check_tls_status(__FUNCTION__, "SH", &session_server, session_status_server_hello);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_client_hello_random, "tls_context_client_hello_random");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_server_hello_random, "tls_context_server_hello_random");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_empty_hash, "tls_context_empty_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");

        // S->C, record epoch 0, sequence 2..8, handshake sequence 2
        ret = do_test_construct_certificate(&session_server, from_server, "certificate");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "certificate");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "SC", &session_client, session_status_server_cert);
        lambda_check_tls_status(__FUNCTION__, "SC", &session_server, session_status_server_cert);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");

        // S->C, record epoch 0, sequence 9..11, handshake sequence 3
        ret = do_test_construct_server_key_exchange(&session_server, from_server, "server key exchange");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "server key exchange");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "SKE", &session_client, session_status_server_key_exchange);
        lambda_check_tls_status(__FUNCTION__, "SKE", &session_server, session_status_server_key_exchange);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");

        // S->C, record epoch 0, sequence 12, handshake sequence 4
        ret = do_test_construct_server_hello_done(&session_server, from_server, "server hello done");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "server hello done");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "SHD", &session_client, session_status_server_hello_done);
        lambda_check_tls_status(__FUNCTION__, "SHD", &session_server, session_status_server_hello_done);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");

        // C->S, record epoch 0, sequence 4, handshake sequence 2
        ret = do_test_construct_client_key_exchange(&session_client, from_client, "client key exchange");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "client key exchange");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "CKE", &session_client, session_status_client_key_exchange);
        lambda_check_tls_status(__FUNCTION__, "CKE", &session_server, session_status_client_key_exchange);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_server_key, "tls_secret_server_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_server_mac_key, "tls_secret_server_mac_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_client_key, "tls_secret_client_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_client_mac_key, "tls_secret_client_mac_key");

        // C->S, record epoch 0, sequence 5, change cipher spec
        ret = do_test_construct_change_cipher_spec(&session_client, from_client, "change cipher spec");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "change cipher spec");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");

        // C->S, record epoch 1, sequence 0, handshake sequence 3
        ret = do_test_construct_finished(&session_client, from_client, "finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "CF", &session_client, session_status_client_finished);
        lambda_check_tls_status(__FUNCTION__, "CF", &session_server, session_status_client_finished);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");

        // S->C, record epoch 0, sequence 13, change cipher spec
        ret = do_test_construct_change_cipher_spec(&session_server, from_server, "change cipher spec");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "change cipher spec");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // S->C, record epoch 1, sequence 0, handshake sequence 5
        ret = do_test_construct_finished(&session_server, from_server, "finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_check_tls_status(__FUNCTION__, "SF", &session_client, session_status_server_finished);
        lambda_check_tls_status(__FUNCTION__, "SF", &session_server, session_status_server_finished);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_res_master, "tls_secret_res_master");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_resumption, "tls_secret_resumption");

        // skip followings
        // - application data
        // - alert close_notify
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            _test_case.test(ret, __FUNCTION__, "DTLS 1.2 construction");
        }
    }
}

void testcase_construct_dtls12_1() {
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");

    // TLS 1.2, httpserver1, curl

    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_256_CCM");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256");
    do_test_construct_dtls12_1("TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384");

#if 1
    // curl - no ciphers available
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
    do_test_construct_dtls12_1("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8");
#endif
}
