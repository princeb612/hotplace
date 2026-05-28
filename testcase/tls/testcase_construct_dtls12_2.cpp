/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_construct_dtls12_2.cpp
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

static return_t do_test_construct_client_hello(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;

    __try2 {
        // tls_advisor* tlsadvisor = tls_advisor::get_instance();
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

static return_t do_test_construct_from_server_hello_to_server_hello_done(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;

    __try2 {
        tls_record_handshake record(session);
        tls_handshake* handshake = nullptr;

        ret = tls_composer::construct_server_hello(&handshake, session, nullptr, tls_12, tls_12);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        record  //
            .add(handshake)
            .add(tls_handshake_type_t::certificate, session)
            .add(tls_handshake_type_t::server_key_exchange, session)
            .add(tls_handshake_type_t::server_hello_done, session);

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_from_client_key_exchange_to_finished(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_records records;
        records
            .add(tls_content_type_t::handshake, session,
                 [&](tls_record* record) -> return_t {
                     (*(tls_record_handshake*)record).add(tls_handshake_type_t::client_key_exchange, session);
                     return errorcode_t::success;
                 })
            .add(tls_content_type_t::change_cipher_spec, session)
            .add(tls_content_type_t::handshake, session,  //
                 [&](tls_record* record) -> return_t {
                     (*(tls_record_handshake*)record).add(tls_handshake_type_t::finished, session);
                     return errorcode_t::success;
                 });

        ret = construct_record_fragmented(&records, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }
    __finally2 {
        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_from_change_cipher_spec_to_finished(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    __try2 {
        tls_records records;
        records.add(tls_content_type_t::change_cipher_spec, session)
            .add(tls_content_type_t::handshake, session,  //
                 [&](tls_record* record) -> return_t {
                     (*(tls_record_handshake*)record).add(tls_handshake_type_t::finished, session);
                     return errorcode_t::success;
                 });

        ret = construct_record_fragmented(&records, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
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
        auto lambda_test_fatal_alert = [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
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

void do_test_construct_dtls12_2(uint32 flags) {
    tls_session session_client(session_type_t::dtls);
    tls_session session_server(session_type_t::dtls);

    session_client.get_dtls_record_publisher().set_flags(flags);
    session_server.get_dtls_record_publisher().set_flags(flags);
    session_client.get_dtls_record_publisher().set_fragment_size(128);
    session_server.get_dtls_record_publisher().set_fragment_size(128);

    // tls_advisor* tlsadvisor = tls_advisor::get_instance();

    return_t ret = errorcode_t::success;

    __try2 {
        // C->S, record epoch 0, sequence 0..1, handshake sequence 0
        ret = do_test_construct_client_hello(&session_client, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // S->C, record epoch 0, sequence 0, handshake sequence 0
        ret = do_test_construct_hello_verify_request(&session_server, from_server, "hello verify request");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "hello verify request");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // C->S, record epoch 0, sequence 2..3, handshake sequence 1
        ret = do_test_construct_client_hello(&session_client, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // S->C
        // case dtls_record_publisher().set_flags(0)
        // record epoch 0, sequence 1..13, handshake sequence 1..4
        //   server_hello        record epoch 0, sequence 1, handshake sequence 1
        //   certificate         record epoch 0, sequence 2..9, handshake sequence 2
        //   server_key_exchange record epoch 0, sequence 10..12, handshake sequence 3
        //   server_hello_done   record epoch 0, sequence 13, handshake sequence 4
        //
        // case dtls_record_publisher().set_flags(dtls_record_publisher_multi_handshakes)
        // record epoch 0, sequence 1..10, handshake sequence 1..4
        //   server_hello        record epoch 0, sequence 1, handshake sequence 1
        //   certificate         record epoch 0, sequence 1..8, handshake sequence 2
        //   server_key_exchange record epoch 0, sequence 8..10, handshake sequence 3
        //   server_hello_done   record epoch 0, sequence 10, handshake sequence 4
        //   -> tls_record_handshake (epoch 0, sequence 1) contains server_hello and certificate (handshake sequences in order 1, 2)
        //   -> tls_record_handshake (epoch 0, sequence 8) contains certificate and server_key_exchange (handshake sequences in order 2, 3)
        //   -> tls_record_handshake (epoch 0, sequence 10) contains server_key_exchange and server_hello_done (handshake sequences in order 3, 4)
        ret = do_test_construct_from_server_hello_to_server_hello_done(&session_server, from_server, "server hello, certificate, server key exchange, server hello done");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "server hello, certificate, server key exchange, server hello done");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::transcript_hash, "tls_secret_t::transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::client_hello_random, "tls_secret_t::client_hello_random");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::server_hello_random, "tls_secret_t::server_hello_random");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::empty_hash, "tls_secret_t::empty_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::transcript_hash, "tls_secret_t::transcript_hash");

        // C->S
        // case dtls_record_publisher().set_flags(0)
        // case dtls_record_publisher().set_flags(dtls_record_publisher_multi_handshakes)
        //  client_key_exchange record epoch 0, sequence 4, handshake sequence 2
        //  change_ciphee_spec  record epoch 0, sequence 5
        //  finished            record epoch 1, sequence 0, handshake sequence 3
        ret = do_test_construct_from_client_key_exchange_to_finished(&session_client, from_client, "client key exchange, change cipher spec, finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "client key exchange, change cipher spec, finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::transcript_hash, "tls_secret_t::transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::server_key, "tls_secret_t::server_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::server_mac_key, "tls_secret_t::server_mac_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::client_key, "tls_secret_t::client_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::client_mac_key, "tls_secret_t::client_mac_key");

        // S->C
        // case dtls_record_publisher().set_flags(0)
        //  change_ciphee_spec  record epoch 0, sequence 14, change cipher spec
        //  finished            epoch 1, sequence 0, handshake sequence 5
        //
        // case dtls_record_publisher().set_flags(dtls_record_publisher_multi_handshakes)
        //  change_ciphee_spec  record epoch 0, sequence 11, change cipher spec
        //  finished            epoch 1, sequence 0, handshake sequence 5
        ret = do_test_construct_from_change_cipher_spec_to_finished(&session_server, from_server, "change cipher spec, finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "change cipher spec, finished");
        if (errorcode_t::success != ret) {
            __leave2;
        }

        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::transcript_hash, "tls_secret_t::transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::res_master, "tls_secret_t::res_master");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_t::resumption, "tls_secret_t::resumption");

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

void testcase_construct_dtls12_2() {
    // tasks
    //  [x] dtls_record_publisher
    //    [x] each handshake starts a new record (easy to control max record size)
    //    [x] record consist of handshakes in the segment
    //  [x] finished
    _test_case.begin("construct DTLS 1.2 (record-handshake 1..1)");
    do_test_construct_dtls12_2(0);
    _test_case.begin("construct DTLS 1.2 (record-handshake 1..*)");
    do_test_construct_dtls12_2(dtls_record_publisher_multi_handshakes);
}
