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

#include <random>

#include "sample.hpp"
#include "udp_traffic.hpp"

static udp_traffic _traffic;

static return_t do_test_construct_client_hello(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    tls_handshake_client_hello* handshake = nullptr;

    __try2 {
        __try_new_catch(handshake, new tls_handshake_client_hello(session), ret, __leave2);

        {
            // client_hello generate random member

            const auto& cookie = session->get_tls_protection().get_item(tls_context_cookie);
            if (false == cookie.empty()) {
                handshake->set_cookie(cookie);
            }
        }

        // cipher suites
        {
            *handshake  // << "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
                        // << "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"
                        // << "TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_AES_256_CCM"
                        // << "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"
                        // << "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
                << "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
                << "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
                << "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
        }

        {
            auto renegotiation_info = new tls_extension_renegotiation_info(session);
            handshake->get_extensions().add(renegotiation_info);
        }
        {
            auto ec_point_formats = new tls_extension_ec_point_formats(session);
            (*ec_point_formats).add("uncompressed");
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
            // encrypt_then_mac
            handshake->get_extensions().add(new tls_extension_unknown(tls_ext_encrypt_then_mac, session));
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
            (*supported_versions).add(dtls_12);
            handshake->get_extensions().add(supported_versions);
        }
    }
    __finally2 {
        if (errorcode_t::success == ret) {
            tls_record_handshake record(session);
            record << handshake;

            ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
        }

        std::string dirstr;
        direction_string(dir, 0, dirstr);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);
    }
    return ret;
}

static return_t do_test_construct_hello_verify_request(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;

    auto handshake = new tls_handshake_hello_verify_request(session);
    if (errorcode_t::success == ret) {
        binary_t cookie;
        openssl_prng prng;
        prng.random(cookie, 20);

        handshake->set_cookie(std::move(cookie));

        tls_record_handshake record(session);
        record << handshake;

        ret = construct_record_fragmented(&record, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });
    }

    std::string dirstr;
    direction_string(dir, 0, dirstr);
    _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);

    return ret;
}

static return_t do_test_construct_from_server_hello_to_server_hello_done(tls_session* session, tls_session* client_session, tls_direction_t dir,
                                                                         const char* message) {
    return_t ret = errorcode_t::success;
    auto& protection = session->get_tls_protection();
    protection.set_tls_version(dtls_12);

    tls_record_handshake record(session);

    uint16 server_cs = 0;
    uint16 server_version = 0;
    protection.negotiate(client_session, session, server_cs, server_version);

    tls_handshake_server_hello* handshake = nullptr;

    __try2 {
        // server hello
        {
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
                // server_hello generate random member

                handshake->set_cipher_suite(server_cs);
            }

            {
                auto renegotiation_info = new tls_extension_renegotiation_info(session);
                handshake->get_extensions().add(renegotiation_info);
            }
            {
                auto ec_point_formats = new tls_extension_ec_point_formats(session);
                (*ec_point_formats).add("uncompressed");
                handshake->get_extensions().add(ec_point_formats);
            }
            {
                auto supported_groups = new tls_extension_supported_groups(session);
                (*supported_groups).add("x25519");
                handshake->get_extensions().add(supported_groups);
            }
            {
                // encrypt_then_mac
                handshake->get_extensions().add(new tls_extension_unknown(tls_ext_encrypt_then_mac, session));
            }

            record << handshake;
        }

        // certificate
        {
            auto handshake = new tls_handshake_certificate(session);
            record << handshake;
        }
        // server key exchange
        {
            //
            record << new tls_handshake_server_key_exchange(session);
        }
        // server hello done
        {
            //
            record << new tls_handshake_server_hello_done(session);
        }

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

    tls_records records;
    // client_key_exchange
    {
        auto record = new tls_record_handshake(session);
        *record << new tls_handshake_client_key_exchange(session);
        records << record;
    }
    // change_cipher_spec
    {
        auto record = new tls_record_change_cipher_spec(session);
        records << record;
    }
    // finished
    {
        auto record = new tls_record_handshake(session);
        *record << new tls_handshake_finished(session);
        records << record;
    }

    ret = construct_record_fragmented(&records, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });

    std::string dirstr;
    direction_string(dir, 0, dirstr);
    _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);

    return ret;
}

static return_t do_test_construct_from_change_cipher_spec_to_finished(tls_session* session, tls_direction_t dir, const char* message) {
    return_t ret = errorcode_t::success;

    tls_records records;
    // change_cipher_spec
    {
        auto record = new tls_record_change_cipher_spec(session);
        records << record;
    }
    // finished
    {
        auto record = new tls_record_handshake(session);
        *record << new tls_handshake_finished(session);
        records << record;
    }

    ret = construct_record_fragmented(&records, dir, [&](tls_session*, binary_t& bin) -> void { _traffic.sendto(std::move(bin)); });

    std::string dirstr;
    direction_string(dir, 0, dirstr);
    _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), message);

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
        _traffic.shuffle();
        auto lambda = [&](const binary_t& bin) { arrange.produce(&bin[0], bin.size()); };
        _traffic.consume(lambda);

        bool has_fatal = false;
        auto lambda_test_fatal_alert = [&](uint8 level, uint8 desc) -> void {
            if (tls_alertlevel_fatal == level) {
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
        uint32 retry = 10;  // max elements
        while (retry--) {
            auto test = arrange.consume(epoch, seq, bin);
            if (empty == test) {
                break;
            } else if (not_ready == test) {
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
    tls_session session_client(session_type_dtls);
    tls_session session_server(session_type_dtls);

    session_client.get_dtls_record_publisher().set_flags(flags);
    session_server.get_dtls_record_publisher().set_flags(flags);
    session_client.get_dtls_record_publisher().set_fragment_size(128);
    session_server.get_dtls_record_publisher().set_fragment_size(128);

    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    auto lambda_test_next_seq = [&](const char* func, tls_session* session, tls_direction_t dir, uint16 expect_epoch, uint64 expect_next_rcseq,
                                    uint16 expect_next_hsseq) -> void {
        uint16 rcepoch = session->get_session_info(dir).get_keyvalue().get(session_dtls_epoch);
        uint64 next_rcseq = session->get_session_info(dir).get_keyvalue().get(session_dtls_seq);
        uint16 next_hsseq = session->get_session_info(dir).get_keyvalue().get(session_dtls_message_seq);
        bool test = (expect_epoch == rcepoch) && (expect_next_hsseq == next_hsseq) && (expect_next_hsseq == next_hsseq);
        _test_case.assert(test, func, "%s record (epoch %i next sequence %I64i) handshake (next sequence %i)", tlsadvisor->nameof_direction(dir).c_str(),
                          rcepoch, next_rcseq, next_hsseq);
    };
    auto lambda_test_seq = [&](const char* func, tls_session* session, tls_direction_t dir, uint16 expect_epoch, uint64 expect_rcseq,
                               uint16 expect_hsseq) -> void {
        uint16 rcepoch = session->get_session_info(dir).get_keyvalue().get(session_dtls_epoch);
        uint64 rcseq = session->get_session_info(dir).get_keyvalue().get(session_dtls_seq);
        uint16 hsseq = session->get_session_info(dir).get_keyvalue().get(session_dtls_message_seq);
        bool test = (expect_epoch == rcepoch) && (expect_hsseq == hsseq) && (expect_hsseq == hsseq);
        _test_case.assert(test, func, "%s record (epoch %i sequence %I64i) handshake (sequence %i)", tlsadvisor->nameof_direction(dir).c_str(), rcepoch, rcseq,
                          hsseq);
    };

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
        lambda_test_next_seq(__FUNCTION__, &session_client, from_client, 0, 2, 1);
        lambda_test_seq(__FUNCTION__, &session_server, from_client, 0, 1, 0);

        // S->C, record epoch 0, sequence 0, handshake sequence 0
        ret = do_test_construct_hello_verify_request(&session_server, from_server, "hello verify request");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "hello verify request");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_test_next_seq(__FUNCTION__, &session_server, from_server, 0, 1, 1);
        lambda_test_seq(__FUNCTION__, &session_client, from_server, 0, 0, 0);

        // C->S, record epoch 0, sequence 2..3, handshake sequence 1
        ret = do_test_construct_client_hello(&session_client, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_server, from_client, "client hello");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        lambda_test_next_seq(__FUNCTION__, &session_client, from_client, 0, 4, 2);
        lambda_test_seq(__FUNCTION__, &session_server, from_client, 0, 3, 1);

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
        ret = do_test_construct_from_server_hello_to_server_hello_done(&session_server, &session_client, from_server,
                                                                       "server hello, certificate, server key exchange, server hello done");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_test_send_record(&session_client, from_server, "server hello, certificate, server key exchange, server hello done");
        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (flags & dtls_record_publisher_multi_handshakes) {
            lambda_test_next_seq(__FUNCTION__, &session_server, from_server, 0, 11, 5);
            lambda_test_seq(__FUNCTION__, &session_client, from_server, 0, 10, 4);
        } else {
            lambda_test_next_seq(__FUNCTION__, &session_server, from_server, 0, 14, 5);
            lambda_test_seq(__FUNCTION__, &session_client, from_server, 0, 13, 4);
        }

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_client_hello_random, "tls_context_client_hello_random");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_server_hello_random, "tls_context_server_hello_random");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_empty_hash, "tls_context_empty_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");

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
        lambda_test_next_seq(__FUNCTION__, &session_client, from_client, 1, 1, 4);
        lambda_test_seq(__FUNCTION__, &session_server, from_client, 1, 0, 3);

        do_cross_check_keycalc(&session_client, &session_server, tls_context_transcript_hash, "tls_context_transcript_hash");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_server_key, "tls_secret_server_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_server_mac_key, "tls_secret_server_mac_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_client_key, "tls_secret_client_key");
        do_cross_check_keycalc(&session_client, &session_server, tls_secret_client_mac_key, "tls_secret_client_mac_key");

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
        lambda_test_next_seq(__FUNCTION__, &session_server, from_server, 1, 1, 6);
        lambda_test_seq(__FUNCTION__, &session_client, from_server, 1, 0, 5);

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

void test_construct_dtls12_2() {
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
