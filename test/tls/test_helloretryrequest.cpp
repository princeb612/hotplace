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

static return_t do_test_construct_client_hello(tls_session* session, tls_direction_t dir, const char* group, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();

    tls_record_handshake record(session);
    tls_handshake_client_hello* handshake = nullptr;

    __try2 {
        __try_new_catch(handshake, new tls_handshake_client_hello(session), ret, __leave2);

        // random
        {
            openssl_prng prng;

            binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
            time_t gmt_unix_time = time(nullptr);
            binary_append(random, gmt_unix_time, hton64);
            random.resize(sizeof(uint32));
            binary_t temp;
            prng.random(temp, 28);
            binary_append(random, temp);
            handshake->set_random(random);

            binary_t session_id;
            prng.random(session_id, 32);
            handshake->set_session_id(session_id);
        }

        {
            // cipher suites
            handshake->add_ciphersuites("TLS_AES_128_GCM_SHA256");
        }

        {
            // RFC 9325 4.2.1
            // Note that [RFC8422] deprecates all but the uncompressed point format.
            // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element, "uncompressed".
            auto ec_point_formats = new tls_extension_ec_point_formats(session);
            (*ec_point_formats).add("uncompressed");
            handshake->get_extensions().add(ec_point_formats);
        }
        {
            // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
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
            auto extension = new tls_extension_unknown(tls_ext_encrypt_then_mac, session);
            handshake->get_extensions().add(extension);
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
            (*supported_versions).add(tls_13);
            handshake->get_extensions().add(supported_versions);
        }
        {
            auto psk_key_exchange_modes = new tls_extension_psk_key_exchange_modes(session);
            (*psk_key_exchange_modes).add("psk_dhe_ke");
            handshake->get_extensions().add(psk_key_exchange_modes);
        }
        {
            auto key_share = new tls_extension_client_key_share(session);
            key_share->clear();
            key_share->add(group);
            handshake->get_extensions().add(key_share);

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

static return_t do_test_construct_server_hello(tls_session* session, tls_session* client_session, tls_direction_t dir, binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;

    auto& protection = session->get_tls_protection();

    uint16 server_cs = 0;
    uint16 server_version = 0;
    protection.negotiate(client_session, session, server_cs, server_version);

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

            // server_key_exchange, client_key_exchange
            binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
            time_t gmt_unix_time = time(nullptr);
            binary_append(random, gmt_unix_time, hton64);
            random.resize(sizeof(uint32));
            binary_t temp;
            prng.random(temp, 28);
            binary_append(random, temp);
            handshake->set_random(random);

            binary_t session_id;
            prng.random(session_id, 32);
            handshake->set_session_id(session_id);

            handshake->set_cipher_suite(server_cs);
        }

        {
            auto supported_versions = new tls_extension_server_supported_versions(session);
            (*supported_versions).set(server_version);
            handshake->get_extensions().add(supported_versions);
        }
        {
            auto key_share = new tls_extension_server_key_share(session);
            key_share->clear();
            key_share->add_keyshare();
            handshake->get_extensions().add(key_share);
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

void test_helloretryrequest() {
    _test_case.begin("HelloRetryRequest");

    auto tlsadvisor = tls_advisor::get_instance();
    tls_session session_client;
    tls_session session_server;
    uint32 session_status = 0;
    tls_flow_t flow;
    std::string flow_status;
    basic_stream step;

    // enforce server key share group 0x001d "x25519"
    session_server.get_keyvalue().set(session_conf_enforce_key_share_group, 0x001d);

    {
        flow = session_server.get_tls_protection().get_flow();
        flow_status = tlsadvisor->nameof_tls_flow(flow);
        _test_case.assert(tls_flow_1rtt == flow, __FUNCTION__, "1-RTT");
    }

    {
        // client hello
        binary_t bin;
        step.clear();
        step << flow_status << " client hello";
        do_test_construct_client_hello(&session_client, from_client, "secp256r1", bin, step.c_str());
        do_test_send_record(&session_server, from_client, bin, step.c_str());
    }

    {
        // test
        session_status = session_server.get_session_status();
        _test_case.assert(session_status_client_hello == session_status, __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
    }

    {
        // server hello
        // MUST be HelloRetryRequest
        binary_t bin;
        step.clear();
        step << flow_status << " server hello";
        do_test_construct_server_hello(&session_server, &session_client, from_server, bin, step.c_str());
        do_test_send_record(&session_client, from_server, bin, step.c_str());
    }

    {
        flow = session_server.get_tls_protection().get_flow();
        flow_status = tlsadvisor->nameof_tls_flow(flow);
    }

    {
        // test
        session_status = session_server.get_session_status();
        _test_case.assert((session_status_server_hello & session_status), __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
        _test_case.assert(tls_flow_hello_retry_request == flow, __FUNCTION__, "HelloRetryRequest");
    }

    {
        // client hello
        // "x25519"
        binary_t bin;
        step.clear();
        step << flow_status << " client hello";
        do_test_construct_client_hello(&session_client, from_client, "x25519", bin, step.c_str());
        do_test_send_record(&session_server, from_client, bin, step.c_str());
    }

    {
        // test
        session_status = session_server.get_session_status();
        _test_case.assert((session_status_client_hello == session_status), __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
    }

    {
        // server hello
        binary_t bin;
        step.clear();
        step << flow_status << " server hello";
        do_test_construct_server_hello(&session_server, &session_client, from_server, bin, step.c_str());
        do_test_send_record(&session_client, from_server, bin, step.c_str());
    }

    {
        // test
        session_status = session_server.get_session_status();
        _test_case.assert((session_status_server_hello & session_status), __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
    }

    {
        flow = session_server.get_tls_protection().get_flow();
        flow_status = tlsadvisor->nameof_tls_flow(flow);
        _test_case.assert(tls_flow_1rtt == flow, __FUNCTION__, "%s", flow_status.c_str());
    }
}
