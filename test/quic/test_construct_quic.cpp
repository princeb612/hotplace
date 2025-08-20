/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

static int max_udp_payload_size = 1200;

void construct_quic_initial_client_hello(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    auto lambda = [&](tls_handshake* handshake, tls_direction_t dir) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            if (nullptr == handshake) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }

            {
                auto quic_params = new tls_extension_quic_transport_parameters(handshake);
                (*quic_params)
                    .set(quic_param_disable_active_migration, binary_t())
                    .set(quic_param_initial_source_connection_id, binary_t())
                    .set(quic_param_max_idle_timeout, 120000)
                    .set(quic_param_max_udp_payload_size, max_payload_size)
                    .set(quic_param_active_connection_id_limit, 2)
                    .set(quic_param_initial_max_data, 0xc0000)
                    .set(quic_param_initial_max_stream_data_bidi_local, 0x80000)
                    .set(quic_param_initial_max_stream_data_bidi_remote, 0x80000)
                    .set(quic_param_initial_max_stream_data_uni, 0x80000)
                    .set(quic_param_initial_max_streams_bidi, 100)
                    .set(quic_param_initial_max_streams_uni, 100);
                handshake->get_extensions().add(quic_params);
            }
            {
                auto sni = new tls_extension_sni(handshake);
                auto& hostname = sni->get_hostname();
                hostname = "test.server.com";
                handshake->get_extensions().add(sni);
            }
            {
                auto extension = new tls_extension_alpn(handshake);
                binary_t protocols;
                binary_append(protocols, uint8(2));
                binary_append(protocols, "h3");
                extension->set_protocols(protocols);
                handshake->get_extensions().add(extension);
            }
        }
        __finally2 {}
        return ret;
    };

    quic_packet_publisher publisher;
    tls_handshake* handshake = nullptr;

    tls_composer::construct_client_hello(&handshake, session, lambda, tls_13, tls_13);

    // CRYPTO[CH], PADDING
    publisher.set_session(session)
        .set_payload_size(max_payload_size)
        .set_flags(quic_packet_flag_t::quic_pad_packet)  // add a padding frame and make a packet max_udp_payload_size
        .add(handshake)
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            auto tlsadvisor = tls_advisor::get_instance();
            auto test = max_udp_payload_size == packet.size();
            _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
        });
}

void construct_quic_initial_server_hello(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;
    tls_handshake* handshake = nullptr;

    tls_composer::construct_server_hello(&handshake, session, nullptr, tls_13, tls_13);

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    // ACK, CRYPTO[SH], PADDING
    publisher.set_session(session)
        .set_payload_size(max_payload_size)
        .set_flags(quic_ack_packet | quic_pad_packet)
        .add(handshake)
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            auto tlsadvisor = tls_advisor::get_instance();
            auto test = max_udp_payload_size == packet.size();
            _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
        });
}

void construct_quic_handshake_ee_cert_cv_fin_settings(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);
    publisher.set_session(session).set_payload_size(max_payload_size).set_flags(quic_ack_packet | quic_pad_packet).set_streaminfo(0x3, h3_control_stream);

    {
        // EE
        {
            auto handshake = new tls_handshake_encrypted_extensions(session);
            // SNI
            {
                auto sni = new tls_extension_sni(handshake);
                auto& hostname = sni->get_hostname();
                hostname = "";
                handshake->get_extensions().add(sni);
            }
            // ALPN
            {
                auto extension = new tls_extension_alpn(handshake);
                binary_t protocols;
                binary_append(protocols, uint8(2));
                binary_append(protocols, "h3");
                extension->set_protocols(protocols);
                handshake->get_extensions().add(extension);
            }
            // QUIC parameters
            {
                auto quic_params = new tls_extension_quic_transport_parameters(handshake);
                (*quic_params)
                    .set(quic_param_initial_max_stream_data_bidi_local, 0x20000)
                    .set(quic_param_stateless_reset_token, binary_t())
                    .set(quic_param_initial_max_stream_data_uni, 0x20000)
                    .set(quic_param_initial_source_connection_id, binary_t())
                    .set(quic_param_version_information, binary_t())
                    .set(quic_param_initial_max_data, 0x30000)
                    .set(quic_param_original_destination_connection_id, binary_t())
                    .set(quic_param_max_idle_timeout, 240000)
                    .set(quic_param_initial_max_streams_uni, 103)
                    .set(quic_param_initial_max_stream_data_bidi_remote, 0x20000)
                    .set(quic_param_google_version, binary_t())
                    .set(quic_param_max_datagram_frame_size, 0x10000)
                    .set(quic_param_max_udp_payload_size, max_udp_payload_size)
                    .set(quic_param_initial_max_streams_bidi, 100);
                handshake->get_extensions().add(quic_params);
            }
            publisher << handshake;
        }
        // CERT
        {
            auto handshake = new tls_handshake_certificate(session);
            publisher << handshake;
        }
        // CV
        {
            auto handshake = new tls_handshake_certificate_verify(session);
            publisher << handshake;
        }
        // FIN
        {
            auto handshake = new tls_handshake_finished(session);
            publisher << handshake;
        }
    }

    // PACKET.handshake + PACKET.1-RTT
    {
        auto& dyntable = session->get_quic_session().get_dynamic_table();
        http3_frame_builder builder;
        auto frame = (http3_frame_settings*)builder.set(h3_frame_settings).set(&dyntable).build();
        if (frame) {
            (*frame)
                .set(h3_settings_qpack_max_table_capacity, 0x10000)
                .set(h3_settings_max_field_section_size, 0x10000)
                .set(h3_settings_qpack_blocked_streams, 100)
                .set(h3_settings_enable_connect_protocol, 1)
                .set(h3_settings_h3_datagram, 1);

            publisher << frame;
        }
    }

    // CRYPTO[EE, CERT]
    // CRYPTO[CERT]
    // ...
    // CRYPTO[CERT, CV, FIN], PADDING
    publisher.publish(dir, [&](tls_session* session, binary_t& packet) -> void {
        bins.push_back(packet);
        auto tlsadvisor = tls_advisor::get_instance();
        _test_case.assert(true, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
    });
}

void construct_quic_handshake_fin(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    quic_packet_publisher publisher;

    // ACK, CRYPTO[FIN], PADDING
    publisher.set_session(session)
        .set_payload_size(max_payload_size)
        .set_flags(quic_ack_packet | quic_pad_packet)
        .add(new tls_handshake_finished(session))
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            auto tlsadvisor = tls_advisor::get_instance();
            auto test = max_udp_payload_size == packet.size();
            _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
        });
}

void construct_quic_ack(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    quic_packet_publisher publisher;

    // ACK, PADDING
    publisher.set_session(session)
        .set_payload_size(max_payload_size)
        .set_flags(quic_ack_packet | quic_pad_packet)
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            auto tlsadvisor = tls_advisor::get_instance();
            auto test = max_udp_payload_size == packet.size();
            _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
        });
}

return_t send_packet(tls_session* session, tls_direction_t dir, const std::list<binary_t>& bins, const char* message) {
    return_t ret = errorcode_t::success;
    for (auto item : bins) {
        quic_packets packets;
        ret = packets.read(session, dir, item);
        auto tlsadvisor = tls_advisor::get_instance();
        auto test = max_udp_payload_size == item.size();
        _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", item.size(), tlsadvisor->nameof_direction(dir, 1).c_str(), message);
    }
    return ret;
}

void test_construct_quic() {
    // understanding ...

    // PKN
    //      initial handshake application
    // curl 0...I   I+1...H   H+1...
    // test 10...I  20...H    30...A

    // TODO
    // - case payload.size < 16

    _test_case.begin("construct");

    __try2 {
        return_t ret = errorcode_t::success;

        tls_advisor::get_instance()->enable_alpn("h3");

        load_certificate("rsa.crt", "rsa.key", nullptr);
        load_certificate("ecdsa.crt", "ecdsa.key", nullptr);

        std::list<binary_t> bins;
        tls_session session_client(session_type_quic);
        tls_session session_server(session_type_quic);

        session_client.get_quic_session().get_setting().set(quic_param_max_udp_payload_size, max_udp_payload_size);
        session_server.get_quic_session().get_setting().set(quic_param_max_udp_payload_size, max_udp_payload_size);

        // set PKN for a test
        session_client.set_recordno(from_client, 10, protection_initial);
        session_client.set_recordno(from_client, 20, protection_handshake);
        session_client.set_recordno(from_client, 30, protection_application);
        session_server.set_recordno(from_server, 10, protection_initial);
        session_server.set_recordno(from_server, 20, protection_handshake);
        session_server.set_recordno(from_server, 30, protection_application);

        auto lambda = [](tls_session* session, tls_direction_t dir, protection_space_t space, uint32 pkn_expect) -> void {
            uint32 pkn = session->get_recordno(dir, false, space);
            _test_case.assert(pkn_expect == pkn, __FUNCTION__, "PKN %i", pkn);
        };

        // initial
        {
            // C->S PKN#10
            lambda(&session_client, from_client, protection_initial, 10);
            construct_quic_initial_client_hello(&session_client, from_client, bins, "initial [CRYPTO(CH), PADDING]");
            ret = send_packet(&session_server, from_client, bins, "initial [CRYPTO(CH), PADDING]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // S->C PKN#10 (ACK 10)
            lambda(&session_server, from_server, protection_initial, 10);
            construct_quic_initial_server_hello(&session_server, from_server, bins, "initial [ACK, CRYPTO(SH), PADDING]");
            ret = send_packet(&session_client, from_server, bins, "initial [ACK, CRYPTO(SH), PADDING]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                auto& pkns = session_server.get_quic_session().get_pkns(protection_initial);
                ack_t ack;
                ack << pkns;
                ack_t expect(10, 0);
                _test_case.assert(ack == expect, __FUNCTION__, "ack");
            }

            // C->S PKN#11 (ACK 10)
            lambda(&session_client, from_client, protection_initial, 11);
            construct_quic_ack(&session_client, from_client, bins, "initial [ACK]");
            ret = send_packet(&session_server, from_client, bins, "initial [ACK]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                auto& pkns = session_server.get_quic_session().get_pkns(protection_initial);
                ack_t ack;
                ack << pkns;
                ack_t expect(10, 0);
                _test_case.assert(ack == expect, __FUNCTION__, "ack initial");
            }
        }

        // handshake
        {
            // S->C PKN#20, 21 handshake(fragmented), 30 1-RTT
            lambda(&session_server, from_server, protection_handshake, 20);
            lambda(&session_server, from_server, protection_application, 30);
            construct_quic_handshake_ee_cert_cv_fin_settings(&session_server, from_server, bins, "handshake [CRYPTO(EE, CERT, CV, FIN)], 1-RTT [SETTINGS]");
            _test_case.assert(2 == bins.size(), __FUNCTION__, "construct handshake+1-RTT");
            ret = send_packet(&session_client, from_server, bins, "handshake [CRYPTO(EE, CERT, CV, FIN)], 1-RTT [SETTINGS]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // C->S PKN#20 (ACK 20, 21)
            lambda(&session_client, from_client, protection_handshake, 20);
            construct_quic_handshake_fin(&session_client, from_client, bins, "handshake ACK, [CRYPTO(FIN)]");
            ret = send_packet(&session_server, from_client, bins, "handshake ACK, [CRYPTO(FIN)]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            {
                auto& pkns = session_client.get_quic_session().get_pkns(protection_handshake);
                ack_t ack;
                ack << pkns;
                ack_t expect(21, 1);
                _test_case.assert(ack == expect, __FUNCTION__, "ack handshake");
            }
            {
                auto& pkns = session_client.get_quic_session().get_pkns(protection_application);
                ack_t ack;
                ack << pkns;
                ack_t expect(30, 0);
                _test_case.assert(ack == expect, __FUNCTION__, "ack 1-RTT");
            }

            // S->C PKN#22 (ACK 20)
            lambda(&session_server, from_server, protection_handshake, 22);
            construct_quic_ack(&session_server, from_server, bins, "handshake [ACK]");
            ret = send_packet(&session_client, from_server, bins, "handshake [ACK]");
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
    }
    __finally2 {}
}
