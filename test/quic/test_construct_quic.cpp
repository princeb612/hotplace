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

    auto lambda = [&](tls_handshake* handshake, tls_direction_t dir) -> return_t {
        return_t ret = errorcode_t::success;
        __try2 {
            if (nullptr == handshake) {
                ret = errorcode_t::invalid_parameter;
                __leave2;
            }

            {
                auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

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

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    // CRYPTO[CH], PADDING
    publisher.set_session(session)
        .set_payload_size(max_payload_size)
        .set_flags(quic_packet_flag_t::quic_pad_packet)  // add a padding frame and make a packet max_udp_payload_size
        .add(handshake)
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            _test_case.assert(true, __FUNCTION__, "[%zi] %s", packet.size(), message);
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
            _test_case.assert(true, __FUNCTION__, "[%zi] %s", packet.size(), message);
        });
}

void construct_quic_handshake_ee_cert_cv_fin(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    publisher.set_session(session).set_payload_size(max_payload_size).set_flags(quic_ack_packet | quic_pad_packet);

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
                    .set(quic_param_max_udp_payload_size, 1472)
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

    // CRYPTO[EE, CERT]
    // CRYPTO[CERT]
    // ...
    // CRYPTO[CERT, CV, FIN]
    publisher.publish(dir, [&](tls_session* session, binary_t& packet) -> void {
        bins.push_back(packet);
        _test_case.assert(true, __FUNCTION__, "[%zi] %s", packet.size(), message);
    });
}

void construct_quic_handshake_fin(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    // ACK, CRYPTO[FIN], PADDING
    publisher.set_session(session)
        .set_payload_size(max_payload_size)
        .set_flags(quic_ack_packet | quic_pad_packet)
        .add(new tls_handshake_finished(session))
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            _test_case.assert(true, __FUNCTION__, "[%zi] %s", packet.size(), message);
        });
}

void construct_quic_ack(tls_session* session, tls_direction_t dir, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    // ACK, PADDING
    publisher.set_session(session)
        .set_payload_size(max_payload_size)
        .set_flags(quic_ack_packet | quic_pad_packet)
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            _test_case.assert(true, __FUNCTION__, "[%zi] %s", packet.size(), message);
        });
}

return_t send_packet(tls_session* session, tls_direction_t dir, const std::list<binary_t>& bins, const char* message) {
    return_t ret = errorcode_t::success;
    for (auto item : bins) {
        quic_packets packets;
        ret = packets.read(session, dir, item);
        // TODO
        // goal condition (item.size() <= max_udp_payload_size)
        _test_case.assert(true, __FUNCTION__, "[%zi] %s", item.size(), message);
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
    // - certificate fragmentation
    // - case payload.size < 16

    _test_case.begin("construct");

    __try2 {
        return_t ret = errorcode_t::success;

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

        // initial
        {
            // C->S PKN#10
            construct_quic_initial_client_hello(&session_client, from_client, bins, "{C...} initial [CRYPTO(CH), PADDING]");
            ret = send_packet(&session_server, from_client, bins, "{C->S} initial [CRYPTO(CH), PADDING]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // S->C PKN#10 (ACK 10)
            construct_quic_initial_server_hello(&session_server, from_server, bins, "{S...} initial [ACK, CRYPTO(SH), PADDING]");
            ret = send_packet(&session_client, from_server, bins, "{S->C} initial [ACK, CRYPTO(SH), PADDING]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // C->S PKN#11 (ACK 10)
            construct_quic_ack(&session_client, from_client, bins, "{C...} initial [ACK]");
            ret = send_packet(&session_server, from_client, bins, "{C->S} initial [ACK]");
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        // handshake
        {
            // S->C PKN#20
            construct_quic_handshake_ee_cert_cv_fin(&session_server, from_server, bins, "{S...} handshake [CRYPTO(EE, CERT, CV, FIN)]");
            ret = send_packet(&session_client, from_server, bins, "{S->C} handshake [CRYPTO(EE, CERT, CV, FIN)]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // C->S PKN#20 (ACK 20)
            construct_quic_handshake_fin(&session_client, from_client, bins, "{C...} handshake ACK, [CRYPTO(FIN)]");
            ret = send_packet(&session_server, from_client, bins, "{C->S} handshake ACK, [CRYPTO(FIN)]");
            if (errorcode_t::success != ret) {
                __leave2;
            }
            // S->C PKN#21 (ACK 20)
            construct_quic_ack(&session_server, from_server, bins, "{S...} handshake [ACK]");
            ret = send_packet(&session_client, from_server, bins, "{S->C} handshake [ACK]");
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }
    }
    __finally2 {}
}
