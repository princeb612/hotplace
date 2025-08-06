/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void construct_quic_initial_client_hello(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto packet = packet_builder.set(quic_packet_type_initial).set_session(session).set(dir).construct().build();
    quic_frame_builder frame_builder;

    auto lambda = [](tls_handshake* handshake, tls_direction_t dir) -> return_t {
        return_t ret = errorcode_t::success;
        {
            auto quic_params = new tls_extension_quic_transport_parameters(handshake);
            (*quic_params)
                .set(quic_param_disable_active_migration, binary_t())
                .set(quic_param_initial_source_connection_id, binary_t())
                .set(quic_param_max_idle_timeout, 120000)
                .set(quic_param_max_udp_payload_size, 1200)
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
        return ret;
    };

    {
        auto crypto = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(packet).build();

        tls_handshake* handshake = nullptr;
        tls_composer::construct_client_hello(&handshake, session, lambda, tls_13, tls_13);

        *crypto << handshake;
        *packet << crypto;
    }
    {
        // quic_param_max_udp_payload_size
        auto padding = (quic_frame_padding*)frame_builder.set(quic_frame_type_padding).set(packet).build();
        padding->pad(1182);  // TODO
        *packet << padding;
    }

    packet->write(dir, bin);

    packet->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_initial_server_hello(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto packet = packet_builder.set(quic_packet_type_initial).set_session(session).set(dir).construct().build();
    quic_frame_builder frame_builder;

    {
        auto ack = (quic_frame_ack*)frame_builder.set(quic_frame_type_ack).set(packet).build();
        ack->set_protection_level(protection_initial);
        *packet << ack;
    }
    {
        auto crypto = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(packet).build();

        tls_handshake* handshake = nullptr;
        tls_composer::construct_server_hello(&handshake, session, nullptr, tls_13, tls_13);

        *crypto << handshake;
        *packet << crypto;
    }
    {
        auto padding = (quic_frame_padding*)frame_builder.set(quic_frame_type_padding).set(packet).build();
        padding->pad(1182);  // TODO
        *packet << padding;
    }

    packet->write(dir, bin);

    packet->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_initial_ack(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto packet = packet_builder.set(quic_packet_type_initial).set_session(session).set(dir).construct().build();
    quic_frame_builder frame_builder;

    {
        auto ack = (quic_frame_ack*)frame_builder.set(quic_frame_type_ack).set(packet).build();
        ack->set_protection_level(protection_initial);
        *packet << ack;
    }
    {
        auto padding = (quic_frame_padding*)frame_builder.set(quic_frame_type_padding).set(packet).build();
        padding->pad(1182);  // TODO
        *packet << padding;
    }

    packet->write(dir, bin);

    packet->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_handshake_ee_cert(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto packet = packet_builder.set(quic_packet_type_handshake).set_session(session).set(dir).construct().build();
    quic_frame_builder frame_builder;

    {
        auto crypto = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(packet).build();

        // EE
        {
            auto handshake = new tls_handshake_encrypted_extensions(session);
            {
                auto sni = new tls_extension_sni(handshake);
                auto& hostname = sni->get_hostname();
                hostname = "";
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

            *crypto << handshake;
        }
        // CERT
        *crypto << new tls_handshake_certificate(session);

        *packet << crypto;
    }

    packet->write(dir, bin);

    packet->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_handshake_cv_fin(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto packet = packet_builder.set(quic_packet_type_handshake).set_session(session).set(dir).construct().build();
    quic_frame_builder frame_builder;

    {
        auto crypto = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(packet).build();
        // CV
        *crypto << new tls_handshake_certificate_verify(session);
        // FIN
        *crypto << new tls_handshake_finished(session);

        *packet << crypto;
    }

    packet->write(dir, bin);

    packet->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_handshake_ack(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto packet = packet_builder.set(quic_packet_type_handshake).set_session(session).set(dir).construct().build();
    quic_frame_builder frame_builder;

    {
        auto ack = (quic_frame_ack*)frame_builder.set(quic_frame_type_ack).set(packet).build();
        ack->set_protection_level(protection_handshake);
        *packet << ack;
    }
    {
        auto padding = (quic_frame_padding*)frame_builder.set(quic_frame_type_padding).set(packet).build();
        padding->pad(1182);  // TODO
        *packet << padding;
    }

    packet->write(dir, bin);

    packet->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

return_t send_packet(tls_session* session, tls_direction_t dir, const binary_t& bin, const char* message) {
    return_t ret = errorcode_t::success;
    quic_packets packets;
    ret = packets.read(session, dir, bin);
    _test_case.assert(true, __FUNCTION__, "%s", message);
    return ret;
}

void test_construct_quic() {
    // understanding ...

    // PKN
    //      initial handshake application
    // curl 0...I   I+1...H   H+1...
    // test 0...I   0...H     0...A

    // TODO
    // - certificate fragmentation
    // - case payload.size < 16

    _test_case.begin("construct");

    __try2 {
        return_t ret = errorcode_t::success;

        load_certificate("rsa.crt", "rsa.key", nullptr);
        load_certificate("ecdsa.crt", "ecdsa.key", nullptr);

        binary_t bin;
        tls_session session_client(session_type_quic);
        tls_session session_server(session_type_quic);

        auto lambda = [](tls_session* session, tls_direction_t dir, protection_level_t level, uint32 pkn_expect) -> void {
            uint32 pkn = session->get_recordno(dir, false, level);
            _test_case.assert(pkn_expect == pkn, __FUNCTION__, "PKN %i", pkn);
        };

        // initial
        {
            // C->S
            lambda(&session_client, from_client, protection_initial, 0);
            construct_quic_initial_client_hello(&session_client, from_client, bin, "{C...} initial [CRYPTO(CH), PADDING]");
            lambda(&session_server, from_client, protection_initial, 0);
            ret = send_packet(&session_server, from_client, bin, "{C->S} initial [CRYPTO(CH), PADDING]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // S->C
            lambda(&session_server, from_server, protection_initial, 0);
            construct_quic_initial_server_hello(&session_server, from_server, bin, "{S...} initial [ACK, CRYPTO(SH), PADDING]");
            lambda(&session_client, from_server, protection_initial, 0);
            ret = send_packet(&session_client, from_server, bin, "{S->C} initial [ACK, CRYPTO(SH), PADDING]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // C->S
            lambda(&session_client, from_client, protection_initial, 1);
            construct_quic_initial_ack(&session_client, from_client, bin, "{C...} initial [ACK, PADDING]");
            lambda(&session_server, from_client, protection_initial, 1);
            ret = send_packet(&session_server, from_client, bin, "{C->S} initial [ACK, PADDING]");
            if (errorcode_t::success != ret) {
                __leave2;
            }
        }

        // handshake
        {
            // S->C

            lambda(&session_server, from_server, protection_handshake, 0);
            construct_quic_handshake_ee_cert(&session_server, from_server, bin, "{S...} handshake [CRYPTO(EE, CERT)]");
            lambda(&session_client, from_server, protection_handshake, 0);
            ret = send_packet(&session_client, from_server, bin, "{S->C} handshake [CRYPTO(EE, CERT)]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            lambda(&session_server, from_server, protection_handshake, 1);
            construct_quic_handshake_cv_fin(&session_server, from_server, bin, "{S...} handshake [CRYPTO(CV, FIN)]");
            lambda(&session_client, from_server, protection_handshake, 1);
            ret = send_packet(&session_client, from_server, bin, "{S->C} handshake [CRYPTO(CV, FIN)]");
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // C->S
            lambda(&session_client, from_client, protection_handshake, 0);
            construct_quic_handshake_ack(&session_client, from_client, bin, "{C...} packet [ACK]");
            lambda(&session_server, from_client, protection_handshake, 0);
            send_packet(&session_server, from_client, bin, "{C->S} packet [ACK]");
        }
    }
    __finally2 {}
}
