/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

// - TODO
//   - [ ] fragmentation

void construct_quic_initial_client_hello(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto initial = packet_builder.set(quic_packet_type_initial).set_session(session).build();
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
        auto crypto = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(initial).build();

        tls_handshake* handshake = nullptr;
        tls_composer::construct_client_hello(&handshake, session, lambda, tls_13, tls_13);

        *crypto << handshake;
        *initial << crypto;
    }
    {
        // quic_param_max_udp_payload_size
        auto padding = (quic_frame_padding*)frame_builder.set(quic_frame_type_padding).set(initial).build();
        padding->pad(1182);  // TODO
        *initial << padding;
    }

    initial->write(from_client, bin);
    initial->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_initial_server_hello(tls_session* client_session, tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto initial = packet_builder.set(quic_packet_type_initial).set_session(session).build();
    quic_frame_builder frame_builder;

    {
        auto ack = frame_builder.set(quic_frame_type_ack).set(initial).build();
        // read PKNs from session
        *initial << ack;
    }
    {
        auto crypto = (quic_frame_crypto*)frame_builder.set(quic_frame_type_crypto).set(initial).build();

        tls_handshake* handshake = nullptr;
        tls_composer::construct_server_hello(&handshake, session, nullptr, tls_13, tls_13);

        *crypto << handshake;
        *initial << crypto;
    }
    {
        auto padding = frame_builder.set(quic_frame_type_padding).set(initial).build();
        *initial << padding;
    }

    initial->write(from_server, bin);
    initial->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_initial_ack(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    quic_packet_builder packet_builder;
    auto initial = packet_builder.set(quic_packet_type_initial).set_session(session).build();
    quic_frame_builder frame_builder;

    {
        auto ack = frame_builder.set(quic_frame_type_ack).set(initial).build();
        // read PKNs from session
        *initial << ack;
    }

    initial->write(from_server, bin);
    initial->release();

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_handshake(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
    bin.clear();

    // auto handshake = new tls_handshake_certificate(session);

    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void send_packet(tls_session* session, tls_direction_t dir, const binary_t& bin, const char* message) {
    quic_packets packets;
    packets.read(session, dir, bin);
    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void test_construct_quic() {
    _test_case.begin("construct (sketch version)");

    binary_t bin;
    tls_session session_client(session_type_quic);
    tls_session session_server(session_type_quic);

    // C->S
    construct_quic_initial_client_hello(&session_client, from_client, bin, "{C...} initial [CRYPTO(CH), PADDING]");
    send_packet(&session_server, from_client, bin, "{C->S} initial [CRYPTO(CH), PADDING]");
    // S->C
    construct_quic_initial_server_hello(&session_client, &session_server, from_server, bin, "{S...} initial [ACK, CRYPTO(SH), PADDING]");
    send_packet(&session_client, from_server, bin, "{S->C} initial [ACK, CRYPTO(SH), PADDING]");
    //
    construct_quic_initial_ack(&session_client, from_client, bin, "{C...} initial [ACK, PADDING]");
    send_packet(&session_server, from_client, bin, "{S->C} initial [ACK, PADDING]");
    // S->C
    construct_quic_handshake(&session_server, from_server, bin, "{S...} handshake [CRYPTO(EE, CERT, CV, FIN)], short [STREAM(HTTP3 SETTINGS)]");
    send_packet(&session_client, from_server, bin, "{S->C} handshake [CRYPTO(EE, CERT, CV, FIN)], short [STREAM(HTTP3 SETTINGS)]");
}
