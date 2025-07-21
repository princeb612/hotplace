/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

// http3.pcapng
// - sketch
//   - #1~#14
// - [ ] prep
//   - [ ] quic_packet_publisher (generate fragmented CRYPTO) cf. dtls_record_publisher
//   - [ ] PKNs informations in tls_session
//   - [ ] padding (randomize and align the packet size)
//   - [ ] ...

void construct_quic_initial_client_hello(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
#if 0
    bin.clear();

    quic_packet_builder packet_builder;
    auto initial = packet_builder.set(quic_packet_type_initial).set_session(session).build();
    quic_frame_builder frame_builder;

    {
        auto crypto = frame_builder.set(quic_frame_type_crypto).set(initial).build();

        auto handshake = new tls_handshake_client_hello(session);
        // do something
        // handshake->add_ciphersuites(...);
        // handshake->get_extensions(new tls_extension_xxx(handshake));
        //                               tls_extension_quic_transport_parameters
        //                               tls_extension_sni
        //                               tls_extension_ec_point_formats
        //                               tls_extension_supported_groups
        //                               tls_extension_alpn
        //                               tls_extension_unknown(tls_ext_encrypt_then_mac, handshake);
        //                               tls_extension_unknown(tls_ext_extended_master_secret, handshake);
        //                               tls_extension_signature_algorithms
        //                               tls_extension_client_supported_versions
        //                               tls_extension_psk_key_exchange_modes
        //                               tls_extension_client_key_share

        *crypto << handshake;
        *initial << crypto;
    }
    {
        auto padding = frame_builder.set(quic_frame_type_padding).set(initial).build();
        // bin -> crypto || padding
        // range.minimum < bin (randomized size) < range.maximum
        // true == (0 = (bin.size() % 0x10))
        padding->guide(range_padded, 0x10);
        *initial << padding;
    }

    initial->write(from_client, bin);
    initial->release();
#endif
    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_initial_server_hello(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
#if 0
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
        auto crypto = frame_builder.set(quic_frame_type_crypto).set(initial).build();

        auto handshake = new tls_handshake_server_hello(session);

        // handshake->set_ciphersuite("TLS_AES_256_GCM_SHA384");
        // handshake->get_extensions(new new tls_extension_server_key_share(handshake));
        // handshake->get_extensions(new new tls_extension_server_supported_versions(handshake));

        *crypto << handshake;
        *initial << crypto;
    }
    {
        auto padding = frame_builder.set(quic_frame_type_padding).set(initial).build();
        // bin -> crypto || padding
        // range.minimum < bin (randomized size) < range.maximum
        // true == (0 = (bin.size() % 0x10))
        padding->guide(range_padded, 0x10);
        *initial << padding;
    }

    initial->write(from_server, bin);
    initial->release();
#endif
}

void construct_ack(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
#if 0
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
        auto padding = frame_builder.set(quic_frame_type_padding).set(initial).build();
        // bin -> crypto || padding
        // range.minimum < bin (randomized size) < range.maximum
        // true == (0 = (bin.size() % 0x10))
        padding->guide(range_padded, 0x10);
        *initial << padding;
    }

    initial->write(from_server, bin);
    initial->release();
#endif
    _test_case.assert(true, __FUNCTION__, "%s", message);
}

void construct_quic_handshake(tls_session* session, tls_direction_t dir, binary_t& bin, const char* message) {
#if 0
    bin.clear();

    //
#endif
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
    construct_quic_initial_server_hello(&session_server, from_server, bin, "{S...} initial [ACK, CRYPTO(SH), PADDING]");
    send_packet(&session_client, from_server, bin, "{S->C} initial [ACK, CRYPTO(SH), PADDING]");
    //
    construct_ack(&session_client, from_client, bin, "{C...} initial [ACK, PADDING]");
    send_packet(&session_server, from_client, bin, "{S->C} initial [ACK, PADDING]");
    // S->C
    construct_quic_handshake(&session_server, from_server, bin, "{S...} handshake [CRYPTO(EE, CERT, CV, FIN)], short [STREAM(HTTP3 SETTINGS)]");
    send_packet(&session_client, from_server, bin, "{S->C} handshake [CRYPTO(EE, CERT, CV, FIN)], short [STREAM(HTTP3 SETTINGS)]");
}
