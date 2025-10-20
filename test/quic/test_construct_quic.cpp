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

void enum_pkns(quic_packet_publisher& publisher) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    _logger->colorln("PKN published");
    publisher.for_each_pkn(
        [&](protection_space_t space, uint64 pkn) -> void { _logger->colorln("+ %s %I64i", tlsadvisor->protection_space_string(space).c_str(), pkn); });
}

void construct_quic_cli_initial(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);

    // CRYPTO[CH], PADDING
    publisher.set_session(session)
        .set_flags(flags)  // add a padding frame and make a packet max_udp_payload_size
        .add(tls_hs_client_hello, dir,
             [&](tls_handshake* handshake, tls_direction_t dir) -> return_t {
                 return_t ret = errorcode_t::success;
                 handshake->get_extensions()
                     .add(tls_ext_server_name, dir, handshake,
                          [&](tls_extension* extension) -> return_t {
                              auto sni = (tls_extension_sni*)extension;
                              sni->set_hostname("test.server.com");
                              return success;
                          })
                     .add(tls_ext_alpn, dir, handshake,
                          [&](tls_extension* extension) -> return_t {
                              auto alpn = (tls_extension_alpn*)extension;
                              binary_t protocols;
                              binary_append(protocols, uint8(2));
                              binary_append(protocols, "h3");
                              alpn->set_protocols(protocols);
                              return success;
                          })
                     .add(tls_ext_quic_transport_parameters, dir, handshake,  //
                          [&](tls_extension* extension) -> return_t {
                              auto quic_params = (tls_extension_quic_transport_parameters*)(extension);
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
                              return success;
                          });
                 return ret;
             })
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_svr_initial(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    // ACK, CRYPTO[SH], PADDING
    publisher.set_session(session)
        .set_flags(flags)
        .add(tls_hs_server_hello, dir)
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_svr_handshakes_settings(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    // handshake
    //   CRYPTO[EE, CERT]
    //   CRYPTO[CERT]
    //   ...
    //   CRYPTO[CERT, CV, FIN]
    // 1-RTT
    //   SETTINGS

    publisher.set_session(session)
        .set_flags(flags)
        .add(tls_hs_encrypted_extensions, dir,
             [](tls_handshake* handshake, tls_direction_t dir) -> return_t {
                 handshake->get_extensions()
                     .add(tls_ext_sni, dir, handshake,
                          [](tls_extension* extension) -> return_t {
                              (*(tls_extension_sni*)extension).set_hostname("localhost");
                              return success;
                          })
                     .add(tls_ext_alpn, dir, handshake,
                          [](tls_extension* extension) -> return_t {
                              binary_t protocols;
                              binary_append(protocols, uint8(2));
                              binary_append(protocols, "h3");
                              (*(tls_extension_alpn*)extension).set_protocols(protocols);
                              return success;
                          })
                     .add(tls_ext_quic_transport_parameters, dir, handshake,  //
                          [](tls_extension* extension) -> return_t {
                              (*(tls_extension_quic_transport_parameters*)extension)
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
                              return success;
                          });
                 return success;
             })
        .add(tls_hs_certificate, dir)
        .add(tls_hs_certificate_verify, dir)
        .add(tls_hs_finished, dir)
        .add_stream(quic_stream_server_uni, h3_control_stream, h3_frame_settings,
                    [&](http3_frame* frame) -> return_t {
                        return_t ret = errorcode_t::success;
                        http3_frame_settings* settings = (http3_frame_settings*)frame;
                        (*settings)
                            .set(h3_settings_qpack_max_table_capacity, 0x10000)
                            .set(h3_settings_max_field_section_size, 0x10000)
                            .set(h3_settings_qpack_blocked_streams, 100)
                            .set(h3_settings_enable_connect_protocol, 1)
                            .set(h3_settings_h3_datagram, 1);
                        return ret;
                    })
        .publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            bins.push_back(packet);
            auto tlsadvisor = tls_advisor::get_instance();
            auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
            _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
        });

    enum_pkns(publisher);
}

void construct_quic_cli_handshake(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    // ACK, CRYPTO[FIN]
    publisher.set_session(session)
        .set_flags(flags)
        .add(tls_hs_finished, dir)
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_cli_settings(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    publisher.set_session(session)
        .set_flags(flags)
        .add_stream(quic_stream_client_uni, h3_control_stream, h3_frame_settings,
                    [&](http3_frame* frame) -> return_t {
                        return_t ret = errorcode_t::success;
                        http3_frame_settings* settings = (http3_frame_settings*)frame;
                        (*settings)
                            .set(h3_settings_max_field_section_size, 4611686018427387903)
                            .set(h3_settings_qpack_max_table_capacity, 0)
                            .set(h3_settings_qpack_blocked_streams, 100);
                        return ret;
                    })
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });
}

void construct_quic_cli_decoder(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    // try to publish [decoder stream (03) || no data]
    publisher.set_session(session)
        .set_flags(flags)
        .add_stream(10, h3_qpack_decoder_stream)
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_cli_encoder(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    // try to publish [decoder stream (03) || encoder stream]
    publisher.set_session(session)
        .set_flags(flags)
        .add_stream(6, h3_qpack_encoder_stream,
                    [](qpack_stream& stream) -> return_t {
                        stream.set_encode_flags(qpack_indexing | qpack_huffman | qpack_intermediary)
                            .set_capacity(4096)
                            .encode_header(":authority", "localhost")
                            .encode_header("user-agent", "hotplace 1.58.864");
                        return success;
                    })
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });
}

void construct_http3_cli_get(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    publisher.set_session(session)
        .set_flags(flags)
        .add_stream(quic_stream_client_bidi, h3_control_stream, h3_frame_headers,
                    [&](http3_frame* frame) -> return_t {
                        return_t ret = errorcode_t::success;
                        http3_frame_headers* headers = (http3_frame_headers*)frame;
                        (*headers)
                            .add(":method", "GET")
                            .add(":scheme", "https")
                            .add(":authority", "localhost")
                            .add(":path", "/")
                            .add("user-agent", "hotplace 1.58.864")
                            .add("accept", "*/*");
                        return ret;
                    })
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_svr_nst(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;
    publisher.get_handshakes().get_container().set_flags(0);  // turn off distinct_type_in_container

    publisher.set_session(session)
        .set_flags(flags)
        .add(tls_hs_new_session_ticket, dir)
        .add(tls_hs_new_session_ticket, dir)
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_svr_done_nt_nci(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    publisher.set_session(session)
        .set_flags(flags)
        .add(quic_frame_type_handshake_done)
        .add(quic_frame_type_new_token)
        .add(quic_frame_type_new_connection_id)
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });
}

void construct_quic_svr_decoder(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    // try to publish [decoder stream (03) || no data]
    publisher.set_session(session)
        .set_flags(flags)
        .add_stream(7, h3_qpack_decoder_stream,
                    [](qpack_stream& stream) -> return_t {
                        stream.ack(0);  // STREAM(0) HEADERS GET /
                        return success;
                    })
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_http3_svr_ok(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    publisher.set_session(session)
        .set_flags(flags)
        .add_stream(11, h3_qpack_encoder_stream,
                    [](qpack_stream& stream) -> return_t {
                        stream.increment(0);
                        return success;
                    })
        .add_stream(quic_stream_client_bidi, h3_control_stream, h3_frame_headers,
                    [&](http3_frame* frame) -> return_t {
                        return_t ret = errorcode_t::success;
                        http3_frame_headers* headers = (http3_frame_headers*)frame;
                        (*headers).add(":status", "200").add("content-type", "text/html; charset=ISO-8859-1");
                        return ret;
                    })
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_http3_svr_resp(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    publisher.set_session(session)
        .set_flags(flags)
        .add_stream(
            quic_stream_client_bidi, h3_control_stream, h3_frame_data,
            [&](http3_frame* frame) -> return_t {
                return_t ret = errorcode_t::success;
                http3_frame_data* headers = (http3_frame_data*)frame;
                headers->set_contents(R"(<!DOCTYPE html><html><head><title>test</title><meta charset="UTF-8"></head><body><p>Hello world</p></body></html>)");
                return ret;
            })
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_connection_close(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    publisher.set_session(session)
        .set_flags(flags)
        .add(quic_frame_type_connection_close)
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

void construct_quic_ack(tls_session* session, tls_direction_t dir, uint32 flags, std::list<binary_t>& bins, const char* message) {
    bins.clear();

    quic_packet_publisher publisher;

    // ACK
    publisher.set_session(session)
        .set_flags(quic_ack_packet | flags)
        .publish(dir,  //
                 [&](tls_session* session, binary_t& packet) -> void {
                     bins.push_back(packet);
                     auto tlsadvisor = tls_advisor::get_instance();
                     auto test = (quic_pad_packet & flags) ? (max_udp_payload_size == packet.size()) : true;
                     _test_case.assert(test, __FUNCTION__, "[%zi] {%s} %s", packet.size(), tlsadvisor->nameof_direction(dir, 0).c_str(), message);
                 });

    enum_pkns(publisher);
}

return_t send_packet(tls_session* session, tls_direction_t dir, const std::list<binary_t>& bins, const char* message) {
    return_t ret = errorcode_t::success;
    for (auto item : bins) {
        quic_packets packets;
        ret = packets.read(session, dir, item);
        auto tlsadvisor = tls_advisor::get_instance();
        _test_case.test(ret, __FUNCTION__, "[%zi] {%s} %s", item.size(), tlsadvisor->nameof_direction(dir, 1).c_str(), message);
        if (errorcode_t::success != ret) {
            break;
        }
    }
    return ret;
}

void test_construct_quic() {
    // understanding ...

    // PKN
    //      initial handshake application
    // curl 0...I   I+1...H   H+1...
    // test 10...I  20...H    30...A

    _test_case.begin("construct");

    __try2 {
        return_t ret = errorcode_t::success;

        auto tlsadvisor = tls_advisor::get_instance();
        tlsadvisor->enable_alpn("h3");

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

        auto lambda_check_pkn = [](tls_session* session, tls_direction_t dir, protection_space_t space, uint32 pkn_expect) -> void {
            uint32 pkn = session->get_recordno(dir, false, space);
            _test_case.assert(pkn_expect == pkn, __FUNCTION__, "PKN %i", pkn);
        };
        auto lambda_test_ready_to_ack = [](tls_session* session, protection_space_t space, uint32 largest, uint32 range) -> void {
            auto tlsadvisor = tls_advisor::get_instance();
            auto& pkns = session->get_quic_session().get_pkns(space);
            ack_t ack;
            ack << pkns;
            ack_t expect(largest, range);
            _test_case.assert(ack == expect, __FUNCTION__, "confirm ack %s %i..%i", tlsadvisor->protection_space_string(space).c_str(), largest,
                              largest - range);
        };

        // initial (PADDING)
        {
            // cf. http3.pcapng #1
            // #Frame C->S
            //   PKN 10 initial [CRYPTO(CH), PADDING]
            size_t range_ch = 0;
            {
                const char* text = "initial [CRYPTO(CH), PADDING]";
                lambda_check_pkn(&session_client, from_client, protection_initial, 10);
                construct_quic_cli_initial(&session_client, from_client, quic_pad_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                range_ch = bins.size() ? (bins.size() - 1) : 0;  // consider fragmentation
                lambda_test_ready_to_ack(&session_server, protection_initial, 10 + range_ch, range_ch);
            }

            // cf. http3.pcapng #3
            // #Frame S->C
            //   PKN 10 initial [ACK (10), CRYOTO(SH), PADDING]
            {
                const char* text = "initial [ACK, CRYPTO(SH), PADDING]";
                lambda_check_pkn(&session_server, from_server, protection_initial, 10);
                construct_quic_svr_initial(&session_server, from_server, quic_ack_packet | quic_pad_packet, bins, text);
                send_packet(&session_client, from_server, bins, text);
                auto range_sh = bins.size() ? (bins.size() - 1) : 0;
                lambda_test_ready_to_ack(&session_client, protection_initial, 10 + range_sh, range_sh);
            }

            // cf. http3.pcapng #4
            // #Frame C->S
            //   PKN 11 initial [ACK (10), PADDING]
            {
                const char* text = "initial [ACK, PADDING]";
                lambda_check_pkn(&session_client, from_client, protection_initial, 10 + range_ch + 1);
                construct_quic_ack(&session_client, from_client, quic_pad_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
            }
        }

        // handshake, 1-RTT (upto max_udp_payload_size)
        {
            // cf. http3.pcapng #8,9,12,13,14
            // #Frame S->C
            //   PKN 20 handshake [ACK(10), CRYPTO(EE, CERT, CV fragmented)]
            // #Frame S->C
            //   PKN 21 handshake [CRYPTO(CV fragmented, FIN)]
            //   PKN 30 1-RTT [STREAM(HTTP/3 SETTINGS)]
            {
                const char* text = "handshake [CRYPTO(EE, CERT, CV, FIN)], 1-RTT [STREAM(HTTP/3 SETTINGS)]";
                lambda_check_pkn(&session_server, from_server, protection_handshake, 20);
                lambda_check_pkn(&session_server, from_server, protection_application, 30);
                construct_quic_svr_handshakes_settings(&session_server, from_server, quic_ack_packet, bins, text);
                _test_case.assert(2 == bins.size(), __FUNCTION__, "segmentation");
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_handshake, 21, 1);    // CRYPTO(EE, CERT, CV, FIN)
                lambda_test_ready_to_ack(&session_client, protection_application, 30, 0);  // SETTINGS
            }

            // EE
            {
                auto lambda_alpn = [&](tls_session* session, const char* text) -> void {
                    auto& alpn = session->get_tls_protection().get_secrets().get(tls_context_alpn);
                    auto test = alpn.empty() ? false : (0 == memcmp(&alpn[0], "\x2h3", 3));
                    _test_case.assert(test, __FUNCTION__, text);
                };
                lambda_alpn(&session_client, "ALPN of session client");
                lambda_alpn(&session_server, "ALPN of session server");
            }

            // cf. http3.pcapng #17
            // #Frame C->S
            //   PKN 20 handshake [ACK (21..20), CRYPTO(FIN)]
            //   PKN 30 1-RTT [ACK (30)]
            {
                lambda_check_pkn(&session_client, from_client, protection_handshake, 20);
                lambda_check_pkn(&session_client, from_client, protection_application, 30);

                const char* text = "handshake [ACK, CRYPTO(FIN)], 1-RTT [ACK]";
                construct_quic_cli_handshake(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_handshake, 20, 0);
                lambda_test_ready_to_ack(&session_server, protection_application, 30, 0);
            }

            // #Frame S->C
            //   PKN 22 [ACK (20)]
            {
                const char* text = "handshake [ACK]";
                lambda_check_pkn(&session_server, from_server, protection_handshake, 22);
                construct_quic_ack(&session_server, from_server, 0, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_handshake, 20, 0);
                lambda_test_ready_to_ack(&session_server, protection_application, 30, 0);
            }
        }

        // 1-RTT
        {
            // cf. http3.pcapng #20
            // #Frame C->S
            //   PKN 31 [ACK (31, 30), STREAM(HTTP/3 SETTINGS)]
            {
                const char* text = "1-RTT [ACK, STREAM(HTTP/3 SETTINGS)]";
                construct_quic_cli_settings(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_application, 31, 1);
            }

            // #Frame S->C
            //   PKN 32 [ACK (31..30)]
            {
                const char* text = "1-RTT [ACK]";
                construct_quic_ack(&session_server, from_server, 0, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 32, 2);
            }

            // cf. http3.pcapng #21
            // #Frame C->S
            //  PKN 32 [STREAM(QPACK_DECODER_STREAM)]
            //    stream id 10
            //    client_initiated_uni
            //    qpack decoder stream
            {
                const char* text = "1-RTT [STREAM(QPACK_DECODER_STREAM)]";
                construct_quic_cli_decoder(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_application, 32, 2);
            }

            // cf. http3.pcapng #22,23
            // #Frame C->S
            //   PKN 33 [STREAM(QPACK_ENCODER_STREAM)]
            //     stream id 6
            //     client_initiated_uni
            //     qpack encoder stream
            {
                const char* text = "1-RTT [STREAM(QPACK_ENCODER_STREAM)]";
                construct_quic_cli_encoder(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_application, 33, 3);
            }

            // #Frame S->C
            //   PKN 33 [ACK(33..30)]
            {
                const char* text = "1-RTT [ACK]";
                construct_quic_ack(&session_server, from_server, 0, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 33, 3);
            }

            // cf. http3.pcapng #24
            // #Frame C->S
            //   PKN 34 [ACK(33..30),STREAM(HTTP/3 HEADERS]
            // GET /
            {
                const char* text = "1-RTT [ACK, STREAM(HTTP/3 HEADERS)]";
                construct_http3_cli_get(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_application, 34, 4);
            }

            // #Frame S->C
            //   PKN 34 [ACK(34..30)]
            {
                const char* text = "1-RTT [ACK]";
                construct_quic_ack(&session_server, from_server, quic_ack_packet, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 34, 4);
            }

            // cf. http3.pcapng #28
            // #Frame S->C
            //   PKN 35 [ACK(34..30), CRYPTO(NST, NST)]
            {
                // 2 NST handshakes in 1 CRYPTO FRAME
                const char* text = "1-RTT [CRYPTO(NST, NST)]";
                construct_quic_svr_nst(&session_server, from_server, quic_ack_packet, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 35, 5);
            }

            // cf. http3.pcapng #29
            // #Frame S->C
            //   PKN 36 [DONE, NT, NCI]
            {
                const char* text = "1-RTT [CRYPTO(DONE, NT, NCI)]";
                construct_quic_svr_done_nt_nci(&session_server, from_server, quic_ack_packet, bins, text);
                // DONE || NT || NCI || 0x80(?) -> bad data
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 36, 6);
            }

            // #Frame C->S
            //   PKN 35
            {
                const char* text = "1-RTT [ACK]";
                construct_quic_ack(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_application, 35, 5);
            }

            // #Frame S->C
            //   PKN 37 [ACK]
            {
                const char* text = "1-RTT [ACK]";
                construct_quic_ack(&session_server, from_server, quic_ack_packet, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 37, 7);
            }

            // cf. http3.pcapng #34,36
            // #Frame S->C
            //   PKN 38 [STREAM(QPACK_DECODER_STREAM)]
            {
                const char* text = "1-RTT [STREAM(QPACK_DECODER_STREAM)]";
                construct_quic_svr_decoder(&session_server, from_server, quic_ack_packet, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 38, 8);
            }

            // #Frame C->S
            //   PKN 36
            {
                const char* text = "1-RTT [ACK]";
                construct_quic_ack(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_application, 36, 6);
            }

            // cf. http3.pcapng #38
            // #Frame S->C
            //   PKN 39
            {
                const char* text = "1-RTT [STREAM(QPACK_DECODER_STREAM), STREAM(HTTP/3 HEADERS)]";
                construct_http3_svr_ok(&session_server, from_server, quic_ack_packet, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 39, 9);
            }

            // cf. http3.pcapng #39~45
            {
                const char* text = "1-RTT [STREAM(HTTP/3 DATA)]";
                construct_http3_svr_resp(&session_server, from_server, quic_ack_packet, bins, text);
                send_packet(&session_client, from_server, bins, text);
                lambda_test_ready_to_ack(&session_client, protection_application, 40, 10);
            }

            // cf. http3.pcapng #67
            {
                const char* text = "1-RTT [CC]";
                construct_quic_connection_close(&session_client, from_client, quic_ack_packet, bins, text);
                send_packet(&session_server, from_client, bins, text);
                lambda_test_ready_to_ack(&session_server, protection_application, 37, 7);
            }
        }
    }
    __finally2 {}
}
