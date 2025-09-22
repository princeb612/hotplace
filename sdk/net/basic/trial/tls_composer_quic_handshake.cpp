/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_settings.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_alpn.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_quic_transport_parameters.hpp>
#include <hotplace/sdk/net/tls/tls/extension/tls_extension_sni.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_composer::do_quic_client_handshake(unsigned wto, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto& publisher = session->get_quic_packet_publisher();
        auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);
        auto dir = from_client;
        uint32 session_status = 0;
        uint32 flags = quic_pad_packet;

        // C->S CRYPTO[CH], PADDING
        publisher.set_session(session)
            .set_flags(flags)
            .add(tls_hs_client_hello, dir,
                 [&](tls_handshake* handshake, tls_direction_t dir) -> return_t {
                     return_t ret = errorcode_t::success;
                     handshake->get_extensions()
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
            .publish(dir, [&](tls_session* session, binary_t& packet) -> void { func(session, packet); });

        // S->C SH, CERT, CV, FIN
        uint32 session_status_finished = 0;
        uint32 session_status_prerequisite =
            session_status_server_hello | session_status_server_cert | session_status_server_cert_verified | session_status_server_finished;
        session->wait_change_session_status(session_status_prerequisite, wto);
        session_status = session->get_session_status();

        if (0 == (session_status & session_status_prerequisite)) {
            ret = error_handshake;
            __leave2_trace(ret);
        }

        // C->S ACK, CRYPTO[FIN]
        publisher.set_session(session).set_flags(flags).add(tls_hs_finished, dir).publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            func(session, packet);
        });

        // wait FIN
        session_status_finished = session_status_client_finished;

        session->wait_change_session_status(session_status_finished, wto);
        session_status = session->get_session_status();

        if (0 == (session_status_finished & session_status)) {
            ret = errorcode_t::error_handshake;
            __leave2_trace(ret);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_quic_server_handshake(std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto& publisher = session->get_quic_packet_publisher();
        auto max_payload_size = session->get_quic_session().get_setting().get(quic_param_max_udp_payload_size);
        auto dir = from_server;
        uint32 flags = quic_ack_packet | quic_pad_packet;

        // S->C ACK, CRYPTO[SH], PADDING
        publisher.set_session(session).set_flags(flags).add(tls_hs_server_hello, dir).publish(dir, [&](tls_session* session, binary_t& packet) -> void {
            func(session, packet);
        });

        // S->C CERT, CV, FIN
        flags = quic_ack_packet;
        publisher.set_session(session)
            .set_flags(flags)
            .add(tls_hs_encrypted_extensions, dir,
                 [&](tls_handshake* handshake, tls_direction_t dir) -> return_t {
                     handshake->get_extensions()
                         .add(tls_ext_alpn, dir, handshake,
                              [](tls_extension* extension) -> return_t {
                                  binary_t protocols;
                                  binary_append(protocols, uint8(2));
                                  binary_append(protocols, "h3");
                                  (*(tls_extension_alpn*)extension).set_protocols(protocols);
                                  return success;
                              })
                         .add(tls_ext_quic_transport_parameters, dir, handshake,  //
                              [&](tls_extension* extension) -> return_t {
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
                                      .set(quic_param_max_udp_payload_size, max_payload_size)
                                      .set(quic_param_initial_max_streams_bidi, 100);
                                  return success;
                              });
                     return success;
                 })
            .add(tls_hs_certificate, dir)
            .add(tls_hs_certificate_verify, dir)
            .add(tls_hs_finished, dir)
            .publish(dir, [&](tls_session* session, binary_t& packet) -> void { func(session, packet); });
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
