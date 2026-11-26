/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_composer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_builder.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_composer::tls_composer(tls_session* session) : _session(session), _minspec(tls1_2), _maxspec(tls1_3) {
    auto session_type = session->get_type();
    switch (session_type) {
        case session_type_t::dtls: {
            auto& publisher = session->get_dtls_record_publisher();
            publisher.set_fragment_size(1024);
            publisher.set_segment_size(1024);
            publisher.set_flags(dtls_record_publisher_multi_handshakes);
        } break;
        case session_type_t::quic:
        case session_type_t::quic2: {
            _minspec = tls1_3;
        } break;
        default:
            break;
    }
}

tls_composer::~tls_composer() {}

return_t tls_composer::handshake(tls_direction_t dir, unsigned wto, std::function<void(tls_session*, binary_t&)> func) {
    if (nullptr == func) {
        return errorcode_t::invalid_parameter;
    }
    auto session = get_session();
    auto session_type = session->get_type();
    if ((session_type_t::tls == session_type || session_type_t::dtls == session_type) && (from_client == dir || from_server == dir)) {
        return handshake(dir, wto, std::function<return_t(tls_session*, binary_t&)>([func](tls_session* session, binary_t& bin) -> return_t {
                             func(session, bin);
                             return errorcode_t::success;
                         }));
    }
    if ((session_type_t::quic == session_type || session_type_t::quic2 == session_type) && (from_client == dir)) {
        return do_quic_client_handshake(wto, func);
    }
    return errorcode_t::not_supported;
}

return_t tls_composer::handshake(tls_direction_t dir, unsigned wto, std::function<return_t(tls_session*, binary_t&)> func) {
    if (nullptr == func) {
        return errorcode_t::invalid_parameter;
    }
    auto session = get_session();
    auto session_type = session->get_type();
    if (session_type_t::tls != session_type && session_type_t::dtls != session_type) {
        return errorcode_t::not_supported;
    }
    if (from_client == dir) {
        return do_tls_client_handshake(wto, func);
    }
    if (from_server == dir) {
        return do_tls_server_handshake(wto, func);
    }
    return errorcode_t::not_supported;
}

return_t tls_composer::session_status_changed(uint32 session_status, tls_direction_t dir, uint32 wto, std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
#if defined DEBUG
        if (istraceable(trace_category_t::trace_category_net)) {
            trace_debug_event(trace_category_t::trace_category_net, trace_event_t::trace_event_tls_handshake, [&](basic_stream& dbs) -> void {
                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                dbs.println("hook %s (%s)", tlsadvisor->nameof_session_status(session_status).c_str(), tlsadvisor->nameof_direction(dir).c_str());
            });
        }
#endif
        if (from_client == dir) {
            ret = errorcode_t::not_supported;
        } else if (from_server == dir) {
            auto session = get_session();
            auto& protection = session->get_tls_protection();
            auto session_type = session->get_type();

            // TLS 1.3
            //   C client_hello
            //   S server_hello, certificate, certificate_verify, change_cipher_spec, finished
            //   C change_cipher_spec, finished
            // TLS 1.2 full handshake
            //   C client_hello
            //   S server_hello, certificate, server_key_exchange, server_hello_done
            //   C client_key_exchange, change_cipher_spec, finished
            //   S change_cipher_spec, finished
            // TLS 1.2 abbreviated ticket handshake
            //   C client_hello
            //   S server_hello, [new_session_ticket], change_cipher_spec, finished
            //   C change_cipher_spec, finished
            switch (session_type) {
                case session_type_t::tls:
                case session_type_t::dtls: {
                    switch (session_status) {
                        case session_status_client_hello: {
                            ret = do_tls_server_handshake_phase1(func);
                        } break;
                        case session_status_client_finished: {
                            // Full TLS 1.2 handshakes send Server Finished after
                            // Client Finished. Abbreviated handshakes already sent
                            // Server Finished in phase 1.
                            if (protection.is_kindof_tls1_2() && (0 == session->get_keyvalue().get(session_tls1_2_ticket_resumed))) {
                                ret = do_tls_server_handshake_phase2(func);
                            }
                        } break;
                    }
                } break;
                case session_type_t::quic:
                case session_type_t::quic2: {
                    switch (session_status) {
                        case session_status_client_hello: {
                            return_t callback_ret = errorcode_t::success;
                            return_t compose_ret = do_quic_server_handshake([&](tls_session* current, binary_t& packet) -> void {
                                if (errorcode_t::success == callback_ret) {
                                    callback_ret = func(current, packet);
                                }
                            });
                            ret = (errorcode_t::success == compose_ret) ? callback_ret : compose_ret;
                        } break;
                    }
                } break;
            }
        }
    }
    __finally2 {}
    return ret;
}

tls_session* tls_composer::get_session() { return _session; }

void tls_composer::set_minver(tls_version_t version) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto hint = tlsadvisor->hintof_tls_version(version);
    if (hint) {
        _minspec = hint->spec;
    }
}

void tls_composer::set_maxver(tls_version_t version) {
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    auto hint = tlsadvisor->hintof_tls_version(version);
    if (hint) {
        _maxspec = hint->spec;
    }
}

uint16 tls_composer::get_minver() const { return _minspec; }

uint16 tls_composer::get_maxver() const { return _maxspec; }

}  // namespace net
}  // namespace hotplace
