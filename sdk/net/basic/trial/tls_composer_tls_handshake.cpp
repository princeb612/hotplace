/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   tls_composer_tls_handshake.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_hello_verify_request.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_composer::do_tls_client_handshake(unsigned wto, std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto session_type = session->get_type();
        auto dir = from_client;
        uint32 session_status = 0;
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        const uint32 initial_status = session->get_session_status();
        const tls_flow_t initial_flow = protection.get_flow();
        const bool tls12_renegotiation =
            (session_type_t::tls == session_type) && protection.is_kindof_tls1_2() &&
            ((tls_flow_t::renegotiation == initial_flow) || ((tls_flow_t::one_rtt == initial_flow) && (completed_status == (initial_status & completed_status))));

        uint8 retry = 3;
        do {
            // The completed-handshake bits describe the connection before
            // renegotiation. Clear them before sending ClientHello so the
            // wait below cannot mistake the old state for a peer refusal.
            // A received no_renegotiation alert restores these bits and wakes
            // the waiter; a successful renegotiation instead sets server_hello.
            if (tls12_renegotiation) {
                session->clear_session_status(completed_status);
            }

            // C->S CH
            ret = do_tls_client_hello(func);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // if DTLS(HVR), then CH(cookie)
            if (session_type_t::dtls == session_type) {
                // S->C HVR
                ret = session->wait_change_session_status(session_status_hello_verify_request, wto);
                session_status = session->get_session_status();

                if (0 == (session_status & session_status_hello_verify_request)) {
                    if (errorcode_t::success == ret) {
                        ret = errorcode_t::handshake_failure;
                    }
                    __leave2_trace(ret);
                }
                ret = errorcode_t::success;

                // C->S CH(cookie that server sent)
                ret = do_tls_client_hello(func);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            }

            // S->C SH. During TLS 1.2 renegotiation, also wake when the peer
            // declines with no_renegotiation and the alert handler restores
            // the previously completed connection state.
            uint32 server_hello_wait_status = session_status_server_hello;
            if (tls12_renegotiation) {
                server_hello_wait_status |= completed_status;
            }
            ret = session->wait_change_session_status(server_hello_wait_status, wto, false);

            session_status = session->get_session_status();
            if (session_status & session_status_server_hello) {
                ret = errorcode_t::success;
                break;
            }
            if (tls12_renegotiation && (tls_flow_t::one_rtt == protection.get_flow()) && (completed_status == (session_status & completed_status))) {
                ret = errorcode_t::negotiation_failure;
                __leave2_trace(ret);
            }
        } while ((tls_flow_t::hello_retry_request == protection.get_flow()) && (--retry));

        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }
        auto flow = protection.get_flow();
        const bool accepted_tls12_renegotiation = tls12_renegotiation && (tls_flow_t::renegotiation == flow);
        if (tls_flow_t::one_rtt != flow && tls_flow_t::hello_retry_request != flow && (false == accepted_tls12_renegotiation)) {
            ret = errorcode_t::handshake_failure;
            __leave2_trace(ret);
        }

        tls_records records;
        tls_record_builder builder;
        uint32 session_status_finished = 0;

        if (protection.is_kindof_tls1_3()) {
            uint32 session_status_prerequisite =
                session_status_server_hello | session_status_server_cert | session_status_server_cert_verified | session_status_server_finished;
            ret = session->wait_change_session_status(session_status_prerequisite, wto);
            session_status = session->get_session_status();

            if (session_status_prerequisite != (session_status & session_status_prerequisite)) {
                if (errorcode_t::success == ret) {
                    ret = errorcode_t::handshake_failure;
                }
                __leave2_trace(ret);
            }
            ret = errorcode_t::success;

            builder.set(dir)
                .construct()
                .add(&records, tls_content_type_t::change_cipher_spec, session)
                .set_protected(true)
                .add(&records, tls_content_type_t::handshake, session,  //
                     [&](tls_record* record) -> return_t {
                         record->add(tls_handshake_type_t::finished, session);
                         return errorcode_t::success;
                     });

            session_status_finished = session_status_client_finished;
        } else if (protection.is_kindof_tls1_2()) {
            bool abbreviated = (0 != session->get_keyvalue().get(session_tls1_2_ticket_resumed));
            uint32 session_status_prerequisite = session_status_server_hello;
            if (abbreviated) {
                // The server sends Finished first in the RFC 5077 abbreviated flow.
                session_status_prerequisite |= session_status_server_finished;
            } else {
                session_status_prerequisite |= session_status_server_cert | session_status_server_key_exchange | session_status_server_hello_done;
            }
            ret = session->wait_change_session_status(session_status_prerequisite, wto);
            session_status = session->get_session_status();

            if (session_status_prerequisite != (session_status & session_status_prerequisite)) {
                if (errorcode_t::success == ret) {
                    ret = errorcode_t::handshake_failure;
                }
                __leave2_trace(ret);
            }
            ret = errorcode_t::success;

            builder.set(dir).construct();
            if (false == abbreviated) {
                builder.add(&records, tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
                    record->add(tls_handshake_type_t::client_key_exchange, session);
                    return errorcode_t::success;
                });
            }
            builder.add(&records, tls_content_type_t::change_cipher_spec, session)
                .set_protected(true)
                .add(&records, tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
                    record->add(tls_handshake_type_t::finished, session);
                    return errorcode_t::success;
                });

            session_status_finished = abbreviated ? session_status_client_finished : session_status_server_finished;
        }

        ret = do_tls_compose(&records, dir, func);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // wait FIN
        ret = session->wait_change_session_status(session_status_finished, wto);
        session_status = session->get_session_status();

        if (0 == (session_status_finished & session_status)) {
            if (errorcode_t::success == ret) {
                ret = errorcode_t::handshake_failure;
            }
            __leave2_trace(ret);
        }
        ret = errorcode_t::success;
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_server_handshake(unsigned wto, std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        auto& protection = session->get_tls_protection();
        const uint32 completed_status = session_status_client_finished | session_status_server_finished;
        if ((session_type_t::tls != session->get_type()) || (false == protection.is_kindof_tls1_2())) {
            // Keep TLS 1.3 and DTLS server-handshake behavior unchanged.
            ret = errorcode_t::not_supported;
            __leave2_trace(ret);
        }

        const bool renegotiation_enabled = (0 != session->get_keyvalue().get(session_conf_enable_tls12_renegotiation));
        const bool secure_renegotiation = (0 != session->get_keyvalue().get(session_tls12_secure_renegotiation));
        if ((false == renegotiation_enabled) || (false == secure_renegotiation)) {
            ret = errorcode_t::negotiation_failure;
            __leave2_trace(ret);
        }

        // Read the current flow and, if needed, send HelloRequest under the
        // same lock used by the receive parser. This closes the race where a
        // peer ClientHello could be processed after a stale one_rtt snapshot.
        {
            critical_section_guard send_guard(session->get_tls_io_lock());
            if (session->is_terminal()) {
                ret = errorcode_t::disconnect;
                __leave2;
            }

            const tls_flow_t initial_flow = protection.get_flow();
            const uint32 initial_status = session->get_session_status();
            if (tls_flow_t::one_rtt == initial_flow) {
                if (completed_status != (initial_status & completed_status)) {
                    ret = errorcode_t::bad_request;
                    __leave2;
                }

                tls_records records;
                tls_record_builder builder;
                builder.set(from_server).construct().add(&records, tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
                    record->add(tls_handshake_type_t::hello_request, session);
                    return errorcode_t::success;
                });
                ret = do_tls_compose(&records, from_server, func);
            } else if (tls_flow_t::renegotiation != initial_flow) {
                ret = errorcode_t::bad_request;
            }
        }
        if (errorcode_t::success != ret) {
            __leave2_trace(ret);
        }

        // The peer either answers with ClientHello or declines HelloRequest
        // with no_renegotiation, restoring the previous Finished state.
        const uint32 first_wait_status = session_status_client_hello | completed_status;
        uint32 session_status = 0;
        do {
            ret = session->wait_change_session_status(first_wait_status, wto, false);
            if (session->is_terminal()) {
                ret = errorcode_t::disconnect;
                __leave2;
            }
            session_status = session->get_session_status();
            // HelloRequest resets the old Finished status and signals the
            // semaphore. Consume that empty-state notification, then continue
            // waiting for ClientHello or the peer's refusal alert.
        } while ((errorcode_t::mismatch == ret) && (0 == session_status));

        if (0 == (session_status & session_status_client_hello)) {
            if ((completed_status == (session_status & completed_status)) && (tls_flow_t::one_rtt == protection.get_flow())) {
                ret = errorcode_t::negotiation_failure;
            } else if (errorcode_t::success == ret) {
                ret = errorcode_t::handshake_failure;
            }
            __leave2_trace(ret);
        }

        // Full handshakes send server Finished last; abbreviated handshakes
        // send it before client Finished. Require both bits in either case.
        ret = session->wait_change_session_status(completed_status, wto, true);
        if (session->is_terminal()) {
            ret = errorcode_t::disconnect;
            __leave2;
        }

        session_status = session->get_session_status();
        if (completed_status != (session_status & completed_status)) {
            if (errorcode_t::success == ret) {
                ret = errorcode_t::handshake_failure;
            }
            __leave2_trace(ret);
        }
        if (0 == (session_status & session_status_server_hello)) {
            ret = errorcode_t::negotiation_failure;
            __leave2_trace(ret);
        }
        // The Finished status can be published while the receive-side
        // status-hook callback is still sending the final server flight.
        // Acquiring the same I/O lock used by the read path waits for that
        // callback to finish before this blocking handshake reports success.
        {
            critical_section_guard completion_guard(session->get_tls_io_lock());
            if (session->is_terminal()) {
                ret = errorcode_t::disconnect;
                __leave2;
            }
            const uint32 final_status = session->get_session_status();
            if ((completed_status != (final_status & completed_status)) || (0 == (final_status & session_status_server_hello)) ||
                (tls_flow_t::one_rtt != protection.get_flow())) {
                ret = errorcode_t::handshake_failure;
                __leave2;
            }
        }
        ret = errorcode_t::success;
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_client_hello(std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_record* record = nullptr;
    tls_direction_t dir = from_client;
    __try2 {
        if (nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        if (nullptr == session) {
            ret = errorcode_t::invalid_context;
            __leave2;
        }

        // auto session_type = session->get_type();

        tls_record_builder builder;
        record = builder.set(dir).construct().build(tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
            tls_handshake* ch = nullptr;
            ret = construct_client_hello(&ch, session, nullptr, _minspec, _maxspec);
            if (errorcode_t::success == ret) {
                *record << ch;
            }
            return ret;
        });

        ret = do_tls_compose(record, dir, func);
    }
    __finally2 {
        if (record) {
            record->release();
        }
    }
    return ret;
}

return_t tls_composer::do_tls_server_handshake_phase1(std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_record_builder builder;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    tls_direction_t dir = from_server;
    tls_records records;
    __try2 {
        auto session = get_session();
        auto session_type = session->get_type();
        auto session_status = session->get_session_status();
        auto& protection = session->get_tls_protection();
        std::set<tls_alertdesc_t> fatal_alerts;

        auto lambda_has_fatal = [&fatal_alerts](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                fatal_alerts.insert(desc);
            }
        };

        auto lambda_alert = [this, &func, &session, &dir, &builder, &records](tls_alertdesc_t desc) -> return_t {
            records.clear();
            builder                                                 //
                .add(&records, tls_content_type_t::alert, session,  //
                     [&](tls_record* record) -> return_t {
                         auto alert = (tls_record_alert*)record;
                         alert->set(tls_alertlevel_t::fatal, desc);
                         return errorcode_t::success;
                     });

            return do_tls_compose(&records, dir, func);
        };

        builder.set(dir).construct();

        if ((session_type_t::dtls == session_type) && (0 == (session_status & session_status_hello_verify_request))) {
            // hello_verify_request cookie
            builder                                                     //
                .add(&records, tls_content_type_t::handshake, session,  //
                     [&](tls_record* record) -> return_t {
                         record->add(tls_handshake_type_t::hello_verify_request, session, [&](tls_handshake* handshake) -> return_t {
                             auto hvr = (tls_handshake_hello_verify_request*)handshake;
                             (*hvr).set_cookie(protection.get_secrets().get(tls_secret_t::dtls_cookie));
                             return errorcode_t::success;
                         });
                         return errorcode_t::success;
                     });
        } else {
            // server_hello
            builder                                                     //
                .add(&records, tls_content_type_t::handshake, session,  //
                     [&](tls_record* record) -> return_t {
                         return_t ret = errorcode_t::success;
                         tls_handshake* handshake = nullptr;
                         ret = construct_server_hello(&handshake, session, nullptr, _minspec, _maxspec);
                         if (errorcode_t::success == ret) {
                             *record << handshake;
                         }
                         return ret;
                     });

            bool server_hello_send_attempted = false;
            auto server_hello_sender = [&func, &server_hello_send_attempted](tls_session* current, binary_t& bin) -> return_t {
                server_hello_send_attempted = true;
                return func(current, bin);
            };
            return_t server_hello_ret = do_tls_compose(&records, dir, server_hello_sender);
            records.clear();
            if ((errorcode_t::success != server_hello_ret) && server_hello_send_attempted) {
                // A transport error (including a partial TCP write) makes the
                // stream unusable. Do not append an alert or another record.
                ret = server_hello_ret;
                __leave2_trace(ret);
            }

            // unexpected message
            // Keep queued alerts until their TLS records have been serialized.
            // If record protection fails, the caller can still inspect or retry the alert.
            session->get_alert(from_server, lambda_has_fatal, session_alert_peek);
            if (false == fatal_alerts.empty()) {
                return_t alert_ret = lambda_alert(*fatal_alerts.begin());
                if (errorcode_t::success == alert_ret) {
                    session->get_alert(from_server, [](tls_alertlevel_t, tls_alertdesc_t) {});
                    ret = errorcode_t::handshake_failure;
                } else {
                    ret = alert_ret;
                }
                __leave2_trace(ret);
            }
            if (errorcode_t::success != server_hello_ret) {
                // A failed ServerHello serialization may still be followed by
                // its queued fatal alert, but never by the ordinary server flight.
                ret = server_hello_ret;
                __leave2_trace(ret);
            }

            auto tlsver = protection.get_protection_context().get0_supported_version();
            if (tlsadvisor->is_kindof_tls1_3(tlsver)) {
                builder  //
                    .add(&records, tls_content_type_t::change_cipher_spec, session)
                    .set_protected(true)
                    .add(&records, tls_content_type_t::handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_handshake_type_t::encrypted_extensions, session);
                             return errorcode_t::success;
                         })
                    .add(&records, tls_content_type_t::handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_handshake_type_t::certificate, session);
                             return errorcode_t::success;
                         })
                    .add(&records, tls_content_type_t::handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_handshake_type_t::certificate_verify, session);
                             return errorcode_t::success;
                         })
                    .add(&records, tls_content_type_t::handshake, session,  //
                         [&](tls_record* record) -> return_t {
                             record->add(tls_handshake_type_t::finished, session);
                             return errorcode_t::success;
                         });
            } else if (0 != session->get_keyvalue().get(session_tls1_2_ticket_resumed)) {
                // RFC 5077 abbreviated flow: optional ticket renewal, then
                // server CCS and Finished before the client sends Finished.
                if ((0 != session->get_keyvalue().get(session_tls1_2_ticket_acknowledged)) &&
                    (false == protection.get_secrets().get(tls_secret_t::new_session_ticket).empty())) {
                    builder.add(&records, tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
                        record->add(tls_handshake_type_t::new_session_ticket, session);
                        return errorcode_t::success;
                    });
                }
                builder.add(&records, tls_content_type_t::change_cipher_spec, session)
                    .set_protected(true)
                    .add(&records, tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
                        record->add(tls_handshake_type_t::finished, session);
                        return errorcode_t::success;
                    });
            } else {
                builder  //
                    .add(&records, tls_content_type_t::handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_handshake_type_t::certificate, session);
                             return errorcode_t::success;
                         })
                    .add(&records, tls_content_type_t::handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_handshake_type_t::server_key_exchange, session);
                             return errorcode_t::success;
                         })
                    .add(&records, tls_content_type_t::handshake, session,  //
                         [&](tls_record* record) -> return_t {
                             record->add(tls_handshake_type_t::server_hello_done, session);
                             return errorcode_t::success;
                         });
            }

            // Keep queued alerts until their TLS records have been serialized.
            // If record protection fails, the caller can still inspect or retry the alert.
            session->get_alert(from_server, lambda_has_fatal, session_alert_peek);
            if (false == fatal_alerts.empty()) {
                return_t alert_ret = lambda_alert(*fatal_alerts.begin());
                if (errorcode_t::success == alert_ret) {
                    session->get_alert(from_server, [](tls_alertlevel_t, tls_alertdesc_t) {});
                    ret = errorcode_t::handshake_failure;
                } else {
                    ret = alert_ret;
                }
                __leave2_trace(ret);
            }
        }

        bool final_send_attempted = false;
        auto final_sender = [&func, &final_send_attempted](tls_session* current, binary_t& bin) -> return_t {
            final_send_attempted = true;
            return func(current, bin);
        };
        ret = do_tls_compose(&records, dir, final_sender);
        if ((errorcode_t::success != ret) && (false == final_send_attempted)) {
            // Serialization failed before any transport write. If that failure
            // queued a fatal alert, try to send only that alert.
            fatal_alerts.clear();
            session->get_alert(from_server, lambda_has_fatal, session_alert_peek);
            if (false == fatal_alerts.empty()) {
                return_t alert_ret = lambda_alert(*fatal_alerts.begin());
                if (errorcode_t::success == alert_ret) {
                    session->get_alert(from_server, [](tls_alertlevel_t, tls_alertdesc_t) {});
                    ret = errorcode_t::handshake_failure;
                } else {
                    ret = alert_ret;
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_server_handshake_phase2(std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_record_builder builder;
    tls_direction_t dir = from_server;
    tls_records records;
    __try2 {
        auto session = get_session();

        builder.set(dir).construct();
        if ((0 != session->get_keyvalue().get(session_tls1_2_ticket_acknowledged)) &&
            (false == session->get_tls_protection().get_secrets().get(tls_secret_t::new_session_ticket).empty())) {
            builder.add(&records, tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
                record->add(tls_handshake_type_t::new_session_ticket, session);
                return errorcode_t::success;
            });
        }
        builder.add(&records, tls_content_type_t::change_cipher_spec, session)
            .set_protected(true)
            .add(&records, tls_content_type_t::handshake, session, [&](tls_record* record) -> return_t {
                record->add(tls_handshake_type_t::finished, session);
                return errorcode_t::success;
            });

        bool send_attempted = false;
        auto sender = [&func, &send_attempted](tls_session* current, binary_t& bin) -> return_t {
            send_attempted = true;
            return func(current, bin);
        };
        ret = do_tls_compose(&records, dir, sender);
        if ((errorcode_t::success != ret) && (false == send_attempted)) {
            std::set<tls_alertdesc_t> fatal_alerts;
            auto lambda_has_fatal = [&fatal_alerts](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
                if (tls_alertlevel_t::fatal == level) {
                    fatal_alerts.insert(desc);
                }
            };
            session->get_alert(from_server, lambda_has_fatal, session_alert_peek);
            if (false == fatal_alerts.empty()) {
                records.clear();
                builder.add(&records, tls_content_type_t::alert, session, [&](tls_record* record) -> return_t {
                    static_cast<tls_record_alert*>(record)->set(tls_alertlevel_t::fatal, *fatal_alerts.begin());
                    return errorcode_t::success;
                });
                return_t alert_ret = do_tls_compose(&records, dir, func);
                if (errorcode_t::success == alert_ret) {
                    session->get_alert(from_server, [](tls_alertlevel_t, tls_alertdesc_t) {});
                    ret = errorcode_t::handshake_failure;
                } else {
                    ret = alert_ret;
                }
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_compose(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    if (nullptr == func) {
        return errorcode_t::invalid_parameter;
    }
    return do_tls_compose(record, dir, [func](tls_session* session, binary_t& bin) -> return_t {
        func(session, bin);
        return errorcode_t::success;
    });
}

return_t tls_composer::do_tls_compose(tls_record* record, tls_direction_t dir, std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_type_t::dtls == session_type) {
            ret = session->get_dtls_record_publisher().publish(record, dir, func);
        } else {
            binary_t bin;
            ret = record->write(dir, bin);
            if (errorcode_t::success != ret) {
                __leave2;
            }
            ret = func(session, bin);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_compose(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    if (nullptr == func) {
        return errorcode_t::invalid_parameter;
    }
    return do_tls_compose(records, dir, [func](tls_session* session, binary_t& bin) -> return_t {
        func(session, bin);
        return errorcode_t::success;
    });
}

return_t tls_composer::do_tls_compose(tls_records* records, tls_direction_t dir, std::function<return_t(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_type_t::dtls == session_type) {
            ret = session->get_dtls_record_publisher().publish(records, dir, func);
        } else {
            ret = records->write(session, dir, func);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
