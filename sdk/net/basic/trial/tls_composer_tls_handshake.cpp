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
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/crypto/basic/openssl_prng.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/tls/dtls_record_publisher.hpp>
#include <hotplace/sdk/net/tls/tls/handshake/tls_handshake_hello_verify_request.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_records.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

return_t tls_composer::do_tls_client_handshake(unsigned wto, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto session = get_session();
        auto& protection = session->get_tls_protection();
        auto session_type = session->get_type();
        auto dir = from_client;
        uint32 session_status = 0;

        uint8 retry = 3;
        do {
            // C->S CH
            ret = do_tls_client_hello(func);
            if (errorcode_t::success != ret) {
                __leave2;
            }

            // if DTLS(HVR), then CH(cookie)
            if (session_type_dtls == session_type) {
                // S->C HVR
                session->wait_change_session_status(session_status_hello_verify_request, wto);
                session_status = session->get_session_status();

                if (0 == (session_status & session_status_hello_verify_request)) {
                    ret = errorcode_t::error_handshake;
                    __leave2_trace(ret);
                }

                // C->S CH(cookie that server sent)
                ret = do_tls_client_hello(func);
                if (errorcode_t::success != ret) {
                    __leave2;
                }
            }

            // S->C SH, check HRR
            session->wait_change_session_status(session_status_server_hello, wto);
            session_status = session->get_session_status();

            if (0 == (session_status & session_status_server_hello)) {
                ret = errorcode_t::error_handshake;
                break;
            }
        } while ((tls_flow_hello_retry_request == protection.get_flow()) && (--retry));

        if (errorcode_t::success != ret) {
            __leave2;
        }
        if (tls_flow_1rtt != protection.get_flow()) {
            ret = errorcode_t::error_handshake;
            __leave2;
        }

        tls_records records;
        tls_record_builder builder;
        uint32 session_status_finished = 0;

        if (protection.is_kindof_tls13()) {
            uint32 session_status_prerequisite =
                session_status_server_hello | session_status_server_cert | session_status_server_cert_verified | session_status_server_finished;
            session->wait_change_session_status(session_status_prerequisite, wto);
            session_status = session->get_session_status();

            if (0 == (session_status & session_status_prerequisite)) {
                ret = error_handshake;
                __leave2_trace(ret);
            }

            builder.set(dir)
                .construct()
                .add(&records, tls_content_type_change_cipher_spec, session)
                .set_protected(true)
                .add(&records, tls_content_type_handshake, session,  //
                     [&](tls_record* record) -> return_t {
                         record->add(tls_hs_finished, session);
                         return success;
                     });

            session_status_finished = session_status_client_finished;
        } else if (protection.is_kindof_tls12()) {
            uint32 session_status_prerequisite =
                session_status_server_hello | session_status_server_cert | session_status_server_key_exchange | session_status_server_hello_done;
            session->wait_change_session_status(session_status_prerequisite, wto);
            session_status = session->get_session_status();

            if (0 == (session_status & session_status_prerequisite)) {
                ret = errorcode_t::error_handshake;
                __leave2_trace(ret);
            }

            builder.set(dir)
                .construct()
                .add(&records, tls_content_type_handshake, session,
                     [&](tls_record* record) -> return_t {
                         record->add(tls_hs_client_key_exchange, session);
                         return success;
                     })
                .add(&records, tls_content_type_change_cipher_spec, session)
                .set_protected(true)
                .add(&records, tls_content_type_handshake, session,  //
                     [&](tls_record* record) -> return_t {
                         record->add(tls_hs_finished, session);
                         return success;
                     });

            session_status_finished = session_status_server_finished;
        }

        ret = do_tls_compose(&records, dir, func);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // wait FIN
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

return_t tls_composer::do_tls_client_hello(std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
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

        uint32 session_status = 0;
        auto session_type = session->get_type();
        auto& protection = session->get_tls_protection();
        bool is_dtls = (session_type_dtls == session_type);

        tls_record_builder builder;
        record = builder.set(dir).construct().build(tls_content_type_handshake, session, [&](tls_record* record) -> return_t {
            tls_handshake* ch = nullptr;
            ret = construct_client_hello(&ch, session, nullptr, _minspec, _maxspec);
            if (errorcode_t::success == ret) {
                *record << ch;
            }
            return ret;
        });

        do_tls_compose(record, dir, func);
    }
    __finally2 {
        if (record) {
            record->release();
        }
    }
    return ret;
}

return_t tls_composer::do_tls_server_handshake_phase1(std::function<void(tls_session*, binary_t&)> func) {
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

        builder.set(dir).construct();

        if ((session_type_dtls == session_type) && (0 == (session_status & session_status_hello_verify_request))) {
            // hello_verify_request cookie
            builder                                                  //
                .add(&records, tls_content_type_handshake, session,  //
                     [&](tls_record* record) -> return_t {
                         record->add(tls_hs_hello_verify_request, session, [&](tls_handshake* handshake) -> return_t {
                             auto hvr = (tls_handshake_hello_verify_request*)handshake;
                             (*hvr).set_cookie(protection.get_secrets().get(tls_context_dtls_cookie));
                             return success;
                         });
                         return success;
                     });
        } else {
            // server_hello
            builder                                                  //
                .add(&records, tls_content_type_handshake, session,  //
                     [&](tls_record* record) -> return_t {
                         return_t ret = errorcode_t::success;
                         tls_handshake* handshake = nullptr;
                         ret = construct_server_hello(&handshake, session, nullptr, _minspec, _maxspec);
                         if (errorcode_t::success == ret) {
                             *record << handshake;
                         }
                         return ret;
                     });

            auto tlsver = protection.get_protection_context().get0_supported_version();
            if (tlsadvisor->is_kindof_tls13(tlsver)) {
                builder  //
                    .add(&records, tls_content_type_change_cipher_spec, session)
                    .set_protected(true)
                    .add(&records, tls_content_type_handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_hs_encrypted_extensions, session);
                             return success;
                         })
                    .add(&records, tls_content_type_handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_hs_certificate, session);
                             return success;
                         })
                    .add(&records, tls_content_type_handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_hs_certificate_verify, session);
                             return success;
                         })
                    .add(&records, tls_content_type_handshake, session,  //
                         [&](tls_record* record) -> return_t {
                             record->add(tls_hs_finished, session);
                             return success;
                         });
            } else {
                builder  //
                    .add(&records, tls_content_type_handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_hs_certificate, session);
                             return success;
                         })
                    .add(&records, tls_content_type_handshake, session,
                         [&](tls_record* record) -> return_t {
                             record->add(tls_hs_server_key_exchange, session);
                             return success;
                         })
                    .add(&records, tls_content_type_handshake, session,  //
                         [&](tls_record* record) -> return_t {
                             record->add(tls_hs_server_hello_done, session);
                             return success;
                         });
            }
        }

        do_tls_compose(&records, dir, func);
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_server_handshake_phase2(std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_record_builder builder;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    tls_direction_t dir = from_server;
    tls_records records;
    __try2 {
        auto session = get_session();

        builder  //
            .set(dir)
            .construct()
            .add(&records, tls_content_type_change_cipher_spec, session)
            .set_protected(true)
            .add(&records, tls_content_type_handshake, session,  //
                 [&](tls_record* record) -> return_t {
                     record->add(tls_hs_finished, session);
                     return success;
                 });

        do_tls_compose(&records, dir, func);
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_compose(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == record || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_type_dtls == session_type) {
            // fragmentation
            session->get_dtls_record_publisher().publish(record, dir, func);
        } else {
            binary_t bin;
            ret = record->write(dir, bin);
            func(session, bin);
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_tls_compose(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == records || nullptr == func) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        auto session = get_session();
        auto session_type = session->get_type();
        if (session_type_dtls == session_type) {
            // fragmentation
            session->get_dtls_record_publisher().publish(records, dir, func);
        } else {
            records->write(session, dir, func);
        }
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
