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

tls_composer::tls_composer(tls_session* session) : _session(session), _minspec(tls_12), _maxspec(tls_13) {
    if (session) {
        session->addref();
    } else {
        throw exception(errorcode_t::no_session);
    }

    if (session_type_dtls == session->get_type()) {
        auto& publisher = session->get_dtls_record_publisher();
        publisher.set_fragment_size(1024);
        publisher.set_segment_size(1024);
        publisher.set_flags(dtls_record_publisher_multi_handshakes);
    }
}

tls_composer::~tls_composer() {
    auto session = get_session();
    if (session) {
        session->release();
    }
}

return_t tls_composer::session_status_changed(uint32 session_status, tls_direction_t dir, uint32 wto, std::function<void(tls_session*, binary_t&)> func) {
    return_t ret = errorcode_t::success;
    tls_advisor* tlsadvisor = tls_advisor::get_instance();
    __try2 {
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("hook %s (%s)", tlsadvisor->session_status_string(session_status).c_str(), tlsadvisor->nameof_direction(dir).c_str());
            trace_debug_event(trace_category_net, trace_event_tls_handshake, &dbs);
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
            // TLS 1.2
            //   C client_hello
            //   S server_hello, certificate, server_key_exchange, server_hello_done
            //   C client_key_exchange, change_cipher_spec, finished
            //   S change_cipher_spec, finished
            switch (session_status) {
                case session_status_client_hello: {
                    ret = do_server_handshake_phase1(func);
                } break;
                case session_status_client_finished: {
                    // TLS 1.2
                    if (protection.is_kindof_tls12()) {
                        ret = do_server_handshake_phase2(func);
                    }
                } break;
            }
        }
    }
    __finally2 {}
    return ret;
}

return_t tls_composer::do_compose(tls_record* record, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
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

return_t tls_composer::do_compose(tls_records* records, tls_direction_t dir, std::function<void(tls_session*, binary_t&)> func) {
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

uint16 tls_composer::get_minver() { return _minspec; }

uint16 tls_composer::get_maxver() { return _maxspec; }

}  // namespace net
}  // namespace hotplace
