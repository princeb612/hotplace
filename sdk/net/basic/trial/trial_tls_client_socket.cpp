/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   trial_tls_client_socket.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/basic/trial/trial_tls_client_socket.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

trial_tls_client_socket::trial_tls_client_socket(tls_version_t spec)
    : secure_client_socket(spec), _tls12_ticket_store(std::make_shared<tls12_resumption_ticket_store>()) {
    auto session = get_session();
    session->set_type(session_type_t::tls);
    session->set_tls12_resumption_ticket_store(_tls12_ticket_store);
    session->get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);
}

trial_tls_client_socket::trial_tls_client_socket(const tls_session& resumption_source, tls_version_t spec)
    : secure_client_socket(spec, tls_session_ptr(resumption_source.duplicate(tls_session_copy_t::resumption))),
      _tls12_ticket_store(std::make_shared<tls12_resumption_ticket_store>()) {
    auto session = get_session();
    if (session_type_t::tls != session->get_type()) {
        throw exception(errorcode_t::bad_request);
    }
    if ((0 != session->get_session_status()) || (tls_handshake_type_t::client_hello != session->get_session_info(from_client).get_status()) ||
        (tls_handshake_type_t::client_hello != session->get_session_info(from_server).get_status())) {
        throw exception(errorcode_t::bad_request);
    }
    session->set_tls12_resumption_ticket_store(_tls12_ticket_store);
    session->get_keyvalue().set(session_client_session_ticket_offer_enabled, 1);
}

trial_tls_client_socket::~trial_tls_client_socket() {}

return_t trial_tls_client_socket::send(const char* ptr_data, size_t size_data, size_t* cbsent) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbsent) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *cbsent = 0;

        auto session = get_session();

        binary_t bin;
        tls_record_application_data record(session, (byte_t*)ptr_data, size_data);
        record.write(from_client, bin);

        size_t sent = 0;
        ret = client_socket_prosumer::send((char*)bin.data(), bin.size(), &sent);
        if (errorcode_t::success == ret) {
            *cbsent = size_data;
        }
    }
    __finally2 {}
    return ret;
}

return_t trial_tls_client_socket::do_send(binary_t& bin) {
    return_t ret = errorcode_t::success;
    if (bin.empty()) {
        ret = errorcode_t::empty;
    } else {
        size_t sent = 0;
        ret = secure_client_socket::send((char*)bin.data(), bin.size(), &sent);
    }
    return ret;
}

int trial_tls_client_socket::socket_type() const { return SOCK_STREAM; }

uint32 trial_tls_client_socket::get_scheme() const { return socket_scheme_tls | socket_scheme_trial | socket_scheme_client; }

}  // namespace net
}  // namespace hotplace
