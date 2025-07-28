/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/trial/tls_composer.hpp>
#include <sdk/net/basic/trial/trial_tls_client_socket.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

trial_tls_client_socket::trial_tls_client_socket(tls_version_t version) : secure_client_socket(version) {
    auto session = &_session;
    session->set_type(session_type_tls);
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
        tls_record_application_data record(session);
        record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
        record.write(from_client, bin);

        size_t sent = 0;
        ret = client_socket_prosumer::send((char*)&bin[0], bin.size(), &sent);
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
        ret = secure_client_socket::send((char*)&bin[0], bin.size(), &sent);
    }
    return ret;
}

int trial_tls_client_socket::socket_type() { return SOCK_STREAM; }

}  // namespace net
}  // namespace hotplace
