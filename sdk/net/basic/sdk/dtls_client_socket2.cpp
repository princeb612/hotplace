/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          openssl not support DTLS 1.3 yet
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk/dtls_client_socket2.hpp>
#include <sdk/net/basic/sdk/tls_composer.hpp>
#include <sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/types.hpp>

namespace hotplace {
namespace net {

dtls_client_socket2::dtls_client_socket2(tls_version_t version) : secure_client_socket(version) {
    auto session = &_session;
    session->set_type(session_dtls);
}

return_t dtls_client_socket2::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == ptr_data || nullptr == cbsent || nullptr == addr) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *cbsent = 0;

        auto session = get_session();
        binary_t bin;

        auto tlsver = session->get_tls_protection().get_tls_version();

        if (dtls_13 == tlsver) {
            dtls13_ciphertext record(tls_content_type_application_data, session);
            record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
            record.write(from_client, bin);
        } else {
            tls_record_application_data record(session);
            record.get_records().add(new tls_record_application_data(session, (byte_t*)ptr_data, size_data));
            record.write(from_client, bin);
        }

        size_t sent = 0;
        ret = client_socket_prosumer::sendto((char*)&bin[0], bin.size(), &sent, addr, addrlen);
        if (errorcode_t::success == ret) {
            *cbsent = size_data;
        }
    }
    __finally2 {}
    return ret;
}

return_t dtls_client_socket2::do_send(binary_t& bin) {
    return_t ret = errorcode_t::success;
    if (bin.empty()) {
        ret = errorcode_t::empty;
    } else {
        size_t cbsent = 0;
        ret = client_socket_prosumer::sendto((char*)&bin[0], bin.size(), &cbsent, (sockaddr*)&_sa, sizeof(_sa));
    }
    return ret;
}

int dtls_client_socket2::socket_type() { return SOCK_DGRAM; }

}  // namespace net
}  // namespace hotplace
