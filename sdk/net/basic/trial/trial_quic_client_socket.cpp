/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/basic/trial/tls_composer.hpp>
#include <hotplace/sdk/net/basic/trial/trial_quic_client_socket.hpp>
#include <hotplace/sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

trial_quic_client_socket::trial_quic_client_socket() : secure_client_socket(tls_13) {}

trial_quic_client_socket::~trial_quic_client_socket() {}

uint32 trial_quic_client_socket::get_scheme() { return socket_scheme_quic | socket_scheme_trial | socket_scheme_client; }

}  // namespace net
}  // namespace hotplace
