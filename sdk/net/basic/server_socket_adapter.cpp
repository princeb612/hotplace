/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/basic/server_socket_adapter.hpp>

namespace hotplace {
namespace net {

server_socket_adapter::server_socket_adapter() { _shared.make_share(this); }

server_socket_adapter::~server_socket_adapter() {}

return_t server_socket_adapter::startup_tls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer) {
    return errorcode_t::not_implemented;
}

return_t server_socket_adapter::startup_dtls(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer) {
    return errorcode_t::not_implemented;
}

return_t server_socket_adapter::startup_quic(const std::string& server_cert, const std::string& server_key, const std::string& cipher_list, int verify_peer) {
    return errorcode_t::not_implemented;
}

return_t server_socket_adapter::shutdown_tls() { return errorcode_t::not_implemented; }

return_t server_socket_adapter::shutdown_dtls() { return errorcode_t::not_implemented; }

return_t server_socket_adapter::shutdown_quic() { return errorcode_t::not_implemented; }

server_socket* server_socket_adapter::get_tcp_server_socket() { return nullptr; }

server_socket* server_socket_adapter::get_tls_server_socket() { return nullptr; }

server_socket* server_socket_adapter::get_dtls_server_socket() { return nullptr; }

return_t server_socket_adapter::enable_alpn(const char* prot) { return errorcode_t::not_implemented; }

void server_socket_adapter::addref() { _shared.addref(); }

void server_socket_adapter::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
