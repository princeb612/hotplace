/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/client_socket.hpp>

namespace hotplace {
namespace net {

client_socket::client_socket() : basic_socket(), _wto(1000) {}

client_socket::~client_socket() { close(); }

return_t client_socket::connect(const char* address, uint16 port, uint32 timeout) { return errorcode_t::do_nothing; }

return_t client_socket::open(sockaddr_storage_t* sa, const char* address, uint16 port) { return errorcode_t::do_nothing; }

return_t client_socket::close() { return errorcode_t::do_nothing; }

return_t client_socket::read(char* ptr_data, size_t size_data, size_t* cbread) { return errorcode_t::do_nothing; }

return_t client_socket::more(char* ptr_data, size_t size_data, size_t* cbread) { return errorcode_t::do_nothing; }

return_t client_socket::send(const char* ptr_data, size_t size_data, size_t* cbsent) { return errorcode_t::do_nothing; }

return_t client_socket::recvfrom(char* ptr_data, size_t size_data, size_t* cbread, struct sockaddr* addr, socklen_t* addrlen) {
    return errorcode_t::do_nothing;
}

return_t client_socket::sendto(const char* ptr_data, size_t size_data, size_t* cbsent, const struct sockaddr* addr, socklen_t addrlen) {
    return errorcode_t::do_nothing;
}

socket_t client_socket::get_socket() { return INVALID_SOCKET; }

void client_socket::set_wto(uint32 milliseconds) { _wto = milliseconds; }

uint32 client_socket::get_wto() { return _wto; }

}  // namespace net
}  // namespace hotplace
