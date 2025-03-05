/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/basic_socket.hpp>

namespace hotplace {
namespace net {

basic_socket::basic_socket() : _fd(INVALID_SOCKET) { _shared.make_share(this); }

basic_socket::~basic_socket() {}

bool basic_socket::support_tls() { return false; }

int basic_socket::socket_type() { return 0; }

int basic_socket::addref() { return _shared.addref(); }

int basic_socket::release() { return _shared.delref(); }

}  // namespace net
}  // namespace hotplace
