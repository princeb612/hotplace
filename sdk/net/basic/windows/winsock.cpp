/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/basic/sdk.hpp>

namespace hotplace {
namespace net {

return_t winsock_startup() {
    WSADATA wsaData;
    BYTE wMajorVersion = 2;
    BYTE wMinorVersion = 2;
    WORD wVersionRequested = MAKEWORD(wMinorVersion, wMajorVersion);

    WSAStartup(wVersionRequested, &wsaData);
    return GetLastError();
}

void winsock_cleanup() { WSACleanup(); }

}  // namespace net
}  // namespace hotplace
