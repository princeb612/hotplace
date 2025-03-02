/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

const tls_version_hint_t tls_version_hint[] = {
    {0x0304, 1, 0, "TLS v1.3"},  //
    {0x0303, 1, 0, "TLS v1.2"},  // RFC 5246 A.1.  Record Layer
    {0xfefc, 1, 0, "DTLS 1.3"},  //
    {0xfefd, 1, 0, "DTLS 1.2"},  //
    {0x0302, 0, 0, "TLS v1.1"},  // RFC 4346 A.1. Record Layer
    {0x0301, 0, 0, "TLS v1.0"},  // RFC 2246 A.1. Record layer
};
const size_t sizeof_tls_version_hint = RTL_NUMBER_OF(tls_version_hint);

}  // namespace net
}  // namespace hotplace
