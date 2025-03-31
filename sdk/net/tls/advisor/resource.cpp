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
    {0x0304, tls_13, 1, flag_kindof_tls, "TLS v1.3"},  //
    {0x0303, tls_12, 1, flag_kindof_tls, "TLS v1.2"},  // RFC 5246 A.1.  Record Layer
    {0x0302, tls_11, 0, flag_kindof_tls, "TLS v1.1"},  // RFC 4346 A.1. Record Layer
    {0x0301, tls_10, 0, flag_kindof_tls, "TLS v1.0"},  // RFC 2246 A.1. Record layer
    {0xfefc, tls_13, 1, 0, "DTLS 1.3"},                //
    {0xfefd, tls_12, 1, 0, "DTLS 1.2"},                //
    {0xfefe, tls_11, 0, 0, "DTLS 1.1"},                //
    {0xfeff, tls_10, 0, 0, "DTLS 1.0"},                //
};
const size_t sizeof_tls_version_hint = RTL_NUMBER_OF(tls_version_hint);

}  // namespace net
}  // namespace hotplace
