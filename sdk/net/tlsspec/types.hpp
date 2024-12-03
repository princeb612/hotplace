/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLSSPEC_TYPES__
#define __HOTPLACE_SDK_NET_TLSSPEC_TYPES__

#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

enum tls_role_t {
    role_server = 0,
    role_client = 1,
};

}  // namespace net
}  // namespace hotplace

#endif
