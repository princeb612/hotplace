/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * spec list
 *      qop=auth
 *      algorithm=MD5|MD5-sess|SHA-256|SHA-256-sess
 *      userhash
 * todo list
 *      qop=auth-int
 *      nextnonce
 */

#ifndef __HOTPLACE_SDK_NET_HTTP_TYPES__
#define __HOTPLACE_SDK_NET_HTTP_TYPES__

#include <map>
#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>
#include <sdk/io.hpp>

namespace hotplace {
using namespace io;
namespace net {

enum http_method_t {
    HTTP_OPTIONS = 1,
    HTTP_GET = 2,
    HTTP_HEAD = 3,
    HTTP_POST = 4,
    HTTP_PUT = 5,
    HTTP_DELETE = 6,
    HTTP_TRACE = 7,
};

}  // namespace net
}  // namespace hotplace

#endif
