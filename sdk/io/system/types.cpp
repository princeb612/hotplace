/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/template.hpp>
#include <sdk/base/template.hpp>
#include <sdk/io/system/types.hpp>
#if defined __linux__
#include <arpa/inet.h>
#endif

namespace hotplace {
namespace io {

#if defined __SIZEOF_INT128__

int128 atoi128(const std::string& in) { return t_atoi<int128>(in); }

uint128 atou128(const std::string& in) { return t_atoi<uint128>(in); }

#endif

}  // namespace io
}  // namespace hotplace
