/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_TYPES__
#define __HOTPLACE_SDK_BASE_TYPES__

#if defined __linux__
#include <hotplace/sdk/base/system/linux/types.hpp>
#elif defined _WIN32 || defined _WIN64
#include <hotplace/sdk/base/system/windows/types.hpp>
#endif

#include <vector>

namespace hotplace {

template <typename RETURN_T, typename TYPE> RETURN_T type_cast (TYPE param)
{
    return static_cast <RETURN_T> (param);
}

typedef unsigned char byte_t;
typedef std::vector<byte_t> binary_t;

#ifndef RTL_NUMBER_OF
#define RTL_NUMBER_OF(x) (sizeof (x) / sizeof (x[0]))
#endif

} // namespace

#endif
