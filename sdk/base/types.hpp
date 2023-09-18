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

#include <map>
#include <string>
#include <vector>

namespace hotplace {

template <typename RETURN_T, typename TYPE> RETURN_T type_cast (TYPE param)
{
    return static_cast <RETURN_T> (param);
}

typedef unsigned char byte_t;
typedef std::vector<byte_t> binary_t;

#ifndef _WIN32 // winnt.h
#define RTL_NUMBER_OF(x) (sizeof (x) / sizeof (x[0]))
#define RTL_FIELD_SIZE(type, field) (sizeof (((type *) 0)->field))
#define FIELD_OFFSET(type, field) ((int32) (arch_t) &(((type *) 0)->field))
#endif

#define __min(a, b) (((a) < (b)) ? (a) : (b))
#define __max(a, b) (((a) > (b)) ? (a) : (b))
#define adjust_range(var, minimum, maximum) { var = __max (var, minimum); var = __min (var, maximum); }

} // namespace

#endif
