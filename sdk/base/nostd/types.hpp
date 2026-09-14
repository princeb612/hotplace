/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_NOSTD_TYPES__
#define __HOTPLACE_SDK_BASE_NOSTD_TYPES__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

enum class range_type_t : int8 {
    minvalue = -1,    // -inf
    ninf = minvalue,  // negative inf
    value = 0,        // value
    maxvalue = 1,     // +inf
    inf = maxvalue,   // positive inf
};
enum class range_flag_t : uint8 {
    excluded = 0,       // open
    open = excluded,    //
    included = 1,       // closed
    closed = included,  //
};

}  // namespace hotplace

#endif
